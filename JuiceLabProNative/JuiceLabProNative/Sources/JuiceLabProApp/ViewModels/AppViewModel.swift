#if canImport(SwiftUI)
import Foundation
import SwiftUI
import Combine
import JuiceLabCore

@MainActor
final class AppViewModel: ObservableObject {
    private let maxVisibleItems = 2000

    enum Route: String, CaseIterable {
        case runs = "Runs"
        case results = "Results"
        case timeline = "Timeline"
        case graph = "Evidence Graph"
        case cases = "Cases"
        case forensic = "Forensic"
        case settings = "Settings"
    }

    @Published var route: Route? = .results
    @Published var settings = ScanSettings(dedupeMode: .exactBytes, enableAI: true)
    @Published var runs: [ScanRun] = []
    @Published var selectedRunID: UUID? {
        didSet { syncInvestigationContext() }
    }
    @Published var selectedRunKey: String? {
        didSet { syncInvestigationContext() }
    }
    @Published var activeForensicFacet: ForensicFacet? {
        didSet { investigationEngine.applyForensicFacet(activeForensicFacet) }
    }
    @Published var selectedItem: FoundItem? {
        didSet { itemTick &+= 1 }
    }
    @Published var query = "" {
        didSet { investigationEngine.updateQuery(query) }
    }
    @Published var selectedCategories = Set(FileCategory.allCases) {
        didSet { investigationEngine.updateCategories(selectedCategories) }
    }
    @Published var progress = ScanProgress()
    @Published var isScanning = false
    @Published var isRunningAgents = false
    @Published var isRunningAgentActions = false
    @Published var droppedURLs: [URL] = []
    @Published var statusMessage: String = ""
    @Published var stageMessage: String = ""
    @Published var commandPalettePresented = false

    /// UI refresh signal (throttled)
    @Published private(set) var itemTick: Int = 0

    private let engine = ScannerEngine()
    private let history = RunHistoryStore()
    private let investigationEngine = InvestigationEngine()

    /// ✅ cancellation handle
    private var scanTask: Task<Void, Never>?

    /// ✅ throttle state
    private var lastTickTime: CFAbsoluteTime = 0
    private var pendingTick: Bool = false

    init() {
        Task {
            let loaded = await history.load()
            runs = normalizeRuns(loaded)
            sanitizeSelectionAfterRunsChange()
            syncInvestigationContext()
        }
    }

    var activeRun: ScanRun? {
        if let selectedRunKey {
            return runs.first(where: { runKey($0) == selectedRunKey })
        }
        if let selectedRunID {
            return runs.first(where: { $0.id == selectedRunID })
        }
        return runs.first
    }

    var filteredItems: [FoundItem] {
        _ = itemTick // drive reevaluation
        return investigationEngine.filteredItems(limit: maxVisibleItems)
    }

    func addSources(_ urls: [URL]) {
        for url in urls where !droppedURLs.contains(url) {
            droppedURLs.append(url)
        }
    }

    func removeSource(_ url: URL) {
        droppedURLs.removeAll { $0 == url }
    }

    func clearSources() {
        droppedURLs.removeAll()
    }

    func startScan() {
        if isScanning {
            statusMessage = "Scan already running."
            return
        }
        guard !droppedURLs.isEmpty else {
            statusMessage = "No sources selected. Add files/folders first."
            return
        }
        isScanning = true
        statusMessage = "Starting scan for \(droppedURLs.count) source(s)..."
        stageMessage = "Preparing scan..."
        progress = ScanProgress()

        scanTask?.cancel()

        scanTask = Task { @MainActor in
            let scopedRoots = droppedURLs.map { url in
                (url, url.startAccessingSecurityScopedResource())
            }
            defer {
                for (url, isScoped) in scopedRoots where isScoped {
                    url.stopAccessingSecurityScopedResource()
                }
            }

            let accessible = validateReadableSources(scopedRoots.map(\.0))
            if !accessible.unreadable.isEmpty {
                statusMessage = "Unreadable sources skipped: \(accessible.unreadable.joined(separator: ", "))"
            }
            if accessible.readable.isEmpty {
                isScanning = false
                if statusMessage.isEmpty {
                    statusMessage = "No readable sources. Re-add files with Add Sources and try again."
                }
                return
            }

            let run = await engine.scan(
                paths: accessible.readable,
                settings: settings,
                onProgress: { update in
                    DispatchQueue.main.async {
                        self.progress = update
                    }
                },
                onItem: { _ in
                    DispatchQueue.main.async {
                        self.throttledTick()
                    }
                },
                onStage: { fileName, stageName in
                    DispatchQueue.main.async {
                        self.stageMessage = "Stage: \(self.prettyStageName(stageName))  File: \(fileName)"
                    }
                }
            )

            if Task.isCancelled {
                self.isScanning = false
                self.stageMessage = ""
                return
            }

            let doneRun: ScanRun
            do {
                doneRun = try await engine.export(run: run)
            } catch {
                doneRun = run
                statusMessage = "Export warning: \(error.localizedDescription)"
            }

            if Task.isCancelled {
                self.isScanning = false
                self.stageMessage = ""
                return
            }

            upsertRun(doneRun)
            selectedRunID = doneRun.id
            selectedRunKey = runKey(doneRun)
            try? await history.save(run: doneRun)
            if doneRun.items.isEmpty {
                statusMessage = "Scan completed with 0 items. Try enabling All types or adding a different source."
            } else if !doneRun.warnings.isEmpty {
                statusMessage = "Scan completed with warnings (\(doneRun.warnings.count))."
            } else {
                statusMessage = "Scan completed: \(doneRun.items.count) items."
            }
            stageMessage = ""
            isScanning = false
        }
    }

    func stopScan() {
        scanTask?.cancel()
        scanTask = nil
        isScanning = false
        stageMessage = ""
    }

    func runAgents() {
        guard !isScanning, !isRunningAgents, let run = activeRun else { return }
        isRunningAgents = true
        stageMessage = "Running local forensic agents..."

        Task { @MainActor in
            do {
                let updated = try await engine.runAgents(for: run)
                upsertRun(updated)
                selectedRunID = updated.id
                selectedRunKey = runKey(updated)
                try? await history.save(run: updated)
                statusMessage = "Agents completed. Open Agent Summary for results."
            } catch {
                statusMessage = "Agent run failed: \(error.localizedDescription)"
            }
            stageMessage = ""
            isRunningAgents = false
        }
    }

    func runRecommendedActions() {
        guard !isScanning, !isRunningAgents, !isRunningAgentActions, let run = activeRun else { return }
        isRunningAgentActions = true
        stageMessage = "Running recommended forensic actions..."

        Task { @MainActor in
            do {
                let updated = try await engine.performRecommendedActions(for: run)
                upsertRun(updated)
                selectedRunID = updated.id
                selectedRunKey = runKey(updated)
                try? await history.save(run: updated)
                statusMessage = "Recommended actions completed. Open Agent Actions report."
            } catch {
                statusMessage = "Recommended actions failed: \(error.localizedDescription)"
            }
            stageMessage = ""
            isRunningAgentActions = false
        }
    }

    func clearResults(removeFiles: Bool = true) {
        if removeFiles {
            let fm = FileManager.default
            for run in runs {
                let path = run.outputRoot
                if path.isEmpty || path == "/" { continue }
                let url = URL(fileURLWithPath: path)
                if fm.fileExists(atPath: url.path) {
                    try? fm.removeItem(at: url)
                }
            }
        }

        runs.removeAll()
        selectedRunID = nil
        selectedRunKey = nil
        activeForensicFacet = nil
        selectedItem = nil
        progress = ScanProgress()
        statusMessage = "Results cleared."
        investigationEngine.reset()

        Task {
            try? await history.clear()
        }
    }

    /// ✅ throttles UI refresh to ~10Hz to prevent churn on huge scans
    private func throttledTick() {
        let now = CFAbsoluteTimeGetCurrent()
        let minInterval: CFAbsoluteTime = 0.10 // 10 Hz

        if now - lastTickTime >= minInterval {
            lastTickTime = now
            itemTick &+= 1
            pendingTick = false
        } else if !pendingTick {
            pendingTick = true
            let delay = minInterval - (now - lastTickTime)
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: UInt64(max(delay, 0) * 1_000_000_000))
                self.lastTickTime = CFAbsoluteTimeGetCurrent()
                self.itemTick &+= 1
                self.pendingTick = false
            }
        }
    }

    private func validateReadableSources(_ urls: [URL]) -> (readable: [URL], unreadable: [String]) {
        var readable: [URL] = []
        var unreadable: [String] = []
        let fm = FileManager.default

        for url in urls {
            let path = url.path
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: path, isDirectory: &isDir) else {
                unreadable.append(url.lastPathComponent)
                continue
            }

            if isDir.boolValue {
                if (try? fm.contentsOfDirectory(atPath: path)) != nil {
                    readable.append(url)
                } else {
                    unreadable.append(url.lastPathComponent)
                }
            } else if fm.isReadableFile(atPath: path) {
                readable.append(url)
            } else {
                unreadable.append(url.lastPathComponent)
            }
        }
        return (readable, unreadable)
    }

    private func prettyStageName(_ raw: String) -> String {
        switch raw {
        case "forensic_sniff": return "Forensic Sniff"
        case "file_carve": return "File Carving"
        case "media_type": return "Media Typing"
        case "ai_classification": return "AI Classification"
        case "embeddings": return "Embeddings"
        case "archive_extract": return "Archive Extraction"
        default: return raw.replacingOccurrences(of: "_", with: " ").capitalized
        }
    }

    func runKey(_ run: ScanRun) -> String {
        "\(run.id.uuidString)|\(run.outputRoot)"
    }

    var activeForensicFacetLabel: String? {
        guard let activeForensicFacet else { return nil }
        switch activeForensicFacet {
        case .remFiles: return ".REM Files"
        case .mediaRecovered: return "Media Recovered"
        case .possibleDecryptableDBs: return "Possible Decryptable DBs"
        case .nestedArchives: return "Nested Archives"
        case .decryptableSignals: return "Decryptable Signals"
        case .thumbnails: return "Thumbnails"
        case .messageSignals: return "Message Signals"
        case .keys: return "Keys"
        case .emails: return "Emails"
        case .urls: return "URLs"
        case .phoneNumbers: return "Phone Numbers"
        case .languageText: return "Language Text"
        case .hashCandidates: return "Hash Candidates"
        case .aiSafe: return "AI Safe"
        case .aiSuggestive: return "AI Suggestive"
        case .aiExplicit: return "AI Explicit"
        case .aiUnknown: return "AI Unknown"
        }
    }

    var activeGraphPivotLabel: String? {
        investigationEngine.graphPivotLabel
    }

    func clearForensicFacet() {
        activeForensicFacet = nil
    }

    func clearSearch() {
        query = ""
    }

    func clearGraphPivot() {
        investigationEngine.clearGraphPivot()
        itemTick &+= 1
    }

    func clearAllFilters() {
        activeForensicFacet = nil
        query = ""
        clearGraphPivot()
        statusMessage = "Cleared active filters."
    }

    func applyGraphPivot(sourceFolder: String, detectedType: String) {
        investigationEngine.applyGraphPivot(sourceFolder: sourceFolder, detectedType: detectedType)
        route = .results
        statusMessage = "Filtering by graph relation: \(sourceFolder) -> \(detectedType)"
        itemTick &+= 1
    }

    func analyzerResult(for item: FoundItem) -> AnalyzerResult? {
        investigationEngine.analyzerResult(for: item)
    }

    func forensicCount(for facet: ForensicFacet) -> Int {
        investigationEngine.count(for: facet)
    }

    func reasonTags(limit: Int = 18) -> [(String, Int)] {
        investigationEngine.reasonTags(limit: limit)
    }

    func timelineItems(limit: Int = 1600) -> [(date: Date, item: FoundItem)] {
        investigationEngine.timelineEvents(limit: limit)
    }

    func evidenceGraphData() -> ([EvidenceGraphNodeModel], [EvidenceGraphEdgeModel]) {
        let graph = investigationEngine.graphData(limitItems: 3000)
        return (graph.nodes, graph.edges)
    }

    func saveInvestigationCase(name: String, notes: String, artifactIDs: Set<UUID>) {
        investigationEngine.saveCase(name: name, notes: notes, artifactIDs: artifactIDs)
    }

    private func upsertRun(_ run: ScanRun) {
        let key = runKey(run)
        runs.removeAll { runKey($0) == key }
        runs.insert(run, at: 0)
        runs = normalizeRuns(runs)
        sanitizeSelectionAfterRunsChange()
    }

    private func normalizeRuns(_ input: [ScanRun]) -> [ScanRun] {
        var seen = Set<String>()
        var output: [ScanRun] = []
        output.reserveCapacity(input.count)
        for run in input {
            let key = runKey(run)
            guard !seen.contains(key) else { continue }
            seen.insert(key)
            output.append(run)
        }
        return output
    }

    private func sanitizeSelectionAfterRunsChange() {
        guard !runs.isEmpty else {
            selectedRunID = nil
            selectedRunKey = nil
            return
        }
        if let key = selectedRunKey, runs.contains(where: { runKey($0) == key }) {
            return
        }
        selectedRunID = runs[0].id
        selectedRunKey = runKey(runs[0])
    }

    private func syncInvestigationContext() {
        investigationEngine.updateCategories(selectedCategories)
        investigationEngine.updateQuery(query)
        investigationEngine.applyForensicFacet(activeForensicFacet)
        investigationEngine.ingest(run: activeRun)
        itemTick &+= 1
    }
}
#endif
