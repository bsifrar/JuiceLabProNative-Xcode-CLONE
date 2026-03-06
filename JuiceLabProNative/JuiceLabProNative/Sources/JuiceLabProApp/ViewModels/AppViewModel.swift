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
        case forensic = "Forensic"
        case settings = "Settings"
    }

    @Published var route: Route? = .results
    @Published var settings = ScanSettings(enableAI: false)
    @Published var runs: [ScanRun] = []
    @Published var selectedRunID: UUID?
    @Published var selectedItem: FoundItem?
    @Published var query = ""
    @Published var selectedCategories = Set(FileCategory.allCases)
    @Published var progress = ScanProgress()
    @Published var isScanning = false
    @Published var isRunningAgents = false
    @Published var droppedURLs: [URL] = []
    @Published var statusMessage: String = ""
    @Published var stageMessage: String = ""

    /// UI refresh signal (throttled)
    @Published private(set) var itemTick: Int = 0

    private let engine = ScannerEngine()
    private let history = RunHistoryStore()

    /// ✅ cancellation handle
    private var scanTask: Task<Void, Never>?

    /// ✅ throttle state
    private var lastTickTime: CFAbsoluteTime = 0
    private var pendingTick: Bool = false

    init() {
        Task { runs = await history.load() }
    }

    var activeRun: ScanRun? {
        if let selectedRunID {
            return runs.first(where: { $0.id == selectedRunID })
        }
        return runs.first
    }

    var filteredItems: [FoundItem] {
        guard let run = activeRun else { return [] }
        _ = itemTick // drive reevaluation
        let filtered = run.items.filter { item in
            selectedCategories.contains(item.category) &&
            (query.isEmpty ||
             item.sourcePath.localizedCaseInsensitiveContains(query) ||
             item.detectedType.localizedCaseInsensitiveContains(query))
        }
        if filtered.count > maxVisibleItems {
            return Array(filtered.prefix(maxVisibleItems))
        }
        return filtered
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
        guard !droppedURLs.isEmpty, !isScanning else { return }
        isScanning = true
        statusMessage = ""
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

            runs.insert(doneRun, at: 0)
            selectedRunID = doneRun.id
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
                if let idx = runs.firstIndex(where: { $0.id == updated.id }) {
                    runs[idx] = updated
                } else {
                    runs.insert(updated, at: 0)
                }
                selectedRunID = updated.id
                try? await history.save(run: updated)
                statusMessage = "Agents completed. Open Agent Summary for results."
            } catch {
                statusMessage = "Agent run failed: \(error.localizedDescription)"
            }
            stageMessage = ""
            isRunningAgents = false
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
        selectedItem = nil
        progress = ScanProgress()
        statusMessage = "Results cleared."

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
}
#endif
