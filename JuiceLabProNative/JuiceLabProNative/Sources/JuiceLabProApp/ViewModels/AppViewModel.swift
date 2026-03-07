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

    enum ForensicFacet: String, Sendable, Equatable {
        case remFiles
        case mediaRecovered
        case possibleDecryptableDBs
        case nestedArchives
        case decryptableSignals
        case thumbnails
        case messageSignals
        case keys
        case emails
        case urls
        case phoneNumbers
        case languageText
        case hashCandidates
        case aiSafe
        case aiSuggestive
        case aiExplicit
        case aiUnknown
    }

    @Published var route: Route? = .results
    @Published var settings = ScanSettings(dedupeMode: .exactBytes, enableAI: true)
    @Published var runs: [ScanRun] = []
    @Published var selectedRunID: UUID?
    @Published var selectedRunKey: String?
    @Published var activeForensicFacet: ForensicFacet?
    @Published var selectedItem: FoundItem?
    @Published var query = ""
    @Published var selectedCategories = Set(FileCategory.allCases)
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
    private var contentSearchIndex: [UUID: String] = [:]
    private var tokenSearchIndex: [String: Set<UUID>] = [:]
    private var indexedRunID: UUID?
    private var indexingTask: Task<Void, Never>?

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
        guard let run = activeRun else { return [] }
        _ = itemTick // drive reevaluation
        ensureSearchIndex(for: run)
        let analyzerByPath = Dictionary(
            uniqueKeysWithValues: run.forensic.analyzerResults.map { ($0.sourcePath, $0) }
        )
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let queryCandidates = candidateItemIDs(for: q)
        let filtered = run.items.filter { item in
            selectedCategories.contains(item.category) &&
            matchesForensicFacet(item: item, analyzer: analyzerByPath[item.sourcePath]) &&
            (q.isEmpty || queryCandidates.contains(item.id) || matchesQuery(item: item, query: q))
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
            rebuildSearchIndex(for: doneRun)
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
        contentSearchIndex.removeAll()
        tokenSearchIndex.removeAll()
        indexedRunID = nil
        indexingTask?.cancel()
        indexingTask = nil

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

    private func matchesQuery(item: FoundItem, query: String) -> Bool {
        if item.sourcePath.lowercased().contains(query) ||
            item.detectedType.lowercased().contains(query) ||
            item.fileExtension.lowercased().contains(query) {
            return true
        }
        if let indexed = contentSearchIndex[item.id], indexed.contains(query) {
            return true
        }
        return false
    }

    private func matchesForensicFacet(item: FoundItem, analyzer: AnalyzerResult?) -> Bool {
        guard let facet = activeForensicFacet else { return true }

        let ext = item.fileExtension.lowercased()
        let type = item.detectedType.lowercased()
        let path = item.sourcePath.lowercased()
        let textishExts: Set<String> = [
            "txt", "md", "rtf", "csv", "json", "xml", "html", "htm", "log",
            "plist", "vcf", "sql", "db", "sqlite", "sqlite3"
        ]

        switch facet {
        case .remFiles:
            return ext == "rem" || path.hasSuffix(".rem") || type.contains("rem")
        case .mediaRecovered:
            return item.category == .images || item.category == .video || item.category == .audio
        case .possibleDecryptableDBs:
            return ["db", "sqlite", "sqlite3", "sqlitedb"].contains(ext) ||
                type.contains("sqlite") || type.contains("database")
        case .nestedArchives:
            return item.category == .archives
        case .decryptableSignals:
            return ["db", "sqlite", "sqlite3", "plist", "bplist", "key", "pem", "p12", "pfx"].contains(ext) ||
                path.contains("keychain") || type.contains("decrypt")
        case .thumbnails:
            return path.contains("thumb") || path.contains("thumbnail") || type.contains("thumbnail")
        case .messageSignals:
            return path.contains("message") || path.contains("sms") || path.contains("chat")
        case .keys:
            return path.contains("key") || ["key", "pem", "p12", "pfx", "cer", "crt", "der"].contains(ext)
        case .emails:
            if item.category == .audio || item.category == .video || item.category == .images { return false }
            let emailExts: Set<String> = ["eml", "msg", "mbox", "pst", "ost"]
            if emailExts.contains(ext) { return true }
            return (path.contains("/mail/") || path.contains("/emails/")) && textishExts.contains(ext)
        case .urls:
            return ["url", "webloc", "html", "htm"].contains(ext) || path.contains("url")
        case .phoneNumbers:
            if item.category == .audio || item.category == .video || item.category == .images || item.category == .archives { return false }
            let phoneDataExts: Set<String> = ["vcf", "csv", "txt", "html", "htm", "json", "xml", "db", "sqlite", "sqlite3", "plist", "log"]
            let likelyPhoneDataPath = path.contains("contact")
                || path.contains("addressbook")
                || path.contains("call")
                || path.contains("sms")
                || path.contains("message")
                || path.contains("phone")
            return phoneDataExts.contains(ext) && likelyPhoneDataPath
        case .languageText:
            return item.category == .text || textishExts.contains(ext)
        case .hashCandidates:
            return path.contains("hash") || type.contains("hash")
        case .aiSafe:
            return analyzer?.nsfwSeverity == NSFWSeverity.none
        case .aiSuggestive:
            return analyzer?.nsfwSeverity == NSFWSeverity.suggestive
        case .aiExplicit:
            return analyzer?.nsfwSeverity == NSFWSeverity.explicit
        case .aiUnknown:
            return analyzer?.nsfwSeverity == NSFWSeverity.unknown
        }
    }

    private func ensureSearchIndex(for run: ScanRun) {
        guard indexedRunID != run.id, indexingTask == nil else { return }
        rebuildSearchIndex(for: run)
    }

    private func rebuildSearchIndex(for run: ScanRun) {
        indexingTask?.cancel()
        indexedRunID = run.id
        contentSearchIndex = [:]
        tokenSearchIndex = [:]

        indexingTask = Task.detached(priority: .utility) { [weak self] in
            guard let self else { return }
            let analyzerByPath: [String: AnalyzerResult] = Dictionary(
                uniqueKeysWithValues: run.forensic.analyzerResults.map { ($0.sourcePath, $0) }
            )
            var index: [UUID: String] = [:]
            var tokens: [String: Set<UUID>] = [:]
            let maxCharsPerItem = 6000

            for item in run.items {
                if Task.isCancelled { return }
                var fields: [String] = [
                    item.sourcePath,
                    item.detectedType,
                    item.fileExtension,
                    item.category.rawValue
                ]

                if let ar = analyzerByPath[item.sourcePath] {
                    fields.append(ar.nsfwSeverity.rawValue)
                    fields.append(String(ar.nsfwScore))
                    for det in ar.reasonDetections ?? [] {
                        fields.append(det.reason.rawValue)
                        fields.append(det.modelLabel)
                        if let notes = det.notes { fields.append(notes) }
                    }
                }

                if let textSnippet = Self.readSearchableSnippet(for: item) {
                    fields.append(textSnippet)
                }

                let merged = fields
                    .joined(separator: " ")
                    .lowercased()
                let truncated = String(merged.prefix(maxCharsPerItem))
                index[item.id] = truncated

                // Inverted index for fast term-based lookups on large runs.
                let terms = Self.tokenize(truncated)
                for term in terms {
                    tokens[term, default: []].insert(item.id)
                }
            }

            let builtIndex = index
            let builtTokens = tokens
            await MainActor.run {
                self.contentSearchIndex = builtIndex
                self.tokenSearchIndex = builtTokens
                self.itemTick &+= 1
                self.indexingTask = nil
            }
        }
    }

    private nonisolated static func tokenize(_ text: String) -> Set<String> {
        var out = Set<String>()
        out.reserveCapacity(128)
        for piece in text.split(whereSeparator: { !$0.isLetter && !$0.isNumber }) {
            let raw = String(piece.prefix(48)).lowercased()
            if raw.count < 3 { continue }
            for variant in searchTokenVariants(for: raw) {
                out.insert(variant)
            }
            if out.count >= 300 { break }
        }
        return out
    }

    private func candidateItemIDs(for query: String) -> Set<UUID> {
        guard !query.isEmpty else { return [] }
        let terms = query.lowercased()
            .split(whereSeparator: { !$0.isLetter && !$0.isNumber })
            .map { String($0) }
            .filter { $0.count >= 3 }
        guard !terms.isEmpty else { return [] }

        var running = Set<UUID>()
        for term in terms {
            var bucket = Set<UUID>()
            for variant in Self.searchTokenVariants(for: term) {
                if let ids = tokenSearchIndex[variant] {
                    bucket.formUnion(ids)
                }
            }
            if bucket.isEmpty { continue }
            running.formUnion(bucket)
        }
        return running
    }

    private nonisolated static func searchTokenVariants(for token: String) -> Set<String> {
        var out = Set<String>()
        var normalized = token
            .lowercased()
            .replacingOccurrences(of: "_", with: "")
            .replacingOccurrences(of: "-", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard normalized.count >= 3 else { return out }

        let alias: [String: String] = [
            "baloon": "balloon",
            "ballon": "balloon",
            "cellphone": "iphone",
            "mobilephone": "iphone",
            "smartphone": "iphone",
            "iphones": "iphone",
            "breasts": "breast",
            "penises": "penis",
            "genitals": "genital",
            "boates": "boat"
        ]
        if let mapped = alias[normalized] {
            normalized = mapped
        }

        out.insert(normalized)

        if normalized.hasSuffix("ies"), normalized.count > 4 {
            let stem = String(normalized.dropLast(3)) + "y"
            if stem.count >= 3 { out.insert(stem) }
        } else if normalized.hasSuffix("es"), normalized.count > 4 {
            let stem = String(normalized.dropLast(2))
            if stem.count >= 3 { out.insert(stem) }
        } else if normalized.hasSuffix("s"), normalized.count > 3 {
            let stem = String(normalized.dropLast())
            if stem.count >= 3 { out.insert(stem) }
        }

        return out
    }

    private nonisolated static func readSearchableSnippet(for item: FoundItem) -> String? {
        let ext = item.fileExtension.lowercased()
        let textish: Set<String> = [
            "txt", "md", "rtf", "csv", "json", "xml", "html", "htm", "log",
            "plist", "vcard", "vcf", "sql", "db", "sqlite", "sqlite3"
        ]
        guard textish.contains(ext) else { return nil }

        let path = item.outputPath ?? item.sourcePath
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe) else { return nil }
        let chunk = data.prefix(80_000)

        if let s = String(data: chunk, encoding: .utf8) ?? String(data: chunk, encoding: .ascii) {
            return s
        }

        // Fallback for binary-ish text containers (db/plist cache): extract printable runs.
        let bytes = [UInt8](chunk)
        var out = ""
        var cur = ""
        for b in bytes {
            if (32...126).contains(Int(b)) || b == 9 || b == 10 || b == 13 {
                cur.append(Character(UnicodeScalar(Int(b))!))
            } else {
                if cur.count >= 4 {
                    out.append(cur)
                    out.append("\n")
                }
                cur.removeAll(keepingCapacity: true)
            }
        }
        if cur.count >= 4 {
            out.append(cur)
        }
        return out.isEmpty ? nil : out
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

    func clearForensicFacet() {
        activeForensicFacet = nil
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
}
#endif
