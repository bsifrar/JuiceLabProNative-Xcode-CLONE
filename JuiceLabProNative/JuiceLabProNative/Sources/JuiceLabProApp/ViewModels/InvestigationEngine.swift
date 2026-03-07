#if canImport(SwiftUI)
import Foundation
import JuiceLabCore

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

struct InvestigationCase: Identifiable, Sendable {
    let id: UUID
    var name: String
    var notes: String
    var artifactIDs: Set<UUID>

    init(id: UUID = UUID(), name: String, notes: String = "", artifactIDs: Set<UUID> = []) {
        self.id = id
        self.name = name
        self.notes = notes
        self.artifactIDs = artifactIDs
    }
}

private struct InvestigationArtifact: Sendable {
    let item: FoundItem
    let analyzer: AnalyzerResult?
    let sourceFolder: String
    let dayBucket: Date
    let searchableText: String
}

private struct ArtifactFilter: Sendable {
    var categories = Set(FileCategory.allCases)
    var query = ""
    var forensicFacet: ForensicFacet?
    var sourceFolderPivot: String?
    var detectedTypePivot: String?
}

private struct ArtifactIndex: Sendable {
    let allIDs: [UUID]
    let artifactsByID: [UUID: InvestigationArtifact]
    let analyzerBySourcePath: [String: AnalyzerResult]
    let idsByDay: [Date: Set<UUID>]
    let sourceFolderTypePairs: [String: Int]
    let tokenIndex: [String: Set<UUID>]

    init(run: ScanRun) {
        let analyzerBySourcePath = Dictionary(uniqueKeysWithValues: run.forensic.analyzerResults.map { ($0.sourcePath, $0) })
        var allIDs: [UUID] = []
        allIDs.reserveCapacity(run.items.count)

        var artifactsByID: [UUID: InvestigationArtifact] = [:]
        artifactsByID.reserveCapacity(run.items.count)

        var idsByDay: [Date: Set<UUID>] = [:]
        var sourceFolderTypePairs: [String: Int] = [:]
        var tokenIndex: [String: Set<UUID>] = [:]

        let calendar = Calendar.current
        let maxCharsPerItem = 6000

        for item in run.items {
            let analyzer = analyzerBySourcePath[item.sourcePath]
            let sourceFolder = URL(fileURLWithPath: item.sourcePath).deletingLastPathComponent().lastPathComponent
            let day = Self.dayBucket(for: item, runFallbackDate: run.startedAt, calendar: calendar)

            var fields = [
                item.sourcePath,
                sourceFolder,
                item.detectedType,
                item.fileExtension,
                item.category.rawValue
            ]

            if let analyzer {
                fields.append(analyzer.nsfwSeverity.rawValue)
                fields.append(String(analyzer.nsfwScore))
                for detection in analyzer.reasonDetections ?? [] {
                    fields.append(detection.reason.rawValue)
                    fields.append(detection.modelLabel)
                    if let notes = detection.notes {
                        fields.append(notes)
                    }
                }
            }

            if let textSnippet = Self.readSearchableSnippet(for: item) {
                fields.append(textSnippet)
            }

            let searchableText = String(fields.joined(separator: " ").lowercased().prefix(maxCharsPerItem))
            for token in Self.tokenize(searchableText) {
                tokenIndex[token, default: []].insert(item.id)
            }

            let artifact = InvestigationArtifact(
                item: item,
                analyzer: analyzer,
                sourceFolder: sourceFolder,
                dayBucket: day,
                searchableText: searchableText
            )
            artifactsByID[item.id] = artifact
            allIDs.append(item.id)
            idsByDay[day, default: []].insert(item.id)

            let pairKey = "\(sourceFolder)|\(item.detectedType.uppercased())"
            sourceFolderTypePairs[pairKey, default: 0] += 1
        }

        self.allIDs = allIDs
        self.artifactsByID = artifactsByID
        self.analyzerBySourcePath = analyzerBySourcePath
        self.idsByDay = idsByDay
        self.sourceFolderTypePairs = sourceFolderTypePairs
        self.tokenIndex = tokenIndex
    }

    func candidateIDs(for query: String) -> Set<UUID> {
        guard !query.isEmpty else { return [] }
        let terms = query.lowercased()
            .split(whereSeparator: { !$0.isLetter && !$0.isNumber })
            .map { String($0) }
            .filter { $0.count >= 3 }

        guard !terms.isEmpty else { return [] }

        var candidates = Set<UUID>()
        for term in terms {
            for variant in Self.searchTokenVariants(for: term) {
                if let ids = tokenIndex[variant] {
                    candidates.formUnion(ids)
                }
            }
        }
        return candidates
    }

    private static func dayBucket(for item: FoundItem, runFallbackDate: Date, calendar: Calendar) -> Date {
        let path = item.outputPath ?? item.sourcePath
        let attrs = try? FileManager.default.attributesOfItem(atPath: path)
        let date = (attrs?[.creationDate] as? Date)
            ?? (attrs?[.modificationDate] as? Date)
            ?? runFallbackDate
        return calendar.startOfDay(for: date)
    }

    private static func tokenize(_ text: String) -> Set<String> {
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

    private static func searchTokenVariants(for token: String) -> Set<String> {
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

    private static func readSearchableSnippet(for item: FoundItem) -> String? {
        let ext = item.fileExtension.lowercased()
        let textish: Set<String> = [
            "txt", "md", "rtf", "csv", "json", "xml", "html", "htm", "log",
            "plist", "vcard", "vcf", "sql", "db", "sqlite", "sqlite3"
        ]
        guard textish.contains(ext) else { return nil }

        let path = item.outputPath ?? item.sourcePath
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe) else { return nil }
        let chunk = data.prefix(32_000)

        if let s = String(data: chunk, encoding: .utf8) ?? String(data: chunk, encoding: .ascii) {
            return s
        }

        let bytes = [UInt8](chunk)
        var out = ""
        var current = ""
        for b in bytes {
            if (32...126).contains(Int(b)) || b == 9 || b == 10 || b == 13 {
                current.append(Character(UnicodeScalar(Int(b))!))
            } else {
                if current.count >= 4 {
                    out.append(current)
                    out.append("\n")
                }
                current.removeAll(keepingCapacity: true)
            }
        }

        if current.count >= 4 {
            out.append(current)
        }

        return out.isEmpty ? nil : out
    }
}

@MainActor
final class InvestigationEngine {
    private(set) var activeRun: ScanRun?
    private(set) var cases: [InvestigationCase] = []

    private var index: ArtifactIndex?
    private var filter = ArtifactFilter()

    func ingest(run: ScanRun?) {
        activeRun = run
        if let run {
            index = ArtifactIndex(run: run)
        } else {
            index = nil
        }
    }

    func reset() {
        activeRun = nil
        index = nil
        filter = ArtifactFilter()
        cases.removeAll()
    }

    func updateCategories(_ categories: Set<FileCategory>) {
        filter.categories = categories
    }

    func updateQuery(_ query: String) {
        filter.query = query.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func applyForensicFacet(_ facet: ForensicFacet?) {
        filter.forensicFacet = facet
    }

    func clearForensicFacet() {
        filter.forensicFacet = nil
    }

    func applyGraphPivot(sourceFolder: String?, detectedType: String?) {
        filter.sourceFolderPivot = sourceFolder
        filter.detectedTypePivot = detectedType?.uppercased()
    }

    func clearGraphPivot() {
        filter.sourceFolderPivot = nil
        filter.detectedTypePivot = nil
    }

    func clearSearch() {
        filter.query = ""
    }

    func clearAllFilters() {
        filter.forensicFacet = nil
        filter.query = ""
        filter.sourceFolderPivot = nil
        filter.detectedTypePivot = nil
    }

    var activeForensicFacet: ForensicFacet? {
        filter.forensicFacet
    }

    var activeQuery: String {
        filter.query
    }

    var hasGraphPivot: Bool {
        filter.sourceFolderPivot != nil || filter.detectedTypePivot != nil
    }

    var graphPivotLabel: String? {
        guard hasGraphPivot else { return nil }
        let source = filter.sourceFolderPivot ?? "Any Source"
        let type = filter.detectedTypePivot ?? "Any Type"
        return "\(source) -> \(type)"
    }

    func filteredItems(limit: Int? = nil) -> [FoundItem] {
        guard let index else { return [] }
        let query = filter.query.lowercased()
        let queryCandidates = index.candidateIDs(for: query)

        var output: [FoundItem] = []
        output.reserveCapacity(min(index.allIDs.count, 4000))

        for id in index.allIDs {
            guard let artifact = index.artifactsByID[id] else { continue }
            let item = artifact.item

            if !filter.categories.contains(item.category) {
                continue
            }
            if let sourceFolderPivot = filter.sourceFolderPivot,
               artifact.sourceFolder.caseInsensitiveCompare(sourceFolderPivot) != .orderedSame {
                continue
            }
            if let detectedTypePivot = filter.detectedTypePivot,
               item.detectedType.uppercased() != detectedTypePivot {
                continue
            }
            if !matchesForensicFacet(item: item, analyzer: artifact.analyzer, facet: filter.forensicFacet) {
                continue
            }
            if !query.isEmpty {
                if !queryCandidates.contains(item.id), !artifact.searchableText.contains(query) {
                    continue
                }
            }

            output.append(item)
            if let limit, output.count >= limit {
                break
            }
        }

        return output
    }

    func analyzerResult(for item: FoundItem) -> AnalyzerResult? {
        index?.analyzerBySourcePath[item.sourcePath]
    }

    func count(for facet: ForensicFacet) -> Int {
        guard let index else { return 0 }
        var count = 0
        for id in index.allIDs {
            guard let artifact = index.artifactsByID[id] else { continue }
            if matchesForensicFacet(item: artifact.item, analyzer: artifact.analyzer, facet: facet) {
                count += 1
            }
        }
        return count
    }

    func reasonTags(limit: Int = 18) -> [(String, Int)] {
        guard let run = activeRun else { return [] }
        var counts: [String: Int] = [:]

        for result in run.forensic.analyzerResults {
            for detection in result.reasonDetections ?? [] {
                counts[detection.reason.rawValue, default: 0] += 1
            }
        }

        return counts
            .sorted { lhs, rhs in
                if lhs.value == rhs.value { return lhs.key < rhs.key }
                return lhs.value > rhs.value
            }
            .prefix(limit)
            .map { ($0.key, $0.value) }
    }

    func timelineEvents(limit: Int = 1600) -> [(date: Date, item: FoundItem)] {
        guard let index else { return [] }

        var rows: [(date: Date, item: FoundItem)] = []
        rows.reserveCapacity(min(limit, index.allIDs.count))

        for item in filteredItems(limit: limit) {
            guard let artifact = index.artifactsByID[item.id] else { continue }
            rows.append((artifact.dayBucket, item))
        }

        rows.sort { $0.date > $1.date }
        return rows
    }

    func graphData(limitItems: Int = 3000) -> (nodes: [EvidenceGraphNodeModel], edges: [EvidenceGraphEdgeModel]) {
        let scoped = filteredItems(limit: limitItems)
        guard !scoped.isEmpty else { return ([], []) }

        var sourceCounts: [String: Int] = [:]
        var typeCounts: [String: Int] = [:]
        var pairCounts: [String: Int] = [:]

        for item in scoped {
            let sourceFolder = URL(fileURLWithPath: item.sourcePath).deletingLastPathComponent().lastPathComponent
            let type = item.detectedType.uppercased()
            sourceCounts[sourceFolder, default: 0] += 1
            typeCounts[type, default: 0] += 1
            pairCounts["\(sourceFolder)|\(type)", default: 0] += 1
        }

        let topSources = sourceCounts.sorted { $0.value > $1.value }.prefix(12)
        let topTypes = typeCounts.sorted { $0.value > $1.value }.prefix(10)

        let sourceSet = Set(topSources.map(\.key))
        let typeSet = Set(topTypes.map(\.key))

        let nodes = topSources.map { EvidenceGraphNodeModel(id: "src:\($0.key)", title: $0.key, kind: "source", count: $0.value) }
            + topTypes.map { EvidenceGraphNodeModel(id: "type:\($0.key)", title: $0.key, kind: "type", count: $0.value) }

        let edges = pairCounts.compactMap { key, value -> EvidenceGraphEdgeModel? in
            let parts = key.split(separator: "|", maxSplits: 1).map(String.init)
            guard parts.count == 2 else { return nil }
            let source = parts[0]
            let type = parts[1]
            guard sourceSet.contains(source), typeSet.contains(type) else { return nil }
            return EvidenceGraphEdgeModel(from: "src:\(source)", to: "type:\(type)", weight: value)
        }
        .sorted { $0.weight > $1.weight }
        .prefix(40)

        return (nodes, Array(edges))
    }

    func saveCase(name: String, notes: String, artifactIDs: Set<UUID>) {
        let normalizedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedName.isEmpty else { return }

        if let idx = cases.firstIndex(where: { $0.name.caseInsensitiveCompare(normalizedName) == .orderedSame }) {
            cases[idx].notes = notes
            cases[idx].artifactIDs = artifactIDs
        } else {
            cases.insert(InvestigationCase(name: normalizedName, notes: notes, artifactIDs: artifactIDs), at: 0)
        }
    }

    private func matchesForensicFacet(item: FoundItem, analyzer: AnalyzerResult?, facet: ForensicFacet?) -> Bool {
        guard let facet else { return true }

        let ext = item.fileExtension.lowercased()
        let type = item.detectedType.lowercased()
        let path = item.sourcePath.lowercased()

        let textishExts: Set<String> = [
            "txt", "md", "rtf", "csv", "json", "xml", "html", "htm", "log",
            "plist", "vcf", "sql", "db", "sqlite", "sqlite3", "eml", "msg", "mbox", "pst", "ost"
        ]

        switch facet {
        case .remFiles:
            return ext == "rem" || path.hasSuffix(".rem") || type.contains("rem")
        case .mediaRecovered:
            return item.category == .images || item.category == .video || item.category == .audio
        case .possibleDecryptableDBs:
            return ["db", "sqlite", "sqlite3", "sqlitedb"].contains(ext)
                || type.contains("sqlite")
                || type.contains("database")
        case .nestedArchives:
            return item.category == .archives
        case .decryptableSignals:
            return ["db", "sqlite", "sqlite3", "plist", "bplist", "key", "pem", "p12", "pfx"].contains(ext)
                || path.contains("keychain")
                || type.contains("decrypt")
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
            let mailPath = path.contains("/mail/") || path.contains("/emails/") || path.contains("inbox")
            return mailPath && textishExts.contains(ext)
        case .urls:
            if item.category == .audio || item.category == .video || item.category == .images { return false }
            return ["url", "webloc", "html", "htm", "txt", "csv", "json", "xml", "log"].contains(ext) || path.contains("url")
        case .phoneNumbers:
            if item.category == .audio || item.category == .video || item.category == .images || item.category == .archives {
                return false
            }
            let phoneDataExts: Set<String> = ["vcf", "csv", "txt", "html", "htm", "json", "xml", "db", "sqlite", "sqlite3", "plist", "log"]
            let likelyPhonePath = path.contains("contact")
                || path.contains("addressbook")
                || path.contains("call")
                || path.contains("sms")
                || path.contains("message")
                || path.contains("phone")
            return phoneDataExts.contains(ext) && likelyPhonePath
        case .languageText:
            return item.category == .text || textishExts.contains(ext)
        case .hashCandidates:
            return path.contains("hash") || type.contains("hash")
        case .aiSafe:
            return analyzer?.nsfwSeverity == NSFWSeverity.none
        case .aiSuggestive:
            return analyzer?.nsfwSeverity == .suggestive
        case .aiExplicit:
            return analyzer?.nsfwSeverity == .explicit
        case .aiUnknown:
            return analyzer?.nsfwSeverity == .unknown
        }
    }
}

struct EvidenceGraphNodeModel: Identifiable, Hashable {
    let id: String
    let title: String
    let kind: String
    let count: Int
}

struct EvidenceGraphEdgeModel: Identifiable {
    let id = UUID()
    let from: String
    let to: String
    let weight: Int
}
#endif
