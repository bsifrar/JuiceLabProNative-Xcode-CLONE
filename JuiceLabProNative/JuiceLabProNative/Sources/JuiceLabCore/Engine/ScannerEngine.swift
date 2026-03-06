import Foundation

#if canImport(AVFoundation)
import AVFoundation
#endif

#if canImport(CoreGraphics)
import CoreGraphics
#endif

#if canImport(ImageIO)
import ImageIO
#endif

#if canImport(PDFKit)
import PDFKit
#endif

#if canImport(UniformTypeIdentifiers)
import UniformTypeIdentifiers
#endif

#if canImport(CryptoKit)
import CryptoKit
#endif

#if canImport(SQLite3)
import SQLite3
#endif

#if canImport(ZIPFoundation)
import ZIPFoundation
#endif

public actor ScannerEngine {
    public typealias ProgressHandler = @Sendable (ScanProgress) -> Void
    public typealias ItemHandler = @Sendable (FoundItem) -> Void
    public typealias StageHandler = @Sendable (_ fileName: String, _ stageName: String) -> Void

    // MARK: - Pipeline Types

    struct ScanContext: Sendable {
        let settings: ScanSettings
        let runName: String
        let runID: UUID

        #if APPSTORE
        let enableArchiveExtraction: Bool = false
        #else
        let enableArchiveExtraction: Bool = true
        #endif

        let enableAIClassification: Bool
        let enableEmbeddings: Bool
        let settingsFingerprint: String

        init(settings: ScanSettings, runName: String, runID: UUID) {
            self.settings = settings
            self.runName = runName
            self.runID = runID
            self.enableAIClassification = settings.enableAI
            self.enableEmbeddings = settings.enableEmbeddings
            self.settingsFingerprint = settings.fingerprint()
        }
    }

    struct StageOutput: Sendable {
        var items: [FoundItem] = []
        var warnings: [String] = []
        var forensicDelta: ForensicDelta = .init()
        var analyzerResults: [AnalyzerResult] = []
        var extraFilesToScan: [URL] = []
        var stageTimingsMS: [String: Int] = [:]
    }

    struct ForensicDelta: Sendable {
        var remCount: Int = 0
        var mediaCount: Int = 0
        var possibleDecryptableDBs: Int = 0
        var keyFiles: [String] = []
        var nestedArchives: Int = 0
        var metrics: [String: Int] = [:]

        mutating func merge(_ other: ForensicDelta) {
            remCount += other.remCount
            mediaCount += other.mediaCount
            possibleDecryptableDBs += other.possibleDecryptableDBs
            nestedArchives += other.nestedArchives
            if !other.keyFiles.isEmpty { keyFiles.append(contentsOf: other.keyFiles) }
            if !other.metrics.isEmpty {
                for (k, v) in other.metrics {
                    metrics[k, default: 0] += v
                }
            }
        }
    }

    protocol ScanStage: Sendable {
        var name: String { get }
        func process(file: URL, data: Data, context: ScanContext) async -> StageOutput
    }

    private let maxArchiveDepth = 2
    public init() {}

    // MARK: - Local hashing (for embedding content hashes)

    private enum Hashing {
        static func hexSHA256(_ data: Data) -> String {
            #if canImport(CryptoKit)
            let digest = SHA256.hash(data: data)
            return digest.map { String(format: "%02x", $0) }.joined()
            #else
            // stable fallback (non-crypto)
            return String(data.reduce(into: UInt64(1469598103934665603)) { h, b in
                h ^= UInt64(b)
                h &*= 1099511628211
            })
            #endif
        }
    }

    // MARK: - Scan

    public func scan(
        paths: [URL],
        settings: ScanSettings,
        onProgress: ProgressHandler? = nil,
        onItem: ItemHandler? = nil,
        onStage: StageHandler? = nil
    ) async -> ScanRun {

        let runName = "Run_\(Int(Date().timeIntervalSince1970))"

        var run = ScanRun(
            name: runName,
            sourceRoots: paths.map(\.path),
            settings: settings,
            settingsFingerprint: "",
            outputRoot: settings.outputFolder,
            items: [],
            warnings: [],
            mode: settings.performanceMode,
            forensic: ForensicSummary()
        )

        let context = ScanContext(settings: settings, runName: runName, runID: run.id)
        run.settingsFingerprint = context.settingsFingerprint

        let allFiles = collectFiles(from: paths, enabledTypes: settings.enabledTypes)
        if allFiles.isEmpty {
            run.warnings.append(
                "No candidate files found in selected sources. The source may be empty, hidden-only, unreadable, or filtered by extension settings."
            )
            run.completedAt = Date()
            return run
        }

        let tempRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent(runName, isDirectory: true)
        try? FileManager.default.createDirectory(at: tempRoot, withIntermediateDirectories: true)

        let stages = buildStages(tempRoot: tempRoot)

        var seenPaths = Set<String>()
        var extractBudget: Int64 = 200 * 1_048_576

        var filesToScan = allFiles
        var cursor = 0

        let initialTotalBytes = filesToScan.reduce(into: Int64(0)) { partial, url in
            partial += (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize).map(Int64.init) ?? 0
        }

        let started = Date()
        var progress = ScanProgress(
            bytesScanned: 0,
            totalBytes: initialTotalBytes,
            mbPerSecond: 0,
            etaSeconds: 0,
            currentFile: ""
        )

        var stageTotalMS: [String: Int] = [:]
        var stageFiles: [String: Int] = [:]

        while cursor < filesToScan.count {
            if Task.isCancelled { break }

            let chunkSize = settings.performanceMode.batchSize
            let end = min(cursor + chunkSize, filesToScan.count)
            let batch = Array(filesToScan[cursor..<end])
            cursor = end

            await withTaskGroup(of: (StageOutput, Int64, String).self) { group in
                for file in batch {
                    group.addTask { [stages] in
                        let size = (try? file.resourceValues(forKeys: [.fileSizeKey]).fileSize).map(Int64.init) ?? 0

                        if let capMB = settings.maxFileSizeMB {
                            let capBytes = Int64(capMB) * 1_048_576
                            if size > capBytes {
                                var out = StageOutput()
                                out.warnings.append("Skipped (size cap): \(file.lastPathComponent)")
                                return (out, 0, file.lastPathComponent)
                            }
                        }

                        let data = (try? Data(contentsOf: file, options: .mappedIfSafe)) ?? Data()

                        var combined = StageOutput()
                        for stage in stages {
                            if Task.isCancelled { break }
                            onStage?(file.lastPathComponent, stage.name)
                            let t0 = DispatchTime.now()
                            let o = await stage.process(file: file, data: data, context: context)
                            let dt = Int((DispatchTime.now().uptimeNanoseconds - t0.uptimeNanoseconds) / 1_000_000)
                            combined.stageTimingsMS[stage.name, default: 0] += dt

                            combined.items.append(contentsOf: o.items)
                            combined.warnings.append(contentsOf: o.warnings)
                            combined.forensicDelta.merge(o.forensicDelta)
                            if !o.analyzerResults.isEmpty { combined.analyzerResults.append(contentsOf: o.analyzerResults) }
                            if !o.extraFilesToScan.isEmpty { combined.extraFilesToScan.append(contentsOf: o.extraFilesToScan) }
                        }

                        return (combined, size, file.lastPathComponent)
                    }
                }

                for await (out, bytes, current) in group {
                    if Task.isCancelled { break }

                    progress.bytesScanned += bytes
                    progress.currentFile = current
                    updateRates(&progress, started: started)
                    onProgress?(progress)

                    if !out.items.isEmpty {
                        run.items.append(contentsOf: out.items)
                        if let handler = onItem {
                            for it in out.items { handler(it) }
                        }
                    }
                    if !out.warnings.isEmpty { run.warnings.append(contentsOf: out.warnings) }

                    run.forensic.remCount += out.forensicDelta.remCount
                    run.forensic.mediaCount += out.forensicDelta.mediaCount
                    run.forensic.possibleDecryptableDBs += out.forensicDelta.possibleDecryptableDBs
                    run.forensic.nestedArchives += out.forensicDelta.nestedArchives
                    if !out.forensicDelta.keyFiles.isEmpty { run.forensic.keyFiles.append(contentsOf: out.forensicDelta.keyFiles) }
                    if !out.forensicDelta.metrics.isEmpty {
                        var existing = run.forensic.metrics ?? [:]
                        for (k, v) in out.forensicDelta.metrics {
                            existing[k, default: 0] += v
                        }
                        run.forensic.metrics = existing
                    }

                    if !out.analyzerResults.isEmpty {
                        run.forensic.analyzerResults.append(contentsOf: out.analyzerResults)
                    }

                    for (k, v) in out.stageTimingsMS {
                        stageTotalMS[k, default: 0] += v
                        stageFiles[k, default: 0] += 1
                    }

                    if context.enableArchiveExtraction, !out.extraFilesToScan.isEmpty, extractBudget > 0 {
                        for f in out.extraFilesToScan {
                            let id = f.path
                            if seenPaths.contains(id) { continue }
                            seenPaths.insert(id)

                            let s = (try? f.resourceValues(forKeys: [.fileSizeKey]).fileSize).map(Int64.init) ?? 0
                            if s > 0, extractBudget - s >= 0 {
                                extractBudget -= s
                                filesToScan.append(f)
                                progress.totalBytes += s
                            }
                            if extractBudget <= 0 { break }
                        }
                    }
                }
            }
        }

        run.forensic.stageTimings = stageTotalMS.keys.sorted().map { stage in
            let total = stageTotalMS[stage] ?? 0
            let files = stageFiles[stage] ?? 0
            let avg = files > 0 ? (total / files) : 0
            return StageTiming(stage: stage, files: files, totalMS: total, avgMS: avg)
        }

        let dedupeOutcome = dedupe(items: run.items, mode: settings.dedupeMode)
        run.items = dedupeOutcome.items
        run.dedupeRemoved = dedupeOutcome.removed
        if !dedupeOutcome.removed.isEmpty {
            var metrics = run.forensic.metrics ?? [:]
            metrics["deduped_items", default: 0] += dedupeOutcome.removed.count
            run.forensic.metrics = metrics
            run.warnings.append("Dedupe removed \(dedupeOutcome.removed.count) exact-byte duplicates.")
        }
        run.completedAt = .now
        return run
    }

    // MARK: - Export (Reproducibility Mode)

    public func export(run: ScanRun) async throws -> ScanRun {
        var updated = run

        let runDirName = "\(run.name)-\(Self.dateStamp())"
        let baseOut = resolveWritableOutputBase(preferred: URL(fileURLWithPath: run.settings.outputFolder, isDirectory: true))
        let runRoot = baseOut
            .appendingPathComponent(runDirName, isDirectory: true)
        try FileManager.default.createDirectory(at: runRoot, withIntermediateDirectories: true)
        updated.settings.outputFolder = baseOut.path

        // 1) Copy files
        let exportedItems = exportItems(run: run, to: runRoot)
        updated.items = exportedItems
        _ = generateSQLiteArtifacts(for: &updated, at: runRoot)
        _ = generatePlistArtifacts(for: &updated, at: runRoot)
        _ = generatePDFTextArtifacts(for: &updated, at: runRoot)
        _ = generateBinaryStringArtifacts(for: &updated, at: runRoot)
        _ = generateURLArtifacts(for: &updated, at: runRoot)
        _ = generateAllTextArtifact(for: &updated, at: runRoot)
        _ = generateHashCandidateArtifacts(for: &updated, at: runRoot)
        _ = generateEvidenceIntelligenceReport(for: updated, at: runRoot)
        _ = generateAgentOutputs(for: updated, at: runRoot)
        _ = generateCoverageAudit(for: updated, at: runRoot)
        _ = generateBinaryIntelligenceArtifacts(for: updated, at: runRoot)
        _ = generateDedupeReport(for: updated, at: runRoot)
        _ = generateRunIndexHTML(for: updated, at: runRoot)
        _ = try generateHeatmaps(for: &updated, at: runRoot)

        // 2) Core artifacts
        try writeJSON(updated.settings, to: runRoot.appendingPathComponent("run_settings.json"))
        try writeJSON(updated.forensic, to: runRoot.appendingPathComponent("run_forensic.json"))
        try writeJSON(exportedItems, to: runRoot.appendingPathComponent("run_items.json"))

        // 3) AI report artifact (if AI enabled)
        let aiReport = buildAIReport(run: updated)
        try writeJSON(aiReport, to: runRoot.appendingPathComponent("run_ai.json"))

        // 4) Manifest
        let aiModelHash = AIEngine.shared.detectorModelHash(
            modelName: updated.settings.aiModelName,
            compute: updated.settings.aiComputePreference
        )
        let embeddingModelIdentifier = EmbeddingEngine.shared.modelIdentifier(modelID: updated.settings.embeddingModelID)
        let reportIntegrityHash = try hashJSON(IntegrityPayload(
            settings: updated.settings,
            forensic: updated.forensic,
            items: exportedItems
        ))

        let manifest = RunManifest(
            runID: updated.id.uuidString,
            name: updated.name,
            startedAt: updated.startedAt,
            completedAt: updated.completedAt ?? Date(),
            sourceRoots: updated.sourceRoots,
            outputRoot: runRoot.path,
            totalItems: exportedItems.count,
            warningsCount: updated.warnings.count,
            settingsFingerprint: updated.settingsFingerprint,
            schemaVersion: updated.settings.schemaVersion,
            engineVersion: updated.settings.engineVersion,
            aiEnabled: updated.settings.enableAI,
            aiModelName: updated.settings.aiModelName,
            aiComputePreference: updated.settings.aiComputePreference,
            aiModelHash: aiModelHash,
            embeddingEnabled: updated.settings.enableEmbeddings,
            embeddingModelID: updated.settings.embeddingModelID,
            embeddingModelIdentifier: embeddingModelIdentifier,
            caseMetadata: updated.settings.caseMetadata,
            reportIntegrityHash: reportIntegrityHash
        )
        try writeJSON(manifest, to: runRoot.appendingPathComponent("run_manifest.json"))

        // 5) Optional: embedding snapshot export
        if updated.settings.enableEmbeddings, updated.settings.exportEmbeddingsSnapshot {
            let dst = runRoot.appendingPathComponent("embeddings_snapshot.jsonl")
            try await EmbeddingStore.shared.exportSnapshot(runID: updated.id, to: dst)
        }

        updated.outputRoot = runRoot.path
        return updated
    }

    public func runAgents(for run: ScanRun) async throws -> ScanRun {
        var updated = run
        let runRoot = URL(fileURLWithPath: run.outputRoot, isDirectory: true)
        guard FileManager.default.fileExists(atPath: runRoot.path) else {
            throw NSError(domain: "ScannerEngine", code: 404, userInfo: [
                NSLocalizedDescriptionKey: "Run output folder not found. Run a scan/export first."
            ])
        }

        _ = generateEvidenceIntelligenceReport(for: updated, at: runRoot)
        _ = generateAgentOutputs(for: updated, at: runRoot)
        _ = generateCoverageAudit(for: updated, at: runRoot)
        _ = generateBinaryIntelligenceArtifacts(for: updated, at: runRoot)
        _ = generateDedupeReport(for: updated, at: runRoot)
        _ = generateRunIndexHTML(for: updated, at: runRoot)
        try writeJSON(updated.forensic, to: runRoot.appendingPathComponent("run_forensic.json"))
        try writeJSON(updated.items, to: runRoot.appendingPathComponent("run_items.json"))
        return updated
    }

    public func performRecommendedActions(for run: ScanRun) async throws -> ScanRun {
        var updated = run
        let runRoot = URL(fileURLWithPath: run.outputRoot, isDirectory: true)
        guard FileManager.default.fileExists(atPath: runRoot.path) else {
            throw NSError(domain: "ScannerEngine", code: 404, userInfo: [
                NSLocalizedDescriptionKey: "Run output folder not found. Run a scan/export first."
            ])
        }

        _ = generateRecommendedActionArtifacts(for: updated, at: runRoot)
        _ = generateEvidenceIntelligenceReport(for: updated, at: runRoot)
        _ = generateAgentOutputs(for: updated, at: runRoot)
        _ = generateCoverageAudit(for: updated, at: runRoot)
        _ = generateBinaryIntelligenceArtifacts(for: updated, at: runRoot)
        _ = generateDedupeReport(for: updated, at: runRoot)
        _ = generateRunIndexHTML(for: updated, at: runRoot)
        try writeJSON(updated.forensic, to: runRoot.appendingPathComponent("run_forensic.json"))
        try writeJSON(updated.items, to: runRoot.appendingPathComponent("run_items.json"))
        return updated
    }

    // MARK: - Stage builder

    private func buildStages(tempRoot: URL) -> [ScanStage] {
        [
            ForensicSniffStage(),
            FileCarveStage(),
            MediaTypeStage(),
            AIClassificationStage(),
            EmbeddingStage(),
            ArchiveStage(tempRoot: tempRoot, maxDepth: maxArchiveDepth)
        ]
    }

    // MARK: - Stages

    struct ForensicSniffStage: ScanStage {
        let name: String = "forensic_sniff"

        func process(file: URL, data: Data, context: ScanContext) async -> StageOutput {
            var out = StageOutput()
            let ext = file.pathExtension.lowercased()
            let lowerPath = file.path.lowercased()

            if ext == "rem" { out.forensicDelta.remCount += 1 }

            let lower = file.lastPathComponent.lowercased()
            if lower.contains("key") || lower.contains("keys") || ext == "key" {
                out.forensicDelta.keyFiles.append(file.path)
                out.forensicDelta.metrics["keys"] = 1
            }

            if data.count >= 16,
               let header = String(data: data.prefix(16), encoding: .utf8),
               header.hasPrefix("SQLite format 3") {
                out.forensicDelta.possibleDecryptableDBs += 1
            }

            if lower.contains("thumb") || lower.contains("ithmb") || looksLikeThumbsContainer(data) {
                out.forensicDelta.metrics["thumbnails"] = 1
            }

            if ["rem", "dat", "cod", "ipd", "bbb"].contains(ext), hasSiblingKeyFile(for: file) {
                out.forensicDelta.metrics["decryptable"] = 1
            }

            let indicators = extractForensicTextIndicators(from: data)
            if indicators.messageSignals > 0 { out.forensicDelta.metrics["messages"] = indicators.messageSignals }
            if indicators.emails > 0 { out.forensicDelta.metrics["emails"] = indicators.emails }
            if indicators.urls > 0 { out.forensicDelta.metrics["urls"] = indicators.urls }
            if indicators.phones > 0 { out.forensicDelta.metrics["phones"] = indicators.phones }
            if indicators.languageSignals > 0 { out.forensicDelta.metrics["language_signals"] = indicators.languageSignals }

            let artifactSignals = extractArtifactPathSignals(from: lowerPath)
            for (k, v) in artifactSignals where v > 0 {
                out.forensicDelta.metrics[k] = v
            }
            return out
        }

        private func hasSiblingKeyFile(for file: URL) -> Bool {
            let dir = file.deletingLastPathComponent()
            guard let entries = try? FileManager.default.contentsOfDirectory(
                at: dir,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ) else { return false }
            return entries.contains { $0.pathExtension.lowercased() == "key" }
        }

        private func looksLikeThumbsContainer(_ data: Data) -> Bool {
            if data.count >= 4 {
                if data[0] == 0x22, data[1] == 0x06, data[2] == 0x20, data[3] == 0x09 { return true }
                if data[0] == 0x24, data[1] == 0x05, data[2] == 0x20, data[3] == 0x03 { return true }
            }
            return false
        }

        private func extractForensicTextIndicators(from data: Data) -> (messageSignals: Int, emails: Int, urls: Int, phones: Int, languageSignals: Int) {
            let sample = Data(data.prefix(2 * 1_048_576))
            if sample.isEmpty { return (0, 0, 0, 0, 0) }

            let raw = String(decoding: sample, as: UTF8.self).replacingOccurrences(of: "\u{0}", with: " ")
            if raw.isEmpty { return (0, 0, 0, 0, 0) }
            let lower = raw.lowercased()

            let messageKeywords = [
                "message", "sms", "mms", "chat", "conversation", "inbox", "outbox", "sender", "recipient", "email"
            ]
            var msgHits = 0
            for token in messageKeywords where lower.contains(token) { msgHits += 1 }

            let emails = regexCount(pattern: #"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}"#, in: raw)
            let urls = regexCount(pattern: #"(?:https?://|ftp://|www\.)[^\s"'<>()]{4,}"#, in: raw)
            let phones = regexCount(pattern: #"\+?\d[\d\-\(\) ]{7,}\d"#, in: raw)

            let alphabetic = raw.unicodeScalars.filter { CharacterSet.letters.contains($0) }.count
            let languageSignals = alphabetic > 200 ? 1 : 0

            return (msgHits, emails, urls, phones, languageSignals)
        }

        private func extractArtifactPathSignals(from lowerPath: String) -> [String: Int] {
            let pathGroups: [(String, [String])] = [
                ("artifact_browser", ["history", "cookies", "cache", "webcache", "bookmark", "places.sqlite", "favicons"]),
                ("artifact_messages", ["chat", "message", "sms", "mms", "imessage", "whatsapp", "telegram", "signal", "line", "wechat"]),
                ("artifact_media", ["thumb", "thumbnail", "dcim", "camera", "photos", "media"]),
                ("artifact_system", ["registry", "prefetch", "usn", "eventlog", "evtx", "fsevents"]),
                ("artifact_keys", ["keychain", "keystore", "wallet", "token", "credential"])
            ]

            var metrics: [String: Int] = [:]
            for (metric, needles) in pathGroups {
                if needles.contains(where: { lowerPath.contains($0) }) {
                    metrics[metric] = 1
                }
            }
            return metrics
        }

        private func regexCount(pattern: String, in text: String) -> Int {
            guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return 0 }
            let range = NSRange(text.startIndex..<text.endIndex, in: text)
            return regex.numberOfMatches(in: text, options: [], range: range)
        }
    }

    struct MediaTypeStage: ScanStage {
        let name: String = "media_type"

        func process(file: URL, data: Data, context: ScanContext) async -> StageOutput {
            var out = StageOutput()
            let ext = file.pathExtension.lowercased()
            let contentHash = Hashing.hexSHA256(data)

            let imageExts: Set<String> = ["jpg","jpeg","png","gif","webp","tif","tiff","bmp","heic","heif","ico"]
            let videoExts: Set<String> = ["mp4","mov","mkv","avi","mpeg","m2ts","webm"]
            let audioExts: Set<String> = ["mp3","wav","flac","ogg","m4a","aac","alac"]
            let textExts: Set<String>  = ["txt","md","rtf","csv","json","xml","html","htm","log","pdf"]
            let archiveExts: Set<String> = ["zip","rar","7z","tar","tgz","gz","bz2","xz","zst","deb","rpm","ar"]

            let category: FileCategory
            if imageExts.contains(ext) { category = .images }
            else if videoExts.contains(ext) { category = .video }
            else if audioExts.contains(ext) { category = .audio }
            else if textExts.contains(ext) { category = .text }
            else if archiveExts.contains(ext) { category = .archives }
            else { category = .uncertain }

            let item = FoundItem(
                sourcePath: file.path,
                offset: 0,
                length: data.count,
                detectedType: ext.isEmpty ? "unknown" : ext,
                category: category,
                fileExtension: ext,
                confidence: 0.5,
                validationStatus: .uncertain,
                contentHash: contentHash,
                outputPath: nil
            )

            out.items = [item]
            if category == .images || category == .video { out.forensicDelta.mediaCount += 1 }
            return out
        }
    }

    /// Byte-level signature carving for container/binary files (.dat, .bin, etc).
    struct FileCarveStage: ScanStage {
        let name: String = "file_carve"
        let maxItemsPerFile = 1500

        func process(file: URL, data: Data, context: ScanContext) async -> StageOutput {
            let ext = file.pathExtension.lowercased()
            let archiveExts: Set<String> = [
                "zip", "rar", "7z", "tar", "tgz", "gz", "bz2", "xz", "zst", "deb", "rpm", "ar", "tbz2", "txz"
            ]
            if archiveExts.contains(ext) {
                return StageOutput()
            }

            let carveTargetExts: Set<String> = [
                "dat", "bin", "raw", "tmp", "blob", "cache", "thumb", "thumbs", "rem", "cod", "bbb", "ipd"
            ]
            if !carveTargetExts.contains(ext), ext != "", ext != "db", ext != "sqlite", ext != "sqlite3" {
                return StageOutput()
            }

            guard data.count >= 64 else { return StageOutput() }

            // Byte-accurate scan to avoid missing signatures at non-aligned offsets.
            let stride = 1

            let maxBytesToInspect: Int
            switch context.settings.performanceMode {
            case .fast: maxBytesToInspect = 32 * 1_048_576
            case .balanced: maxBytesToInspect = 96 * 1_048_576
            case .thorough: maxBytesToInspect = 256 * 1_048_576
            }
            let datHeavyExts: Set<String> = ["dat", "thumb", "thumbs", "rem", "ipd"]
            let effectiveInspectLimit: Int
            if datHeavyExts.contains(ext) {
                switch context.settings.performanceMode {
                case .fast: effectiveInspectLimit = 128 * 1_048_576
                case .balanced: effectiveInspectLimit = 384 * 1_048_576
                case .thorough: effectiveInspectLimit = 768 * 1_048_576
                }
            } else {
                effectiveInspectLimit = maxBytesToInspect
            }
            let scanEnd = min(data.count, effectiveInspectLimit)

            var out = StageOutput()
            var seen = Set<String>()
            var foundCount = 0
            var offset = 0

            // BlackBerry thumbs*.dat style record parser (0x22062009 magic + 30-byte record header).
            if ext == "dat", let parsed = parseThumbsStructuredRecords(file: file, data: data, maxItems: maxItemsPerFile) {
                out.forensicDelta.metrics["thumbnails", default: 0] += parsed.count
                for item in parsed {
                    let key = "\(item.detectedType)|\(item.offset)|\(item.length)"
                    if seen.contains(key) { continue }
                    seen.insert(key)
                    out.items.append(item)
                    out.forensicDelta.mediaCount += 1
                    foundCount += 1
                    if foundCount >= maxItemsPerFile {
                        out.warnings.append("Carve limit reached (\(maxItemsPerFile)) for \(file.lastPathComponent)")
                        return out
                    }
                }
            }

            while offset < scanEnd {
                if Task.isCancelled { break }

                let hits = SignatureRegistry.detect(in: data, offset: offset)
                for hit in hits {
                    // Skip top-level signature at offset 0 to avoid duplicate "whole-file" rows.
                    if hit.offset == 0 { continue }
                    if !context.settings.enabledTypes.contains(hit.detectedType) { continue }
                    if hit.length <= 0 || hit.offset + hit.length > data.count { continue }

                    let key = "\(hit.detectedType)|\(hit.offset)|\(hit.length)"
                    if seen.contains(key) { continue }
                    seen.insert(key)

                    let carved = FoundItem(
                        sourcePath: file.path,
                        offset: hit.offset,
                        length: hit.length,
                        detectedType: hit.detectedType,
                        category: hit.category,
                        fileExtension: hit.fileExtension,
                        confidence: hit.confidence,
                        validationStatus: hit.validationStatus,
                        contentHash: nil,
                        outputPath: nil
                    )
                    out.items.append(carved)

                    if carved.category == .images || carved.category == .video {
                        out.forensicDelta.mediaCount += 1
                    }

                    foundCount += 1
                    if foundCount >= maxItemsPerFile {
                        out.warnings.append("Carve limit reached (\(maxItemsPerFile)) for \(file.lastPathComponent)")
                        return out
                    }
                }

                offset += stride
            }

            if scanEnd < data.count {
                out.warnings.append(
                    "Carving truncated at \(ByteCountFormatter.string(fromByteCount: Int64(scanEnd), countStyle: .file)) for \(file.lastPathComponent) (mode \(context.settings.performanceMode.rawValue))."
                )
            }

            return out
        }

        private func parseThumbsStructuredRecords(file: URL, data: Data, maxItems: Int) -> [FoundItem]? {
            guard data.count > 64 else { return nil }
            // 0x22062009 (big endian) magic
            if !(data[0] == 0x22 && data[1] == 0x06 && data[2] == 0x20 && data[3] == 0x09) {
                return nil
            }

            var items: [FoundItem] = []
            items.reserveCapacity(min(200, maxItems))

            let starts = [4, 0]
            for start in starts {
                var offset = start
                var accepted = 0

                while offset + 30 <= data.count, accepted < maxItems {
                    let pathNameLen = readUInt32BE(data: data, at: offset + 5)
                    let fileNameLen = readUInt32BE(data: data, at: offset + 9)
                    let dataLen = readUInt32BE(data: data, at: offset + 13)
                    offset += 30

                    if pathNameLen > 4096 || fileNameLen > 1024 || dataLen > 50 * 1_048_576 {
                        break
                    }
                    let recordBytes = pathNameLen + fileNameLen + dataLen
                    if recordBytes <= 0 || offset + recordBytes > data.count {
                        break
                    }

                    offset += (pathNameLen + fileNameLen)
                    let imageOffset = offset
                    let imageEnd = imageOffset + dataLen
                    if imageEnd > data.count {
                        break
                    }

                    let ext = detectImageExtension(data: data, offset: imageOffset, length: dataLen)
                    if let ext {
                        let item = FoundItem(
                            sourcePath: file.path,
                            offset: imageOffset,
                            length: dataLen,
                            detectedType: ext == "jpg" ? "jpeg" : ext,
                            category: .images,
                            fileExtension: ext,
                            confidence: 0.95,
                            validationStatus: .valid,
                            contentHash: nil,
                            outputPath: nil
                        )
                        items.append(item)
                        accepted += 1
                    }

                    offset = imageEnd
                }

                if !items.isEmpty {
                    return items
                }
            }

            return items.isEmpty ? nil : items
        }

        private func readUInt32BE(data: Data, at offset: Int) -> Int {
            if offset + 4 > data.count { return 0 }
            let b0 = Int(data[offset]) << 24
            let b1 = Int(data[offset + 1]) << 16
            let b2 = Int(data[offset + 2]) << 8
            let b3 = Int(data[offset + 3])
            return b0 | b1 | b2 | b3
        }

        private func detectImageExtension(data: Data, offset: Int, length: Int) -> String? {
            guard length >= 4, offset + length <= data.count else { return nil }

            let b0 = data[offset]
            let b1 = data[offset + 1]
            let b2 = data[offset + 2]
            let b3 = data[offset + 3]

            if b0 == 0xFF, b1 == 0xD8 { return "jpg" }
            if b0 == 0x89, b1 == 0x50, b2 == 0x4E, b3 == 0x47 { return "png" }
            if b0 == 0x47, b1 == 0x49, b2 == 0x46 { return "gif" }
            if b0 == 0x42, b1 == 0x4D { return "bmp" }
            return nil
        }
    }

    struct AIClassificationStage: ScanStage {
        let name: String = "ai_classification"

        func process(file: URL, data: Data, context: ScanContext) async -> StageOutput {
            guard context.enableAIClassification else { return StageOutput() }

            let ext = file.pathExtension.lowercased()
            let imageExts: Set<String> = ["jpg","jpeg","png","gif","webp","tif","tiff","bmp","heic","heif","ico"]
            let videoExts: Set<String> = ["mp4","mov","mkv","avi","mpeg","m2ts","webm"]

            if imageExts.contains(ext) {
                return await analyzeImage(file: file, context: context)
            }
            if videoExts.contains(ext) {
                return await analyzeVideo(file: file, context: context)
            }
            return StageOutput()
        }

        private func analyzeImage(file: URL, context: ScanContext) async -> StageOutput {
            guard let cg = AIEngine.shared.loadCGImage(from: file) else { return StageOutput() }

            var out = StageOutput()
            var ar = AnalyzerResult(sourcePath: file.path)

            let sensitive = await AIEngine.shared.scaIsSensitive(cgImage: cg)
            ar.scaIsSensitive = sensitive

            let reasons = await AIEngine.shared.detectReasons(
                cgImage: cg,
                modelName: context.settings.aiModelName,
                compute: context.settings.aiComputePreference
            )
            ar.reasonDetections = reasons

            // Deterministic scoring
            let (score, severity) = Self.scoreDetections(
                detections: reasons ?? [],
                scaSensitive: sensitive,
                preset: context.settings.resolvedAIThresholdPreset
            )
            ar.nsfwScore = score
            ar.nsfwSeverity = severity
            applyModelStamps(to: &ar, context: context)

            out.analyzerResults = [ar]
            return out
        }

        private func analyzeVideo(file: URL, context: ScanContext) async -> StageOutput {
            #if canImport(AVFoundation)
            let asset = AVURLAsset(url: file)
            let durationSeconds = CMTimeGetSeconds(asset.duration)
            let cappedDuration = min(max(durationSeconds, 1), 30)
            let frameCount = max(1, min(Int(cappedDuration), 30))

            let generator = AVAssetImageGenerator(asset: asset)
            generator.appliesPreferredTrackTransform = true
            generator.requestedTimeToleranceBefore = .zero
            generator.requestedTimeToleranceAfter = .zero

            var sampledFrames = 0
            var sensitiveFrames = 0
            var explicitFrames = 0
            var bestScore = 0.0
            var bestSeverity: NSFWSeverity = .unknown
            var allDetections: [ReasonDetection] = []

            for i in 0..<frameCount {
                let t = CMTime(seconds: Double(i), preferredTimescale: 600)
                var actual = CMTime.zero
                guard let cg = try? generator.copyCGImage(at: t, actualTime: &actual) else { continue }
                sampledFrames += 1

                let sensitive = await AIEngine.shared.scaIsSensitive(cgImage: cg)
                if sensitive == true { sensitiveFrames += 1 }

                let detections = await AIEngine.shared.detectReasons(
                    cgImage: cg,
                    modelName: context.settings.aiModelName,
                    compute: context.settings.aiComputePreference
                ) ?? []

                let (score, severity) = Self.scoreDetections(
                    detections: detections,
                    scaSensitive: sensitive,
                    preset: context.settings.resolvedAIThresholdPreset
                )
                bestScore = max(bestScore, score)
                if severity == .explicit { explicitFrames += 1 }
                if severityPriority(severity) > severityPriority(bestSeverity) { bestSeverity = severity }

                if !detections.isEmpty {
                    let ts = String(format: "%.2fs", CMTimeGetSeconds(actual))
                    allDetections.append(contentsOf: detections.map {
                        ReasonDetection(
                            reason: $0.reason,
                            confidence: $0.confidence,
                            bbox: $0.bbox,
                            modelLabel: $0.modelLabel,
                            notes: "frame=\(ts)"
                        )
                    })
                }
            }

            guard sampledFrames > 0 else { return StageOutput() }

            var out = StageOutput()
            var ar = AnalyzerResult(sourcePath: file.path)
            ar.scaIsSensitive = sensitiveFrames > 0 ? true : nil
            ar.reasonDetections = allDetections.isEmpty ? nil : Array(allDetections.prefix(200))

            if explicitFrames >= 2 {
                ar.nsfwSeverity = .explicit
                ar.nsfwScore = min(bestScore + 0.2, 2.5)
            } else {
                ar.nsfwSeverity = bestSeverity
                ar.nsfwScore = bestScore
            }

            applyModelStamps(to: &ar, context: context)
            out.analyzerResults = [ar]
            return out
            #else
            _ = (file, context)
            return StageOutput()
            #endif
        }

        private func applyModelStamps(to ar: inout AnalyzerResult, context: ScanContext) {

            // Repro stamps
            ar.aiModelName = context.settings.aiModelName
            ar.aiModelHash = AIEngine.shared.detectorModelHash(
                modelName: context.settings.aiModelName,
                compute: context.settings.aiComputePreference
            )
            ar.aiEngineVersion = context.settings.engineVersion
            ar.aiSettingsFingerprint = context.settingsFingerprint
            ar.scoringVersion = 1
        }

        private static func scoreDetections(
            detections: [ReasonDetection],
            scaSensitive: Bool?,
            preset: NSFWThresholdPreset
        ) -> (Double, NSFWSeverity) {
            // weights are deterministic + easy to tune
            func weight(_ r: NSFWReason) -> Double {
                switch r {
                case .exposedGenitals: return 1.00
                case .sexAct:         return 1.00
                case .exposedBreast:  return 0.85
                case .nudity:         return 0.70
                case .lingerie:       return 0.45
                case .buttocks:       return 0.40
                case .other:          return 0.25
                }
            }

            var score = 0.0
            for d in detections {
                score += weight(d.reason) * min(max(d.confidence, 0), 1)
            }

            // small deterministic bump if SCA says sensitive
            if scaSensitive == true { score += 0.20 }

            // clamp
            score = min(max(score, 0), 2.5)

            let severity: NSFWSeverity
            if score >= preset.explicitThreshold { severity = .explicit }
            else if score >= preset.suggestiveThreshold { severity = .suggestive }
            else { severity = .none }

            // If neither model nor SCA could run, keep unknown
            if detections.isEmpty, scaSensitive == nil {
                return (0, .unknown)
            }
            return (score, severity)
        }

        private func severityPriority(_ severity: NSFWSeverity) -> Int {
            switch severity {
            case .unknown: return 0
            case .none: return 1
            case .suggestive: return 2
            case .explicit: return 3
            }
        }
    }

    /// Embedding-based semantic index.
    ///
    /// MAS-safe: uses an on-disk SQLite DB in Application Support.
    /// Deterministic: content hash is SHA256 over a canonical text representation.
    struct EmbeddingStage: ScanStage {
        let name: String = "embeddings"

        func process(file: URL, data: Data, context: ScanContext) async -> StageOutput {
            guard context.enableEmbeddings else { return StageOutput() }
            let fileContentHash = Hashing.hexSHA256(data)

            // Today: embed a stable, searchable string derived from file identity.
            // Next: extend to extracted strings / EXIF / decoded messages.
            let canonicalText = EmbeddingCanonicalizer.canonicalText(
                filePath: file.path,
                fileContentHash: fileContentHash,
                settingsFingerprint: context.settingsFingerprint,
                embeddingModelID: context.settings.embeddingModelID
            )

            guard let textData = canonicalText.data(using: .utf8) else { return StageOutput() }
            let contentHash = Hashing.hexSHA256(textData)

            guard let vector = await EmbeddingEngine.shared.embed(
                text: canonicalText,
                modelID: context.settings.embeddingModelID
            ) else {
                return StageOutput()
            }

            await EmbeddingStore.shared.upsert(
                runID: context.runID,
                sourcePath: file.path,
                contentHash: contentHash,
                modelID: context.settings.embeddingModelID,
                settingsFingerprint: context.settingsFingerprint,
                vector: vector,
                canonicalText: canonicalText
            )

            return StageOutput()
        }
    }

    struct ArchiveStage: ScanStage {
        let name: String = "archive_extract"
        let tempRoot: URL
        let maxDepth: Int

        func process(file: URL, data: Data, context: ScanContext) async -> StageOutput {
            guard context.enableArchiveExtraction else { return StageOutput() }
            guard file.pathExtension.lowercased() == "zip" else { return StageOutput() }

            var out = StageOutput()
            out.forensicDelta.nestedArchives += 1

            out.extraFilesToScan = extractZipSwiftNative(file: file, tempRoot: tempRoot)
            return out
        }

        private func extractZipSwiftNative(file: URL, tempRoot: URL) -> [URL] {
            #if canImport(ZIPFoundation)
            let fm = FileManager.default
            let outDir = tempRoot.appendingPathComponent(UUID().uuidString, isDirectory: true)
            do {
                try fm.createDirectory(at: outDir, withIntermediateDirectories: true)
                try fm.unzipItem(at: file, to: outDir)
            } catch {
                return []
            }

            var extracted: [URL] = []
            if let enumerator = fm.enumerator(
                at: outDir,
                includingPropertiesForKeys: [.isRegularFileKey],
                options: [.skipsHiddenFiles]
            ) {
                while let next = enumerator.nextObject() as? URL {
                    if (try? next.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true {
                        extracted.append(next)
                    }
                }
            }
            return extracted
            #else
            return []
            #endif
        }
    }

    // MARK: - File collection

    private func collectFiles(from roots: [URL], enabledTypes: Set<String>) -> [URL] {
        var results: [URL] = []
        let fm = FileManager.default

        for root in roots {
            if (try? root.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true {
                let ext = root.pathExtension.lowercased()
                if shouldIncludeFile(withExtension: ext, enabledTypes: enabledTypes) {
                    results.append(root)
                }
                continue
            }

            guard let enumerator = fm.enumerator(
                at: root,
                includingPropertiesForKeys: [.isRegularFileKey],
                options: []
            ) else { continue }

            while let next = enumerator.nextObject() as? URL {
                guard (try? next.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else { continue }
                let ext = next.pathExtension.lowercased()
                if !shouldIncludeFile(withExtension: ext, enabledTypes: enabledTypes) { continue }
                results.append(next)
            }
        }
        return results
    }

    private func shouldIncludeFile(withExtension ext: String, enabledTypes: Set<String>) -> Bool {
        if ext.isEmpty || enabledTypes.contains(ext) { return true }

        // Always include common container/binary artifacts so carving can discover embedded media.
        let carveCandidates: Set<String> = [
            "dat", "bin", "db", "sqlite", "sqlite3", "cache", "thumb", "thumbs", "blob", "tmp", "raw",
            "plist", "bplist", "rem", "cod", "bbb", "ipd"
        ]
        return carveCandidates.contains(ext)
    }

    // MARK: - Dedupe

    private struct DedupeOutcome {
        var items: [FoundItem]
        var removed: [DedupeRemoval]
    }

    private func dedupe(items: [FoundItem], mode: DedupeMode) -> DedupeOutcome {
        guard mode != .off else { return DedupeOutcome(items: items, removed: []) }

        var seenByKey: [String: FoundItem] = [:]
        var out: [FoundItem] = []
        var removed: [DedupeRemoval] = []
        var fileHashCache: [String: String] = [:]
        var segmentHashCache: [String: String] = [:]

        for item in items {
            guard let key = dedupeKey(
                for: item,
                mode: mode,
                fileHashCache: &fileHashCache,
                segmentHashCache: &segmentHashCache
            ) else {
                // If we cannot prove exact byte equality, keep the item.
                out.append(item)
                continue
            }

            if let kept = seenByKey[key] {
                removed.append(
                    DedupeRemoval(
                        reason: "exact_bytes",
                        dedupeKey: key,
                        keptSourcePath: kept.sourcePath,
                        removedSourcePath: item.sourcePath,
                        keptOffset: kept.offset,
                        removedOffset: item.offset,
                        length: item.length
                    )
                )
                continue
            }

            seenByKey[key] = item
            out.append(item)
        }

        return DedupeOutcome(items: out, removed: removed)
    }

    private func dedupeKey(
        for item: FoundItem,
        mode: DedupeMode,
        fileHashCache: inout [String: String],
        segmentHashCache: inout [String: String]
    ) -> String? {
        let exactModes: Set<DedupeMode> = [.exactBytes, .hash, .hashAndSize]
        guard exactModes.contains(mode) else { return nil }

        if let contentHash = item.contentHash, !contentHash.isEmpty {
            return "len:\(item.length)|sha:\(contentHash)"
        }

        let source = URL(fileURLWithPath: item.sourcePath)
        let fileSize = (try? source.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0

        if item.offset == 0, item.length > 0, item.length == fileSize {
            if let cached = fileHashCache[source.path] {
                return "len:\(item.length)|sha:\(cached)"
            }
            guard let data = try? Data(contentsOf: source, options: .mappedIfSafe) else { return nil }
            let hash = Hashing.hexSHA256(data)
            fileHashCache[source.path] = hash
            return "len:\(item.length)|sha:\(hash)"
        }

        // Carved segments: hash exact byte range to avoid false dedupe.
        if item.offset >= 0, item.length > 0 {
            let segKey = "\(source.path)|\(item.offset)|\(item.length)"
            if let cached = segmentHashCache[segKey] {
                return "len:\(item.length)|sha:\(cached)"
            }
            guard let data = try? Data(contentsOf: source, options: .mappedIfSafe) else { return nil }
            let end = item.offset + item.length
            guard end <= data.count else { return nil }
            let seg = data.subdata(in: item.offset..<end)
            let hash = Hashing.hexSHA256(seg)
            segmentHashCache[segKey] = hash
            return "len:\(item.length)|sha:\(hash)"
        }

        return nil
    }

    // MARK: - Rate helpers

    private func updateRates(_ progress: inout ScanProgress, started: Date) {
        let elapsed = max(Date().timeIntervalSince(started), 0.001)
        let mb = Double(progress.bytesScanned) / 1_048_576.0
        progress.mbPerSecond = mb / elapsed

        let remainingBytes = max(progress.totalBytes - progress.bytesScanned, 0)
        let remainingMB = Double(remainingBytes) / 1_048_576.0
        progress.etaSeconds = progress.mbPerSecond > 0 ? (remainingMB / progress.mbPerSecond) : 0
    }

    // MARK: - Export helpers

    private func exportItems(run: ScanRun, to root: URL) -> [FoundItem] {
        switch run.settings.organizationScheme {
        case .flat:
            return exportFlat(run.items, to: root)
        case .byType:
            return exportByType(run.items, to: root)
        case .bySource:
            return exportBySource(run.items, to: root)
        }
    }

    private func exportFlat(_ items: [FoundItem], to root: URL) -> [FoundItem] {
        var exported: [FoundItem] = []
        for item in items {
            exported.append(exportOne(item: item, to: root))
        }
        return exported
    }

    private func exportByType(_ items: [FoundItem], to root: URL) -> [FoundItem] {
        var exported: [FoundItem] = []
        let groups = Dictionary(grouping: items, by: { $0.category })
        for (cat, arr) in groups {
            let dir = root.appendingPathComponent(cat.rawValue, isDirectory: true)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            for item in arr {
                exported.append(exportOne(item: item, to: dir))
            }
        }
        return exported
    }

    private func exportBySource(_ items: [FoundItem], to root: URL) -> [FoundItem] {
        var exported: [FoundItem] = []
        for item in items {
            let srcURL = URL(fileURLWithPath: item.sourcePath)
            let base = srcURL.deletingLastPathComponent().lastPathComponent
            let dir = root.appendingPathComponent(base, isDirectory: true)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            exported.append(exportOne(item: item, to: dir))
        }
        return exported
    }

    private func exportOne(item: FoundItem, to dir: URL) -> FoundItem {
        let src = URL(fileURLWithPath: item.sourcePath)
        let srcSize = (try? src.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? item.length
        let looksCarved = item.offset > 0 || (item.length > 0 && item.length < srcSize)

        if looksCarved {
            if let data = try? Data(contentsOf: src, options: .mappedIfSafe) {
                let end = item.offset + item.length

                if item.offset >= 0, item.length > 0, end <= data.count {
                    let carvedBytes = data.subdata(in: item.offset..<end)
                    let ext = item.fileExtension.isEmpty ? (src.pathExtension.isEmpty ? "bin" : src.pathExtension) : item.fileExtension
                    let base = src.deletingPathExtension().lastPathComponent
                    let carvedName = "\(base)_0x\(String(item.offset, radix: 16)).\(ext)"
                    var carvedDst = dir.appendingPathComponent(carvedName)

                    if FileManager.default.fileExists(atPath: carvedDst.path) {
                        carvedDst = dir.appendingPathComponent("\(UUID().uuidString)-\(carvedName)")
                    }

                    if (try? carvedBytes.write(to: carvedDst, options: .atomic)) != nil {
                        var updated = item
                        updated.outputPath = carvedDst.path
                        return updated
                    }
                }
            }
        }

        let destinationDir = FileManager.default.fileExists(atPath: dir.path) ? dir : src.deletingLastPathComponent()
        let dst = destinationDir.appendingPathComponent(src.lastPathComponent)
        let finalDst: URL
        if FileManager.default.fileExists(atPath: dst.path) {
            finalDst = destinationDir.appendingPathComponent("\(UUID().uuidString)-\(src.lastPathComponent)")
        } else {
            finalDst = dst
        }

        do { try FileManager.default.copyItem(at: src, to: finalDst) } catch { }

        var updated = item
        updated.outputPath = finalDst.path
        return updated
    }

    private func resolveWritableOutputBase(preferred: URL) -> URL {
        let fm = FileManager.default
        let appSupport = (fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory()))
            .appendingPathComponent("JuiceLabPro", isDirectory: true)
            .appendingPathComponent("Extracted", isDirectory: true)
        let tempFallback = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("JuiceLabProExtracted", isDirectory: true)

        let candidates = [preferred, appSupport, tempFallback]
        for base in candidates {
            do {
                try fm.createDirectory(at: base, withIntermediateDirectories: true)
                let probe = base.appendingPathComponent(".probe-\(UUID().uuidString)")
                try Data().write(to: probe, options: .atomic)
                try? fm.removeItem(at: probe)
                return base
            } catch {
                continue
            }
        }
        return preferred
    }

    private func generateHeatmaps(for run: inout ScanRun, at runRoot: URL) throws -> Int {
        let heatmapDir = runRoot.appendingPathComponent("heatmaps", isDirectory: true)
        try FileManager.default.createDirectory(at: heatmapDir, withIntermediateDirectories: true)

        var exportedPathBySource: [String: String] = [:]
        for item in run.items {
            if let out = item.outputPath {
                exportedPathBySource[item.sourcePath] = out
            }
        }

        var count = 0
        for idx in run.forensic.analyzerResults.indices {
            var ar = run.forensic.analyzerResults[idx]
            guard let dets = ar.reasonDetections?.filter({ $0.bbox != nil }), !dets.isEmpty else { continue }

            let candidatePath = exportedPathBySource[ar.sourcePath] ?? ar.sourcePath
            guard isImagePath(candidatePath) else { continue }

            let stem = sanitizedFileStem(candidatePath)
            let dst = heatmapDir.appendingPathComponent("\(stem)-\(String(idx)).png")
            if renderHeatmap(sourcePath: candidatePath, detections: dets, destination: dst) {
                ar.heatmapPath = dst.path
                run.forensic.analyzerResults[idx] = ar
                count += 1
            }
        }
        return count
    }

    private func generatePDFTextArtifacts(for run: inout ScanRun, at runRoot: URL) -> Int {
        let textDir = runRoot.appendingPathComponent("pdf_text", isDirectory: true)
        try? FileManager.default.createDirectory(at: textDir, withIntermediateDirectories: true)

        let pdfItems = run.items.filter { item in
            let ext = item.fileExtension.lowercased()
            if ext == "pdf" || item.detectedType.lowercased() == "pdf" {
                return true
            }
            return URL(fileURLWithPath: item.sourcePath).pathExtension.lowercased() == "pdf"
        }

        guard !pdfItems.isEmpty else { return 0 }

        var sourceToAnalyzerIndex: [String: Int] = [:]
        for (idx, ar) in run.forensic.analyzerResults.enumerated() {
            sourceToAnalyzerIndex[ar.sourcePath] = idx
        }

        var created = 0
        for item in pdfItems {
            let sourcePath = item.outputPath ?? item.sourcePath
            guard let text = extractPDFText(from: sourcePath), !text.isEmpty else { continue }

            let stem = sanitizedFileStem(sourcePath)
            var dst = textDir.appendingPathComponent("\(stem).txt")
            if FileManager.default.fileExists(atPath: dst.path) {
                dst = textDir.appendingPathComponent("\(stem)-\(item.id.uuidString.prefix(8)).txt")
            }

            do {
                try text.write(to: dst, atomically: true, encoding: .utf8)
                if let idx = sourceToAnalyzerIndex[item.sourcePath] {
                    run.forensic.analyzerResults[idx].stringsPath = dst.path
                } else {
                    var ar = AnalyzerResult(sourcePath: item.sourcePath)
                    ar.stringsPath = dst.path
                    run.forensic.analyzerResults.append(ar)
                    sourceToAnalyzerIndex[item.sourcePath] = run.forensic.analyzerResults.count - 1
                }
                created += 1
            } catch {
                continue
            }
        }
        return created
    }

    private func generateSQLiteArtifacts(for run: inout ScanRun, at runRoot: URL) -> Int {
        let reportDir = runRoot.appendingPathComponent("sqlite_reports", isDirectory: true)
        try? FileManager.default.createDirectory(at: reportDir, withIntermediateDirectories: true)

        let sqliteExts: Set<String> = ["sqlite", "sqlite3", "db", "sqlitedb"]
        var processed = Set<String>()
        var created = 0

        for item in run.items {
            if processed.contains(item.sourcePath) { continue }

            let ioPath = item.outputPath ?? item.sourcePath
            let src = URL(fileURLWithPath: ioPath)
            let ext = src.pathExtension.lowercased()
            let hasSQLiteHeader = hasSQLiteHeader(path: ioPath)
            if !sqliteExts.contains(ext), !item.detectedType.lowercased().contains("sqlite"), !hasSQLiteHeader {
                continue
            }

            guard let report = extractSQLiteReport(from: ioPath) else { continue }
            processed.insert(item.sourcePath)

            let stem = sanitizedFileStem(ioPath)
            var dst = reportDir.appendingPathComponent("\(stem).sqlite.txt")
            if FileManager.default.fileExists(atPath: dst.path) {
                dst = reportDir.appendingPathComponent("\(stem)-\(item.id.uuidString.prefix(8)).sqlite.txt")
            }

            do {
                try report.write(to: dst, atomically: true, encoding: .utf8)
                upsertAnalyzerArtifact(
                    run: &run,
                    sourcePath: item.sourcePath,
                    artifactPath: dst.path,
                    sqliteDetected: true
                )
                created += 1
            } catch {
                continue
            }
        }

        return created
    }

    private func generatePlistArtifacts(for run: inout ScanRun, at runRoot: URL) -> Int {
        let reportDir = runRoot.appendingPathComponent("plist_reports", isDirectory: true)
        try? FileManager.default.createDirectory(at: reportDir, withIntermediateDirectories: true)

        var processed = Set<String>()
        var created = 0

        for item in run.items {
            if processed.contains(item.sourcePath) { continue }

            let ioPath = item.outputPath ?? item.sourcePath
            let sourceURL = URL(fileURLWithPath: ioPath)
            let ext = sourceURL.pathExtension.lowercased()
            let hasPlistHeader = hasBPlistHeader(path: ioPath)
            if ext != "plist" && ext != "bplist" && !hasPlistHeader {
                continue
            }

            guard let report = extractPlistReport(from: ioPath) else { continue }
            processed.insert(item.sourcePath)

            let stem = sanitizedFileStem(ioPath)
            var dst = reportDir.appendingPathComponent("\(stem).plist.txt")
            if FileManager.default.fileExists(atPath: dst.path) {
                dst = reportDir.appendingPathComponent("\(stem)-\(item.id.uuidString.prefix(8)).plist.txt")
            }

            do {
                try report.write(to: dst, atomically: true, encoding: .utf8)
                upsertAnalyzerArtifact(
                    run: &run,
                    sourcePath: item.sourcePath,
                    artifactPath: dst.path
                )
                created += 1
            } catch {
                continue
            }
        }

        return created
    }

    private func generateBinaryStringArtifacts(for run: inout ScanRun, at runRoot: URL) -> Int {
        let stringsDir = runRoot.appendingPathComponent("strings", isDirectory: true)
        try? FileManager.default.createDirectory(at: stringsDir, withIntermediateDirectories: true)

        let binaryExts: Set<String> = [
            "dat", "bin", "db", "sqlite", "sqlite3", "cache", "tmp", "blob", "raw", "log",
            "rem", "cod", "bbb", "ipd"
        ]

        var sourceToAnalyzerIndex: [String: Int] = [:]
        for (idx, ar) in run.forensic.analyzerResults.enumerated() {
            sourceToAnalyzerIndex[ar.sourcePath] = idx
        }

        var processedSources = Set<String>()
        var created = 0

        for item in run.items {
            if processedSources.contains(item.sourcePath) { continue }
            processedSources.insert(item.sourcePath)

            let sourceURL = URL(fileURLWithPath: item.sourcePath)
            let ext = sourceURL.pathExtension.lowercased()
            let isCandidate = binaryExts.contains(ext) || item.category == .uncertain
            if !isCandidate { continue }

            let ioPath = item.outputPath ?? item.sourcePath
            guard let stringsText = extractMeaningfulStrings(from: ioPath) else { continue }

            let stem = sanitizedFileStem(ioPath)
            var dst = stringsDir.appendingPathComponent("\(stem).strings.txt")
            if FileManager.default.fileExists(atPath: dst.path) {
                dst = stringsDir.appendingPathComponent("\(stem)-\(item.id.uuidString.prefix(8)).strings.txt")
            }

            do {
                try stringsText.write(to: dst, atomically: true, encoding: .utf8)
                if let idx = sourceToAnalyzerIndex[item.sourcePath] {
                    if run.forensic.analyzerResults[idx].stringsPath == nil {
                        run.forensic.analyzerResults[idx].stringsPath = dst.path
                    }
                } else {
                    var ar = AnalyzerResult(sourcePath: item.sourcePath)
                    ar.stringsPath = dst.path
                    if ext == "sqlite" || ext == "db" {
                        ar.sqliteHeaderDetected = true
                    }
                    run.forensic.analyzerResults.append(ar)
                    sourceToAnalyzerIndex[item.sourcePath] = run.forensic.analyzerResults.count - 1
                }
                created += 1
            } catch {
                continue
            }
        }

        return created
    }

    private func generateURLArtifacts(for run: inout ScanRun, at runRoot: URL) -> Int {
        let urlsDir = runRoot.appendingPathComponent("URLs", isDirectory: true)
        try? FileManager.default.createDirectory(at: urlsDir, withIntermediateDirectories: true)

        var textCandidates = collectTextArtifactCandidates(run: run)
        let textItems = run.items.filter { item in
            let ext = item.fileExtension.lowercased()
            return item.category == .text || ["txt", "md", "rtf", "csv", "json", "xml", "html", "htm", "log"].contains(ext)
        }
        for item in textItems {
            let sourceURL = URL(fileURLWithPath: item.outputPath ?? item.sourcePath)
            textCandidates.append(sourceURL)
        }
        // Also scan binary/uncertain files directly; this mirrors metric extraction behavior.
        let binaryExts: Set<String> = ["db", "sqlite", "sqlite3", "dat", "bin", "blob", "cache", "tmp", "raw", "plist", "bplist"]
        for item in run.items where item.category == .uncertain || binaryExts.contains(item.fileExtension.lowercased()) {
            let sourceURL = URL(fileURLWithPath: item.outputPath ?? item.sourcePath)
            textCandidates.append(sourceURL)
        }

        let regex = try? NSRegularExpression(pattern: #"https?://[^\s"'<>()]+"#, options: [.caseInsensitive])
        guard let regex else { return 0 }

        var unique: Set<String> = []
        var urls: [String] = []
        let maxReads = 700
        let maxBytesPerFile = 2 * 1_048_576
        var reads = 0

        for candidate in dedupeURLs(textCandidates) where reads < maxReads {
            guard let s = readTextSample(from: candidate, maxBytes: maxBytesPerFile), !s.isEmpty else { continue }
            reads += 1

            let range = NSRange(s.startIndex..<s.endIndex, in: s)
            regex.enumerateMatches(in: s, options: [], range: range) { match, _, _ in
                guard let match, let r = Range(match.range, in: s) else { return }
                let raw = String(s[r]).trimmingCharacters(in: .whitespacesAndNewlines)
                if raw.isEmpty || unique.contains(raw) { return }
                unique.insert(raw)
                urls.append(raw)
            }
        }

        guard !urls.isEmpty else { return 0 }
        urls.sort()

        do {
            try urls.joined(separator: "\n").write(
                to: urlsDir.appendingPathComponent("URLs.txt"),
                atomically: true,
                encoding: .utf8
            )
        } catch {
            return 0
        }

        let rows = urls.prefix(5000).map { u -> String in
            let e = escapeHTML(u)
            return "<li><a href=\"\(e)\">\(e)</a></li>"
        }.joined(separator: "\n")

        let html = """
        <!doctype html>
        <html>
        <head>
          <meta charset="utf-8" />
          <title>Recovered URLs</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 24px; }
            code { background:#f4f4f4; padding:2px 6px; border-radius:4px; }
          </style>
        </head>
        <body>
          <h1>Recovered URLs</h1>
          <p>Total: <code>\(urls.count)</code></p>
          <ol>
          \(rows)
          </ol>
        </body>
        </html>
        """

        try? html.write(to: urlsDir.appendingPathComponent("URLs.html"), atomically: true, encoding: .utf8)
        return urls.count
    }

    private func generateAllTextArtifact(for run: inout ScanRun, at runRoot: URL) -> Int {
        let txtDir = runRoot.appendingPathComponent("txt", isDirectory: true)
        try? FileManager.default.createDirectory(at: txtDir, withIntermediateDirectories: true)

        var sections: [String] = []
        let maxBytesPerFile = 2 * 1_048_576
        let maxFiles = 500
        var consumed = 0

        let textArtifacts = collectTextArtifactCandidates(run: run)
        for fileURL in dedupeURLs(textArtifacts) where consumed < maxFiles {
            guard let text = readTextSample(from: fileURL, maxBytes: maxBytesPerFile), !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { continue }
            sections.append("===== \(fileURL.lastPathComponent) =====\n\(text)")
            consumed += 1
        }

        guard !sections.isEmpty else { return 0 }
        let output = sections.joined(separator: "\n\n")
        do {
            try output.write(to: txtDir.appendingPathComponent("All The Text.txt"), atomically: true, encoding: .utf8)
            return sections.count
        } catch {
            return 0
        }
    }

    private func generateHashCandidateArtifacts(for run: inout ScanRun, at runRoot: URL) -> Int {
        let outDir = runRoot.appendingPathComponent("hash_candidates", isDirectory: true)
        try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)

        var candidates = collectTextArtifactCandidates(run: run)
        let extraExts: Set<String> = ["txt", "log", "json", "xml", "db", "sqlite", "sqlite3", "plist", "bplist", "dat", "bin"]
        for item in run.items where extraExts.contains(item.fileExtension.lowercased()) || item.category == .uncertain {
            candidates.append(URL(fileURLWithPath: item.outputPath ?? item.sourcePath))
        }

        let patterns: [(label: String, mode: String, regex: NSRegularExpression?)] = [
            ("bcrypt", "3200", try? NSRegularExpression(pattern: #"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"#, options: [])),
            ("sha256", "1400", try? NSRegularExpression(pattern: #"\b[a-fA-F0-9]{64}\b"#, options: [])),
            ("sha1", "100", try? NSRegularExpression(pattern: #"\b[a-fA-F0-9]{40}\b"#, options: [])),
            ("md5_or_ntlm", "0_or_1000", try? NSRegularExpression(pattern: #"\b[a-fA-F0-9]{32}\b"#, options: [])),
            ("ntlmv2_or_netntlm", "5600_family", try? NSRegularExpression(pattern: #"[A-Za-z0-9._-]{1,64}::[A-Za-z0-9._-]{1,64}:[a-fA-F0-9]{16,}:[a-fA-F0-9]{16,}"#, options: []))
        ]

        var unique = Set<String>()
        var rows: [(kind: String, mode: String, value: String)] = []
        let maxFiles = 800
        let maxBytesPerFile = 2 * 1_048_576
        var scanned = 0

        for fileURL in dedupeURLs(candidates) where scanned < maxFiles {
            guard let text = readTextSample(from: fileURL, maxBytes: maxBytesPerFile), !text.isEmpty else { continue }
            scanned += 1
            let range = NSRange(text.startIndex..<text.endIndex, in: text)
            for pattern in patterns {
                guard let regex = pattern.regex else { continue }
                regex.enumerateMatches(in: text, options: [], range: range) { match, _, _ in
                    guard let match, let r = Range(match.range, in: text) else { return }
                    let value = String(text[r]).trimmingCharacters(in: .whitespacesAndNewlines)
                    if value.count < 16 || unique.contains(value) { return }
                    unique.insert(value)
                    rows.append((kind: pattern.label, mode: pattern.mode, value: value))
                }
            }
        }

        guard !rows.isEmpty else { return 0 }

        rows.sort { lhs, rhs in
            if lhs.kind == rhs.kind { return lhs.value < rhs.value }
            return lhs.kind < rhs.kind
        }

        let txt = rows.map { "\($0.value)  # kind=\($0.kind) mode_hint=\($0.mode)" }.joined(separator: "\n")
        let jsonLines = rows.map { #"{"kind":"\#($0.kind)","mode_hint":"\#($0.mode)","hash":"\#($0.value)"}"# }.joined(separator: "\n")

        do {
            try txt.write(to: outDir.appendingPathComponent("hashcat_candidates.txt"), atomically: true, encoding: .utf8)
            try jsonLines.write(to: outDir.appendingPathComponent("hashcat_candidates.jsonl"), atomically: true, encoding: .utf8)
            var metrics = run.forensic.metrics ?? [:]
            metrics["hash_candidates"] = rows.count
            run.forensic.metrics = metrics
            return rows.count
        } catch {
            return 0
        }
    }

    private func generateRunIndexHTML(for run: ScanRun, at runRoot: URL) -> Int {
        let items = run.items
        let byCategory = Dictionary(grouping: items, by: { $0.category })
        let totalBytes = items.reduce(0) { $0 + $1.length }
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file

        func rows(for category: FileCategory) -> String {
            let entries = (byCategory[category] ?? []).prefix(80)
            return entries.map { item in
                let displayName = URL(fileURLWithPath: item.outputPath ?? item.sourcePath).lastPathComponent
                let relPath = relativeOutputPath(for: item.outputPath, root: runRoot)
                let size = formatter.string(fromByteCount: Int64(item.length))
                let validation = item.validationStatus.rawValue
                if let relPath {
                    return "<tr><td><a href=\"\(escapeHTML(relPath))\">\(escapeHTML(displayName))</a></td><td>\(escapeHTML(size))</td><td>\(escapeHTML(validation))</td></tr>"
                }
                return "<tr><td>\(escapeHTML(displayName))</td><td>\(escapeHTML(size))</td><td>\(escapeHTML(validation))</td></tr>"
            }.joined(separator: "\n")
        }

        let categories: [FileCategory] = [.images, .video, .audio, .text, .archives, .uncertain]
        let categoryCards = categories.map { cat in
            let count = byCategory[cat]?.count ?? 0
            return "<div class=\"card\"><h3>\(escapeHTML(cat.rawValue.capitalized))</h3><p>\(count) files</p></div>"
        }.joined(separator: "\n")

        let sectionTables = categories.map { cat in
            """
            <section>
              <h2>\(escapeHTML(cat.rawValue.capitalized))</h2>
              <table>
                <thead><tr><th>File</th><th>Size</th><th>Status</th></tr></thead>
                <tbody>
                \(rows(for: cat))
                </tbody>
              </table>
            </section>
            """
        }.joined(separator: "\n")

        let rootPath = runRoot.path
        let urlPath = "\(rootPath)/URLs/URLs.html"
        let textPath = "\(rootPath)/txt/All The Text.txt"

        let html = """
        <!doctype html>
        <html>
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <title>JuiceLab Run Report</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 20px; color: #111; background: #fafafa; }
            h1, h2 { margin: 0 0 8px 0; }
            .meta { display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; margin: 12px 0 20px 0; }
            .card { background: white; border: 1px solid #e5e5e5; border-radius: 8px; padding: 10px; }
            .links a { margin-right: 10px; }
            table { width: 100%; border-collapse: collapse; margin-bottom: 18px; background: white; }
            th, td { text-align: left; border-bottom: 1px solid #eee; padding: 6px 8px; font-size: 12px; }
            th { background: #f5f5f5; }
          </style>
        </head>
        <body>
          <h1>JuiceLab Run Report</h1>
          <p>Output: <code>\(escapeHTML(rootPath))</code></p>
          <p>Scanned items: <strong>\(items.count)</strong> | Total bytes: <strong>\(escapeHTML(formatter.string(fromByteCount: Int64(totalBytes))))</strong></p>
          <div class="links">
            <a href="URLs/URLs.html">Recovered URLs</a>
            <a href="txt/All The Text.txt">All The Text</a>
            <a href="evidence_intelligence/intelligence_report.md">Evidence Intelligence</a>
            <a href="evidence_intelligence/agents_summary.md">Agent Summary</a>
            <a href="evidence_intelligence/actions/actions_report.md">Agent Actions</a>
            <a href="coverage/coverage_report.md">Coverage Audit</a>
            <a href="binary_intelligence/index.md">Binary Intelligence</a>
            <a href="dedupe/dedupe_report.md">Dedupe Report</a>
            <a href="run_forensic.json">Forensic JSON</a>
            <a href="run_items.json">Items JSON</a>
          </div>
          <div class="meta">
            \(categoryCards)
          </div>
          \(sectionTables)
          <p>Additional artifacts: <code>\(escapeHTML(urlPath))</code> and <code>\(escapeHTML(textPath))</code></p>
        </body>
        </html>
        """

        do {
            try html.write(to: runRoot.appendingPathComponent("index.html"), atomically: true, encoding: .utf8)
            return 1
        } catch {
            return 0
        }
    }

    private func generateEvidenceIntelligenceReport(for run: ScanRun, at runRoot: URL) -> Int {
        let outDir = runRoot.appendingPathComponent("evidence_intelligence", isDirectory: true)
        try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)

        let items = run.items
        let metrics = run.forensic.metrics ?? [:]
        let total = max(items.count, 1)

        let byCategory = Dictionary(grouping: items, by: \.category)
        let topCategories = byCategory
            .map { ($0.key.rawValue, $0.value.count) }
            .sorted { lhs, rhs in
                if lhs.1 == rhs.1 { return lhs.0 < rhs.0 }
                return lhs.1 > rhs.1
            }
            .prefix(6)

        var extCounts: [String: Int] = [:]
        for item in items {
            let ext = item.fileExtension.isEmpty ? "unknown" : item.fileExtension.lowercased()
            extCounts[ext, default: 0] += 1
        }
        let topExts = extCounts
            .sorted { lhs, rhs in
                if lhs.value == rhs.value { return lhs.key < rhs.key }
                return lhs.value > rhs.value
            }
            .prefix(12)

        let urlsPath = outDir.deletingLastPathComponent().appendingPathComponent("URLs/URLs.txt").path
        let allTextPath = outDir.deletingLastPathComponent().appendingPathComponent("txt/All The Text.txt").path
        let hashPath = outDir.deletingLastPathComponent().appendingPathComponent("hash_candidates/hashcat_candidates.jsonl").path

        let topURLs = readFirstLines(path: urlsPath, maxLines: 25)
        let languageSample = readFirstLines(path: allTextPath, maxLines: 30)
            .joined(separator: "\n")
            .prefix(1600)
        let hashKinds = hashKindHistogram(jsonlPath: hashPath)

        let messageLikeSources = items
            .filter {
                let p = $0.sourcePath.lowercased()
                return p.contains("chat") || p.contains("message") || p.contains("sms") || p.contains("mms")
            }
            .map { URL(fileURLWithPath: $0.sourcePath).lastPathComponent }
        let topMessageSources = Array(Set(messageLikeSources)).sorted().prefix(20)

        let riskScore = min(
            100,
            (metrics["messages"] ?? 0) * 2 +
            (metrics["urls"] ?? 0) / 20 +
            (metrics["hash_candidates"] ?? 0) / 50 +
            (run.forensic.possibleDecryptableDBs * 8)
        )
        let riskBand: String = riskScore >= 70 ? "High" : (riskScore >= 35 ? "Medium" : "Low")

        let profilerAgentLines = topCategories.map { "- \($0.0): \($0.1) (\(Int(Double($0.1) / Double(total) * 100))%)" }
        let extAgentLines = topExts.map { "- \($0.key): \($0.value)" }
        let entityAgentLines = topURLs.map { "- \($0)" }
        let hashAgentLines = hashKinds.map { "- \($0.key): \($0.value)" }

        let md = """
        # Evidence Intelligence Report
        
        ## Run
        - Name: \(run.name)
        - Output: \(run.outputRoot)
        - Scanned items: \(items.count)
        
        ## Agent 1: Source Profiler
        Top categories:
        \(profilerAgentLines.isEmpty ? "- none" : profilerAgentLines.joined(separator: "\n"))
        
        Top file extensions:
        \(extAgentLines.isEmpty ? "- none" : extAgentLines.joined(separator: "\n"))
        
        ## Agent 2: Entity Triage
        - URLs detected: \(metrics["urls"] ?? 0)
        - Emails detected: \(metrics["emails"] ?? 0)
        - Phones detected: \(metrics["phones"] ?? 0)
        - Message signals: \(metrics["messages"] ?? 0)
        - Language text signals: \(metrics["language_signals"] ?? 0)
        
        Representative URLs:
        \(entityAgentLines.isEmpty ? "- none" : entityAgentLines.joined(separator: "\n"))
        
        ## Agent 3: Hash Triage
        - Hash candidates: \(metrics["hash_candidates"] ?? 0)
        Hash families:
        \(hashAgentLines.isEmpty ? "- none" : hashAgentLines.joined(separator: "\n"))
        
        ## Agent 4: Message Surface
        Potential message-related sources:
        \(topMessageSources.isEmpty ? "- none" : topMessageSources.map { "- \($0)" }.joined(separator: "\n"))
        
        ## Agent 5: Risk Scorer
        - Risk score: \(riskScore)/100
        - Risk band: \(riskBand)
        - Possible decryptable DBs: \(run.forensic.possibleDecryptableDBs)
        - Nested archives: \(run.forensic.nestedArchives)
        
        ## Analyst Notes Seed
        \(languageSample.isEmpty ? "No text sample available." : String(languageSample))
        """

        let jsonPayload: [String: Any] = [
            "run_name": run.name,
            "output_root": run.outputRoot,
            "scanned_items": items.count,
            "metrics": metrics,
            "risk_score": riskScore,
            "risk_band": riskBand,
            "top_categories": topCategories.map { ["category": $0.0, "count": $0.1] },
            "top_extensions": topExts.map { ["extension": $0.key, "count": $0.value] },
            "top_urls": topURLs,
            "hash_families": hashKinds.map { ["kind": $0.key, "count": $0.value] },
            "message_related_sources": Array(topMessageSources)
        ]

        do {
            try md.write(to: outDir.appendingPathComponent("intelligence_report.md"), atomically: true, encoding: .utf8)
            let data = try JSONSerialization.data(withJSONObject: jsonPayload, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: outDir.appendingPathComponent("intelligence_report.json"))
            return 1
        } catch {
            return 0
        }
    }

    private func generateAgentOutputs(for run: ScanRun, at runRoot: URL) -> Int {
        let outDir = runRoot.appendingPathComponent("evidence_intelligence", isDirectory: true)
        let agentsDir = outDir.appendingPathComponent("agents", isDirectory: true)
        try? FileManager.default.createDirectory(at: agentsDir, withIntermediateDirectories: true)

        let items = run.items
        let metrics = run.forensic.metrics ?? [:]
        let total = max(items.count, 1)

        let byCategory = Dictionary(grouping: items, by: \.category)
        let topCategories = byCategory
            .map { ($0.key.rawValue, $0.value.count) }
            .sorted { lhs, rhs in
                if lhs.1 == rhs.1 { return lhs.0 < rhs.0 }
                return lhs.1 > rhs.1
            }
            .prefix(8)

        var extCounts: [String: Int] = [:]
        for item in items {
            let ext = item.fileExtension.isEmpty ? "unknown" : item.fileExtension.lowercased()
            extCounts[ext, default: 0] += 1
        }
        let topExts = extCounts
            .sorted { lhs, rhs in
                if lhs.value == rhs.value { return lhs.key < rhs.key }
                return lhs.value > rhs.value
            }
            .prefix(15)

        let urlsPath = runRoot.appendingPathComponent("URLs/URLs.txt").path
        let allTextPath = runRoot.appendingPathComponent("txt/All The Text.txt").path
        let hashPath = runRoot.appendingPathComponent("hash_candidates/hashcat_candidates.jsonl").path

        let topURLs = readFirstLines(path: urlsPath, maxLines: 200)
        let allTextLines = readFirstLines(path: allTextPath, maxLines: 1500)
        let hashKinds = hashKindHistogram(jsonlPath: hashPath)

        let messageLikeItems = items.filter {
            let p = $0.sourcePath.lowercased()
            return p.contains("chat") || p.contains("message") || p.contains("sms") || p.contains("mms")
        }
        let topMessageSources = Array(Set(messageLikeItems.map {
            URL(fileURLWithPath: $0.sourcePath).lastPathComponent
        })).sorted().prefix(50)

        let likelyChatDBs = items.filter {
            let ext = $0.fileExtension.lowercased()
            let p = $0.sourcePath.lowercased()
            let dbish = ext == "db" || ext == "sqlite" || ext == "sqlite3" || ext == "plist" || ext == "bplist"
            return dbish && (p.contains("chat") || p.contains("message") || p.contains("sms") || p.contains("imessage"))
        }

        let languageSample = allTextLines.joined(separator: "\n").prefix(3200)
        let riskScore = min(
            100,
            (metrics["messages"] ?? 0) * 2 +
            (metrics["urls"] ?? 0) / 20 +
            (metrics["hash_candidates"] ?? 0) / 50 +
            (run.forensic.possibleDecryptableDBs * 8)
        )
        let riskBand: String = riskScore >= 70 ? "High" : (riskScore >= 35 ? "Medium" : "Low")

        var recommendedActions: [String] = []
        if !likelyChatDBs.isEmpty {
            recommendedActions.append("Prioritize message DB parsing for likely chat databases.")
        }
        if (metrics["hash_candidates"] ?? 0) > 0 {
            recommendedActions.append("Attempt offline cracking against hash candidates with context wordlists.")
        }
        if (metrics["urls"] ?? 0) > 100 {
            recommendedActions.append("Cluster recovered URLs by host and date for lead triage.")
        }
        if run.forensic.possibleDecryptableDBs > 0 {
            recommendedActions.append("Run decryptability checks against detected encrypted database signatures.")
        }
        if recommendedActions.isEmpty {
            recommendedActions.append("No critical triage actions detected; continue manual review by category.")
        }

        var written = 0
        func writeAgent(_ slug: String, title: String, body: String, payload: [String: Any]) {
            do {
                try body.write(
                    to: agentsDir.appendingPathComponent("\(slug).md"),
                    atomically: true,
                    encoding: .utf8
                )
                let data = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
                try data.write(to: agentsDir.appendingPathComponent("\(slug).json"))
                written += 1
            } catch {
                _ = title
            }
        }

        let sourceProfilerLines = topCategories.map {
            "- \($0.0): \($0.1) (\(Int(Double($0.1) / Double(total) * 100))%)"
        }.joined(separator: "\n")
        let topExtLines = topExts.map { "- \($0.key): \($0.value)" }.joined(separator: "\n")
        writeAgent(
            "01_source_profiler",
            title: "Source Profiler",
            body: """
            # Agent 1: Source Profiler
            ## Top Categories
            \(sourceProfilerLines.isEmpty ? "- none" : sourceProfilerLines)

            ## Top Extensions
            \(topExtLines.isEmpty ? "- none" : topExtLines)
            """,
            payload: [
                "agent": "source_profiler",
                "top_categories": topCategories.map { ["category": $0.0, "count": $0.1] },
                "top_extensions": topExts.map { ["extension": $0.key, "count": $0.value] }
            ]
        )

        writeAgent(
            "02_entity_triage",
            title: "Entity Triage",
            body: """
            # Agent 2: Entity Triage
            - URLs: \(metrics["urls"] ?? 0)
            - Emails: \(metrics["emails"] ?? 0)
            - Phones: \(metrics["phones"] ?? 0)
            - Message Signals: \(metrics["messages"] ?? 0)
            - Language Signals: \(metrics["language_signals"] ?? 0)

            ## Sample URLs
            \(topURLs.prefix(60).map { "- \($0)" }.joined(separator: "\n"))
            """,
            payload: [
                "agent": "entity_triage",
                "metrics": [
                    "urls": metrics["urls"] ?? 0,
                    "emails": metrics["emails"] ?? 0,
                    "phones": metrics["phones"] ?? 0,
                    "messages": metrics["messages"] ?? 0,
                    "language_signals": metrics["language_signals"] ?? 0
                ],
                "sample_urls": Array(topURLs.prefix(200))
            ]
        )

        writeAgent(
            "03_hash_triage",
            title: "Hash Triage",
            body: """
            # Agent 3: Hash Triage
            - Hash candidates: \(metrics["hash_candidates"] ?? 0)

            ## Hash Families
            \(hashKinds.map { "- \($0.key): \($0.value)" }.joined(separator: "\n"))
            """,
            payload: [
                "agent": "hash_triage",
                "hash_candidates": metrics["hash_candidates"] ?? 0,
                "hash_families": hashKinds.map { ["kind": $0.key, "count": $0.value] }
            ]
        )

        writeAgent(
            "04_message_surface",
            title: "Message Surface",
            body: """
            # Agent 4: Message Surface
            - Message-like items: \(messageLikeItems.count)
            - Likely chat DB/plist files: \(likelyChatDBs.count)

            ## Candidate Sources
            \(topMessageSources.map { "- \($0)" }.joined(separator: "\n"))
            """,
            payload: [
                "agent": "message_surface",
                "message_like_items": messageLikeItems.count,
                "likely_chat_databases": likelyChatDBs.prefix(100).map {
                    [
                        "source": $0.sourcePath,
                        "extension": $0.fileExtension,
                        "offset": $0.offset,
                        "size": $0.length
                    ]
                }
            ]
        )

        writeAgent(
            "05_risk_scorer",
            title: "Risk Scorer",
            body: """
            # Agent 5: Risk Scorer
            - Risk score: \(riskScore)/100
            - Risk band: \(riskBand)
            - Possible decryptable DBs: \(run.forensic.possibleDecryptableDBs)
            - Nested archives: \(run.forensic.nestedArchives)
            """,
            payload: [
                "agent": "risk_scorer",
                "risk_score": riskScore,
                "risk_band": riskBand,
                "possible_decryptable_dbs": run.forensic.possibleDecryptableDBs,
                "nested_archives": run.forensic.nestedArchives
            ]
        )

        writeAgent(
            "06_action_planner",
            title: "Action Planner",
            body: """
            # Agent 6: Action Planner
            ## Recommended Next Steps
            \(recommendedActions.map { "- \($0)" }.joined(separator: "\n"))

            ## Analyst Notes Seed
            \(languageSample.isEmpty ? "No text sample available." : String(languageSample))
            """,
            payload: [
                "agent": "action_planner",
                "recommended_actions": recommendedActions,
                "analyst_notes_seed": String(languageSample)
            ]
        )

        let summary = """
        # Agent Summary
        - Run: \(run.name)
        - Output: \(run.outputRoot)
        - Agent files generated: \(written)
        - Risk: \(riskBand) (\(riskScore)/100)

        ## Recommended Actions
        \(recommendedActions.map { "- \($0)" }.joined(separator: "\n"))

        ## Agent Outputs
        - agents/01_source_profiler.md
        - agents/02_entity_triage.md
        - agents/03_hash_triage.md
        - agents/04_message_surface.md
        - agents/05_risk_scorer.md
        - agents/06_action_planner.md
        """

        do {
            try summary.write(
                to: outDir.appendingPathComponent("agents_summary.md"),
                atomically: true,
                encoding: .utf8
            )
            let payload: [String: Any] = [
                "run_name": run.name,
                "output_root": run.outputRoot,
                "generated_agents": written,
                "risk_score": riskScore,
                "risk_band": riskBand,
                "recommended_actions": recommendedActions
            ]
            let data = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: outDir.appendingPathComponent("agents_summary.json"))
            return written + 1
        } catch {
            return written
        }
    }

    private func generateRecommendedActionArtifacts(for run: ScanRun, at runRoot: URL) -> Int {
        let outDir = runRoot.appendingPathComponent("evidence_intelligence", isDirectory: true)
        let actionsDir = outDir.appendingPathComponent("actions", isDirectory: true)
        try? FileManager.default.createDirectory(at: actionsDir, withIntermediateDirectories: true)

        let urlsPath = runRoot.appendingPathComponent("URLs/URLs.txt").path
        let allTextPath = runRoot.appendingPathComponent("txt/All The Text.txt").path
        let urlLines = readFirstLines(path: urlsPath, maxLines: 120_000)
        let allText = readFirstLines(path: allTextPath, maxLines: 60_000).joined(separator: "\n")

        var filesWritten = 0

        // Action 1: extract likely message text from SQLite chat/message databases.
        let messageDBCandidates = resolveLikelyMessageDBs(run: run, runRoot: runRoot)
        var messageRows: [String] = []
        for db in messageDBCandidates.prefix(30) {
            let rows = extractMessageRowsFromSQLite(at: db, maxRows: 300)
            if !rows.isEmpty {
                let header = "\n# \(db.lastPathComponent)\n"
                messageRows.append(header)
                messageRows.append(contentsOf: rows.map { "- \($0)" })
            }
        }
        let messageOutput = messageRows.isEmpty
            ? "No message-like rows extracted from SQLite candidates.\n"
            : messageRows.joined(separator: "\n")
        do {
            try messageOutput.write(
                to: actionsDir.appendingPathComponent("messages_extracted.txt"),
                atomically: true,
                encoding: .utf8
            )
            filesWritten += 1
        } catch {}

        // Action 2: build practical wordlist from extracted text + URLs + source names for hash workflows.
        var tokenCounts: [String: Int] = [:]
        for token in tokenizeForWordlist(allText) {
            tokenCounts[token, default: 0] += 1
        }
        for line in urlLines.prefix(30_000) {
            for token in tokenizeForWordlist(line) {
                tokenCounts[token, default: 0] += 1
            }
        }
        for item in run.items.prefix(30_000) {
            let base = URL(fileURLWithPath: item.sourcePath).lastPathComponent
            for token in tokenizeForWordlist(base) {
                tokenCounts[token, default: 0] += 1
            }
        }
        let wordlist = tokenCounts
            .filter { pair in
                if pair.key.count < 6 { return false }
                return pair.key.range(of: #"^\d+$"#, options: .regularExpression) == nil
            }
            .sorted { lhs, rhs in
                if lhs.value == rhs.value { return lhs.key < rhs.key }
                return lhs.value > rhs.value
            }
            .prefix(40_000)
            .map(\.key)
            .joined(separator: "\n")
        do {
            try wordlist.write(
                to: actionsDir.appendingPathComponent("hash_wordlist.txt"),
                atomically: true,
                encoding: .utf8
            )
            filesWritten += 1
        } catch {}

        // Action 3: cluster recovered URLs by host.
        var hostCounts: [String: Int] = [:]
        for line in urlLines {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            let parsed = URL(string: trimmed) ?? URL(string: "https://\(trimmed)")
            guard let host = parsed?.host?.lowercased(), !host.isEmpty else { continue }
            hostCounts[host, default: 0] += 1
        }
        let topHosts = hostCounts.sorted {
            if $0.value == $1.value { return $0.key < $1.key }
            return $0.value > $1.value
        }
        let hostMarkdown = """
        # URL Host Clusters
        - Total unique hosts: \(hostCounts.count)

        \(topHosts.prefix(500).map { "- \($0.key): \($0.value)" }.joined(separator: "\n"))
        """
        do {
            try hostMarkdown.write(
                to: actionsDir.appendingPathComponent("url_clusters.md"),
                atomically: true,
                encoding: .utf8
            )
            let hostPayload: [String: Any] = [
                "unique_hosts": hostCounts.count,
                "top_hosts": topHosts.prefix(2000).map { ["host": $0.key, "count": $0.value] }
            ]
            let data = try JSONSerialization.data(withJSONObject: hostPayload, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: actionsDir.appendingPathComponent("url_clusters.json"))
            filesWritten += 2
        } catch {}

        // Action 4: quick decryptability signatures against DB-like files.
        let decryptCandidates = resolveDBLikeFiles(run: run, runRoot: runRoot).prefix(80)
        var decryptFindings: [[String: Any]] = []
        var decryptLines: [String] = []
        for file in decryptCandidates {
            guard let data = try? Data(contentsOf: file, options: .mappedIfSafe) else { continue }
            let head = data.prefix(131_072)
            let markerChecks: [(String, String)] = [
                ("SQLCipher", "SQLCipher"),
                ("Encrypted", "encrypted"),
                ("Cipher Salt", "cipher_salt"),
                ("Keychain", "keychain"),
                ("backup key", "backup key"),
                ("AES", "aes"),
                ("PBKDF2", "pbkdf2")
            ]
            var markers: [String] = []
            for (name, needle) in markerChecks {
                if containsCaseInsensitiveASCII(head, needle: needle) {
                    markers.append(name)
                }
            }
            if !markers.isEmpty {
                decryptLines.append("- \(file.lastPathComponent): \(markers.joined(separator: ", "))")
                decryptFindings.append([
                    "file": file.path,
                    "markers": markers
                ])
            }
        }
        let decryptReport = """
        # Decryptability Checks
        - Files with potential cryptographic/encryption signals: \(decryptFindings.count)

        \(decryptLines.isEmpty ? "- none" : decryptLines.joined(separator: "\n"))
        """
        do {
            try decryptReport.write(
                to: actionsDir.appendingPathComponent("decryptability_checks.md"),
                atomically: true,
                encoding: .utf8
            )
            let payload: [String: Any] = ["findings": decryptFindings]
            let data = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: actionsDir.appendingPathComponent("decryptability_checks.json"))
            filesWritten += 2
        } catch {}

        let actionsSummary = """
        # Agent Actions Report
        - Run: \(run.name)
        - Output: \(run.outputRoot)
        - Generated artifacts: \(filesWritten)
        - Message DB candidates: \(messageDBCandidates.count)
        - Extracted message rows: \(messageRows.count)
        - URL lines processed: \(urlLines.count)
        - URL unique hosts: \(hostCounts.count)
        - Decryptability findings: \(decryptFindings.count)

        ## Outputs
        - actions/messages_extracted.txt
        - actions/hash_wordlist.txt
        - actions/url_clusters.md
        - actions/url_clusters.json
        - actions/decryptability_checks.md
        - actions/decryptability_checks.json
        """

        do {
            try actionsSummary.write(
                to: actionsDir.appendingPathComponent("actions_report.md"),
                atomically: true,
                encoding: .utf8
            )
            let reportPayload: [String: Any] = [
                "run_name": run.name,
                "output_root": run.outputRoot,
                "generated_artifacts": filesWritten,
                "message_db_candidates": messageDBCandidates.count,
                "extracted_message_rows": messageRows.count,
                "url_lines_processed": urlLines.count,
                "url_unique_hosts": hostCounts.count,
                "decryptability_findings": decryptFindings.count
            ]
            let data = try JSONSerialization.data(withJSONObject: reportPayload, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: actionsDir.appendingPathComponent("actions_report.json"))
            return filesWritten + 2
        } catch {
            return filesWritten
        }
    }

    private func generateCoverageAudit(for run: ScanRun, at runRoot: URL) -> Int {
        let outDir = runRoot.appendingPathComponent("coverage", isDirectory: true)
        try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)

        let groups = Dictionary(grouping: run.items, by: \.sourcePath)
        guard !groups.isEmpty else { return 0 }

        let fm = FileManager.default
        var rows: [[String: Any]] = []

        for (source, items) in groups {
            let sourceURL = URL(fileURLWithPath: source)
            let sourceSize = (try? fm.attributesOfItem(atPath: source)[.size] as? NSNumber)?.intValue ?? 0

            var validBytes = 0
            var partialBytes = 0
            var uncertainBytes = 0
            var topTypes: [String: Int] = [:]

            for item in items {
                let length = max(item.length, 0)
                switch item.validationStatus {
                case .valid: validBytes += length
                case .partial: partialBytes += length
                case .uncertain: uncertainBytes += length
                }
                topTypes[item.detectedType.lowercased(), default: 0] += 1
            }

            let parsedBytes = validBytes + partialBytes
            let coveragePct: Double
            if sourceSize > 0 {
                coveragePct = min(100.0, (Double(parsedBytes) / Double(sourceSize)) * 100.0)
            } else {
                coveragePct = 0
            }

            let topTypeList = topTypes
                .sorted { lhs, rhs in
                    if lhs.value == rhs.value { return lhs.key < rhs.key }
                    return lhs.value > rhs.value
                }
                .prefix(5)
                .map { "\($0.key):\($0.value)" }

            let alert = sourceSize > (1 * 1_048_576) && coveragePct < 5.0
            rows.append([
                "source": source,
                "file": sourceURL.lastPathComponent,
                "source_bytes": sourceSize,
                "item_count": items.count,
                "valid_bytes": validBytes,
                "partial_bytes": partialBytes,
                "uncertain_bytes": uncertainBytes,
                "parsed_coverage_percent": coveragePct,
                "validation_alert": alert,
                "top_detected_types": topTypeList
            ])
        }

        let sortedRows = rows.sorted { lhs, rhs in
            let la = lhs["validation_alert"] as? Bool ?? false
            let ra = rhs["validation_alert"] as? Bool ?? false
            if la != ra { return la && !ra }
            let lc = lhs["parsed_coverage_percent"] as? Double ?? 0
            let rc = rhs["parsed_coverage_percent"] as? Double ?? 0
            if lc == rc {
                let ln = lhs["file"] as? String ?? ""
                let rn = rhs["file"] as? String ?? ""
                return ln < rn
            }
            return lc < rc
        }

        let flagged = sortedRows.filter { $0["validation_alert"] as? Bool == true }

        var lines: [String] = []
        lines.append("# Coverage Audit")
        lines.append("- Run: \(run.name)")
        lines.append("- Sources analyzed: \(sortedRows.count)")
        lines.append("- Low-coverage alerts: \(flagged.count)")
        lines.append("")
        lines.append("## Alerts")
        if flagged.isEmpty {
            lines.append("- none")
        } else {
            for row in flagged.prefix(100) {
                let file = row["file"] as? String ?? "unknown"
                let pct = row["parsed_coverage_percent"] as? Double ?? 0
                let bytes = row["source_bytes"] as? Int ?? 0
                lines.append("- \(file): \(String(format: "%.2f", pct))% parsed from \(ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file))")
            }
        }
        lines.append("")
        lines.append("## Per Source")
        for row in sortedRows.prefix(500) {
            let file = row["file"] as? String ?? "unknown"
            let pct = row["parsed_coverage_percent"] as? Double ?? 0
            let count = row["item_count"] as? Int ?? 0
            let sourceBytes = row["source_bytes"] as? Int ?? 0
            let validBytes = row["valid_bytes"] as? Int ?? 0
            let partialBytes = row["partial_bytes"] as? Int ?? 0
            let uncertainBytes = row["uncertain_bytes"] as? Int ?? 0
            let types = (row["top_detected_types"] as? [String] ?? []).joined(separator: ", ")
            lines.append("- \(file)")
            lines.append("  coverage=\(String(format: "%.2f", pct))% items=\(count) source=\(ByteCountFormatter.string(fromByteCount: Int64(sourceBytes), countStyle: .file)) valid=\(ByteCountFormatter.string(fromByteCount: Int64(validBytes), countStyle: .file)) partial=\(ByteCountFormatter.string(fromByteCount: Int64(partialBytes), countStyle: .file)) uncertain=\(ByteCountFormatter.string(fromByteCount: Int64(uncertainBytes), countStyle: .file)) types=[\(types)]")
        }

        do {
            try lines.joined(separator: "\n").write(
                to: outDir.appendingPathComponent("coverage_report.md"),
                atomically: true,
                encoding: .utf8
            )
            let csvHeader = "file,source_bytes,item_count,valid_bytes,partial_bytes,uncertain_bytes,parsed_coverage_percent,validation_alert,source\n"
            let csvRows = sortedRows.map { row -> String in
                let file = (row["file"] as? String ?? "").replacingOccurrences(of: "\"", with: "\"\"")
                let source = (row["source"] as? String ?? "").replacingOccurrences(of: "\"", with: "\"\"")
                let sourceBytes = row["source_bytes"] as? Int ?? 0
                let itemCount = row["item_count"] as? Int ?? 0
                let validBytes = row["valid_bytes"] as? Int ?? 0
                let partialBytes = row["partial_bytes"] as? Int ?? 0
                let uncertainBytes = row["uncertain_bytes"] as? Int ?? 0
                let pct = row["parsed_coverage_percent"] as? Double ?? 0
                let alert = row["validation_alert"] as? Bool ?? false
                return "\"\(file)\",\(sourceBytes),\(itemCount),\(validBytes),\(partialBytes),\(uncertainBytes),\(String(format: "%.4f", pct)),\(alert),\"\(source)\""
            }.joined(separator: "\n")
            try (csvHeader + csvRows + "\n").write(
                to: outDir.appendingPathComponent("coverage_report.csv"),
                atomically: true,
                encoding: .utf8
            )
            let payload: [String: Any] = [
                "run_name": run.name,
                "sources_analyzed": sortedRows.count,
                "low_coverage_alerts": flagged.count,
                "rows": sortedRows
            ]
            let data = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: outDir.appendingPathComponent("coverage_report.json"))
            return 3
        } catch {
            return 0
        }
    }

    private func generateBinaryIntelligenceArtifacts(for run: ScanRun, at runRoot: URL) -> Int {
        let outDir = runRoot.appendingPathComponent("binary_intelligence", isDirectory: true)
        try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)

        let binaryExts: Set<String> = [
            "dat", "bin", "raw", "blob", "cache", "tmp",
            "db", "sqlite", "sqlite3", "plist", "bplist",
            "rem", "cod", "bbb", "ipd", "gz", "tgz", "xz", "bz2"
        ]

        let grouped = Dictionary(grouping: run.items, by: \.sourcePath)
        guard !grouped.isEmpty else { return 0 }

        var indexRows: [String] = []
        var fileCount = 0

        for (sourcePath, items) in grouped {
            let srcURL = URL(fileURLWithPath: sourcePath)
            let ext = srcURL.pathExtension.lowercased()
            let candidate = binaryExts.contains(ext) || items.contains(where: { $0.category == .uncertain || $0.category == .archives })
            if !candidate { continue }

            guard let data = try? Data(contentsOf: srcURL, options: .mappedIfSafe) else { continue }
            let capped = data.prefix(128 * 1_048_576) // keep bounded
            if capped.isEmpty { continue }

            let headHex = capped.prefix(64).map { String(format: "%02x", $0) }.joined(separator: " ")
            let tailHex = capped.suffix(64).map { String(format: "%02x", $0) }.joined(separator: " ")
            let entropy = shannonEntropy(bytes: capped)
            let entropyClass: String
            if entropy >= 7.6 { entropyClass = "high (compressed/encrypted-like)" }
            else if entropy >= 6.6 { entropyClass = "medium-high" }
            else if entropy >= 5.2 { entropyClass = "medium" }
            else { entropyClass = "low/structured" }

            let sigHits = signatureOffsets(in: capped)
            let topSigLines = sigHits.prefix(120).map { "- \($0.type) @ 0x\(String($0.offset, radix: 16))" }

            let stringsSample = extractMeaningfulStrings(from: srcURL.path)?
                .split(whereSeparator: \.isNewline)
                .prefix(60)
                .map(String.init)
                .joined(separator: "\n") ?? "No printable strings extracted."

            let fileName = sanitizedFileStem(sourcePath)
            let mdPath = outDir.appendingPathComponent("\(fileName).md")
            let jsonPath = outDir.appendingPathComponent("\(fileName).json")

            let md = """
            # Binary Intelligence: \(srcURL.lastPathComponent)

            - Source: \(sourcePath)
            - Size: \(ByteCountFormatter.string(fromByteCount: Int64(data.count), countStyle: .file))
            - SHA256: \(Hashing.hexSHA256(data))
            - Entropy: \(String(format: "%.4f", entropy)) (\(entropyClass))
            - Signature hits: \(sigHits.count)

            ## Hex Head (64 bytes)
            `\(headHex)`

            ## Hex Tail (64 bytes)
            `\(tailHex)`

            ## Signature Offsets
            \(topSigLines.isEmpty ? "- none" : topSigLines.joined(separator: "\n"))

            ## Strings Sample
            \(stringsSample)
            """

            let payload: [String: Any] = [
                "source": sourcePath,
                "size_bytes": data.count,
                "sha256": Hashing.hexSHA256(data),
                "entropy": entropy,
                "entropy_class": entropyClass,
                "signature_hits": sigHits.map { ["type": $0.type, "offset": $0.offset] },
                "hex_head_64": headHex,
                "hex_tail_64": tailHex
            ]

            do {
                try md.write(to: mdPath, atomically: true, encoding: .utf8)
                let json = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
                try json.write(to: jsonPath)
                fileCount += 1
                indexRows.append("- [\(srcURL.lastPathComponent)](\(mdPath.lastPathComponent)) | entropy \(String(format: "%.3f", entropy)) | signatures \(sigHits.count)")
            } catch {
                continue
            }
        }

        let index = """
        # Binary Intelligence Index
        - Run: \(run.name)
        - Files analyzed: \(fileCount)

        \(indexRows.isEmpty ? "- none" : indexRows.joined(separator: "\n"))
        """
        do {
            try index.write(to: outDir.appendingPathComponent("index.md"), atomically: true, encoding: .utf8)
            return fileCount + 1
        } catch {
            return fileCount
        }
    }

    private func generateDedupeReport(for run: ScanRun, at runRoot: URL) -> Int {
        let outDir = runRoot.appendingPathComponent("dedupe", isDirectory: true)
        try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)

        let removed = run.dedupeRemoved
        let md = """
        # Dedupe Report
        - Mode: \(run.settings.dedupeMode.rawValue)
        - Removed duplicates: \(removed.count)
        - Rule: Only exact byte-identical content (hash+length) is removed.

        ## Removed Items
        \(removed.isEmpty ? "- none" : removed.prefix(500).map { rec in
            "- kept=\(URL(fileURLWithPath: rec.keptSourcePath).lastPathComponent)@0x\(String(rec.keptOffset, radix: 16)) removed=\(URL(fileURLWithPath: rec.removedSourcePath).lastPathComponent)@0x\(String(rec.removedOffset, radix: 16)) length=\(rec.length)"
        }.joined(separator: "\n"))
        """

        do {
            try md.write(to: outDir.appendingPathComponent("dedupe_report.md"), atomically: true, encoding: .utf8)
            try writeJSON(removed, to: outDir.appendingPathComponent("dedupe_removed.json"))
            return 2
        } catch {
            return 0
        }
    }

    private func shannonEntropy(bytes: Data.SubSequence) -> Double {
        if bytes.isEmpty { return 0 }
        var counts = Array(repeating: 0, count: 256)
        for b in bytes {
            counts[Int(b)] += 1
        }
        let total = Double(bytes.count)
        var entropy = 0.0
        for c in counts where c > 0 {
            let p = Double(c) / total
            entropy -= p * log2(p)
        }
        return entropy
    }

    private func signatureOffsets(in data: Data.SubSequence) -> [(type: String, offset: Int)] {
        let signatures: [(String, [UInt8])] = [
            ("jpeg", [0xFF, 0xD8, 0xFF]),
            ("png", [0x89, 0x50, 0x4E, 0x47]),
            ("gif", [0x47, 0x49, 0x46, 0x38]),
            ("pdf", [0x25, 0x50, 0x44, 0x46]),
            ("zip", [0x50, 0x4B, 0x03, 0x04]),
            ("gzip", [0x1F, 0x8B]),
            ("xz", [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]),
            ("bzip2", [0x42, 0x5A, 0x68])
        ]
        guard data.count >= 4 else { return [] }
        let arr = Array(data)
        var hits: [(String, Int)] = []
        let n = arr.count
        for (kind, magic) in signatures {
            let m = magic.count
            if n < m { continue }
            var i = 0
            while i <= n - m {
                if arr[i..<(i + m)].elementsEqual(magic) {
                    hits.append((kind, i))
                    if hits.count >= 2000 { return hits }
                }
                i += 1
            }
        }
        return hits.sorted {
            if $0.1 == $1.1 { return $0.0 < $1.0 }
            return $0.1 < $1.1
        }
    }

    private func resolveLikelyMessageDBs(run: ScanRun, runRoot: URL) -> [URL] {
        let dbExts: Set<String> = ["db", "sqlite", "sqlite3"]
        var seen: Set<String> = []
        var out: [URL] = []
        for item in run.items {
            let ext = item.fileExtension.lowercased()
            let source = item.sourcePath.lowercased()
            let isCandidate = dbExts.contains(ext) && (
                source.contains("chat") || source.contains("message") || source.contains("sms") ||
                source.contains("imessage") || source.contains("mms")
            )
            guard isCandidate else { continue }
            if let path = resolvedReadablePath(for: item, runRoot: runRoot), !seen.contains(path.path) {
                seen.insert(path.path)
                out.append(path)
            }
        }
        return out
    }

    private func resolveDBLikeFiles(run: ScanRun, runRoot: URL) -> [URL] {
        let dbExts: Set<String> = ["db", "sqlite", "sqlite3", "plist", "bplist", "dat"]
        var seen: Set<String> = []
        var out: [URL] = []
        for item in run.items {
            let ext = item.fileExtension.lowercased()
            guard dbExts.contains(ext) else { continue }
            if let path = resolvedReadablePath(for: item, runRoot: runRoot), !seen.contains(path.path) {
                seen.insert(path.path)
                out.append(path)
            }
        }
        return out
    }

    private func resolvedReadablePath(for item: FoundItem, runRoot: URL) -> URL? {
        let fm = FileManager.default
        if let outPath = item.outputPath, !outPath.isEmpty, fm.fileExists(atPath: outPath) {
            return URL(fileURLWithPath: outPath)
        }
        if fm.fileExists(atPath: item.sourcePath) {
            return URL(fileURLWithPath: item.sourcePath)
        }
        let fallback = runRoot.appendingPathComponent(URL(fileURLWithPath: item.sourcePath).lastPathComponent)
        if fm.fileExists(atPath: fallback.path) {
            return fallback
        }
        return nil
    }

    private func tokenizeForWordlist(_ text: String) -> [String] {
        let pattern = #"[A-Za-z0-9_\-\.\@\+\!\#\$\%]{6,32}"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let full = NSRange(text.startIndex..<text.endIndex, in: text)
        return regex.matches(in: text, range: full).compactMap { match in
            guard let range = Range(match.range, in: text) else { return nil }
            return String(text[range]).lowercased()
        }
    }

    private func containsCaseInsensitiveASCII(_ data: Data.SubSequence, needle: String) -> Bool {
        guard let s = String(data: Data(data), encoding: .utf8)?.lowercased() else { return false }
        return s.contains(needle.lowercased())
    }

    private func extractMessageRowsFromSQLite(at dbURL: URL, maxRows: Int) -> [String] {
        #if canImport(SQLite3)
        var db: OpaquePointer?
        guard sqlite3_open_v2(dbURL.path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK, let db else {
            return []
        }
        defer { sqlite3_close(db) }

        var tableStmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT name FROM sqlite_master WHERE type='table';", -1, &tableStmt, nil) == SQLITE_OK else {
            return []
        }
        defer { sqlite3_finalize(tableStmt) }

        let tableHints = ["message", "chat", "sms", "mms", "im", "conversation"]
        let colHints = ["body", "text", "message", "content", "payload", "subject"]

        var rows: [String] = []
        while sqlite3_step(tableStmt) == SQLITE_ROW {
            guard let cName = sqlite3_column_text(tableStmt, 0) else { continue }
            let table = String(cString: cName)
            let lowerTable = table.lowercased()

            var columns: [String] = []
            var pragmaStmt: OpaquePointer?
            let pragmaSQL = "PRAGMA table_info(\"\(table.replacingOccurrences(of: "\"", with: "\"\""))\");"
            if sqlite3_prepare_v2(db, pragmaSQL, -1, &pragmaStmt, nil) == SQLITE_OK, let pragmaStmt {
                defer { sqlite3_finalize(pragmaStmt) }
                while sqlite3_step(pragmaStmt) == SQLITE_ROW {
                    if let cCol = sqlite3_column_text(pragmaStmt, 1) {
                        columns.append(String(cString: cCol))
                    }
                }
            }

            let hasTableHint = tableHints.contains { lowerTable.contains($0) }
            let textColumns = columns.filter { col in
                let low = col.lowercased()
                return colHints.contains { low.contains($0) }
            }
            guard hasTableHint || !textColumns.isEmpty else { continue }
            guard !textColumns.isEmpty else { continue }

            let selectCols = textColumns.prefix(3).map { "\"\($0.replacingOccurrences(of: "\"", with: "\"\""))\"" }.joined(separator: ", ")
            let sql = "SELECT \(selectCols) FROM \"\(table.replacingOccurrences(of: "\"", with: "\"\""))\" LIMIT \(max(20, min(maxRows, 500)));"
            var dataStmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &dataStmt, nil) == SQLITE_OK, let dataStmt else { continue }
            defer { sqlite3_finalize(dataStmt) }

            while sqlite3_step(dataStmt) == SQLITE_ROW {
                var parts: [String] = []
                let colCount = sqlite3_column_count(dataStmt)
                if colCount <= 0 { continue }
                for i in 0..<colCount {
                    if let cVal = sqlite3_column_text(dataStmt, i) {
                        let text = String(cString: cVal).trimmingCharacters(in: .whitespacesAndNewlines)
                        if !text.isEmpty { parts.append(text) }
                    }
                }
                guard !parts.isEmpty else { continue }
                rows.append("[\(table)] " + parts.joined(separator: " | "))
                if rows.count >= maxRows { return rows }
            }
        }
        return rows
        #else
        _ = (dbURL, maxRows)
        return []
        #endif
    }

    private func readFirstLines(path: String, maxLines: Int) -> [String] {
        guard maxLines > 0, let raw = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }
        return raw
            .split(whereSeparator: \.isNewline)
            .map(String.init)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .prefix(maxLines)
            .map { $0 }
    }

    private func hashKindHistogram(jsonlPath: String) -> [(key: String, value: Int)] {
        let lines = readFirstLines(path: jsonlPath, maxLines: 20_000)
        guard !lines.isEmpty else { return [] }
        var counts: [String: Int] = [:]
        for line in lines {
            guard let data = line.data(using: .utf8),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let kind = obj["kind"] as? String,
                  !kind.isEmpty else { continue }
            counts[kind, default: 0] += 1
        }
        return counts.sorted {
            if $0.value == $1.value { return $0.key < $1.key }
            return $0.value > $1.value
        }
    }

    private func collectTextArtifactCandidates(run: ScanRun) -> [URL] {
        var out: [URL] = []
        for ar in run.forensic.analyzerResults {
            if let p = ar.stringsPath, !p.isEmpty {
                out.append(URL(fileURLWithPath: p))
            }
        }
        return out
    }

    private func dedupeURLs(_ urls: [URL]) -> [URL] {
        var seen: Set<String> = []
        var out: [URL] = []
        for u in urls {
            let p = u.path
            if seen.contains(p) { continue }
            seen.insert(p)
            out.append(u)
        }
        return out
    }

    private func readTextSample(from fileURL: URL, maxBytes: Int) -> String? {
        guard let data = try? Data(contentsOf: fileURL, options: .mappedIfSafe), !data.isEmpty else { return nil }
        let sample = Data(data.prefix(maxBytes))
        if let s = String(data: sample, encoding: .utf8) { return s }
        if let s = String(data: sample, encoding: .ascii) { return s }
        return String(decoding: sample, as: UTF8.self)
    }

    private func relativeOutputPath(for candidatePath: String?, root: URL) -> String? {
        guard let candidatePath else { return nil }
        let rootPath = root.path
        guard candidatePath.hasPrefix(rootPath) else { return nil }
        var rel = String(candidatePath.dropFirst(rootPath.count))
        if rel.hasPrefix("/") { rel.removeFirst() }
        return rel.isEmpty ? nil : rel
    }

    private func escapeHTML(_ text: String) -> String {
        var out = text
        out = out.replacingOccurrences(of: "&", with: "&amp;")
        out = out.replacingOccurrences(of: "<", with: "&lt;")
        out = out.replacingOccurrences(of: ">", with: "&gt;")
        out = out.replacingOccurrences(of: "\"", with: "&quot;")
        return out
    }

    private func upsertAnalyzerArtifact(
        run: inout ScanRun,
        sourcePath: String,
        artifactPath: String,
        sqliteDetected: Bool = false
    ) {
        if let idx = run.forensic.analyzerResults.firstIndex(where: { $0.sourcePath == sourcePath }) {
            if run.forensic.analyzerResults[idx].stringsPath == nil {
                run.forensic.analyzerResults[idx].stringsPath = artifactPath
            }
            if sqliteDetected {
                run.forensic.analyzerResults[idx].sqliteHeaderDetected = true
            }
            return
        }

        var ar = AnalyzerResult(sourcePath: sourcePath)
        ar.stringsPath = artifactPath
        ar.sqliteHeaderDetected = sqliteDetected
        run.forensic.analyzerResults.append(ar)
    }

    private func extractPlistReport(from path: String) -> String? {
        let url = URL(fileURLWithPath: path)
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe), !data.isEmpty else { return nil }

        let cap = 16 * 1_048_576
        let parseData: Data
        if data.count > cap {
            parseData = Data(data.prefix(cap))
        } else {
            parseData = data
        }

        var format = PropertyListSerialization.PropertyListFormat.binary
        guard let plist = try? PropertyListSerialization.propertyList(
            from: parseData,
            options: [],
            format: &format
        ) else { return nil }

        var lines: [String] = []
        lines.append("# File: \(path)")
        lines.append("# Format: \(format == .binary ? "binary" : "xml")")
        lines.append("# Bytes parsed: \(parseData.count)")
        lines.append("")
        lines.append(contentsOf: renderPlist(value: plist, indent: 0, keyName: nil, maxDepth: 8, maxEntries: 5000))
        return lines.joined(separator: "\n")
    }

    private func hasBPlistHeader(path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else { return false }
        if data.count < 8 { return false }
        return data.prefix(8).elementsEqual(Data("bplist00".utf8))
    }

    private func hasSQLiteHeader(path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else { return false }
        if data.count < 16 { return false }
        return data.prefix(16).elementsEqual(Data("SQLite format 3".utf8))
    }

    private func renderPlist(
        value: Any,
        indent: Int,
        keyName: String?,
        maxDepth: Int,
        maxEntries: Int
    ) -> [String] {
        if maxEntries <= 0 {
            return ["\(String(repeating: " ", count: indent))...truncated..."]
        }
        if maxDepth <= 0 {
            let keyPrefix = keyName.map { "\($0): " } ?? ""
            return ["\(String(repeating: " ", count: indent))\(keyPrefix)<max-depth>"]
        }

        let pad = String(repeating: " ", count: indent)
        let keyPrefix = keyName.map { "\($0): " } ?? ""

        if let dict = value as? [String: Any] {
            var out = ["\(pad)\(keyPrefix){"]
            var remaining = maxEntries - 1
            for key in dict.keys.sorted() {
                if remaining <= 0 {
                    out.append("\(pad)  ...truncated...")
                    break
                }
                let nested = renderPlist(
                    value: dict[key] as Any,
                    indent: indent + 2,
                    keyName: key,
                    maxDepth: maxDepth - 1,
                    maxEntries: remaining
                )
                out.append(contentsOf: nested)
                remaining -= nested.count
            }
            out.append("\(pad)}")
            return out
        }

        if let arr = value as? [Any] {
            var out = ["\(pad)\(keyPrefix)["]
            var remaining = maxEntries - 1
            for (idx, element) in arr.enumerated() {
                if remaining <= 0 {
                    out.append("\(pad)  ...truncated...")
                    break
                }
                let nested = renderPlist(
                    value: element,
                    indent: indent + 2,
                    keyName: "[\(idx)]",
                    maxDepth: maxDepth - 1,
                    maxEntries: remaining
                )
                out.append(contentsOf: nested)
                remaining -= nested.count
            }
            out.append("\(pad)]")
            return out
        }

        if let data = value as? Data {
            let preview = data.prefix(24).map { String(format: "%02x", $0) }.joined()
            return ["\(pad)\(keyPrefix)<Data \(data.count) bytes preview=\(preview)>"]
        }
        if let date = value as? Date {
            return ["\(pad)\(keyPrefix)\(ISO8601DateFormatter().string(from: date))"]
        }
        return ["\(pad)\(keyPrefix)\(String(describing: value))"]
    }

    private func extractSQLiteReport(from path: String) -> String? {
        #if canImport(SQLite3)
        var db: OpaquePointer?
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK, let db else {
            if db != nil { sqlite3_close(db) }
            return nil
        }
        defer { sqlite3_close(db) }

        var lines: [String] = []
        lines.append("# File: \(path)")
        lines.append("# Type: SQLite")
        lines.append("")

        if let version = sqliteSingleString(db: db, sql: "PRAGMA user_version;"), !version.isEmpty {
            lines.append("PRAGMA user_version: \(version)")
        }

        let tableNames = sqliteColumnStrings(
            db: db,
            sql: "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 60;"
        )
        lines.append("Tables found: \(tableNames.count)")
        lines.append("")

        for table in tableNames {
            let escaped = table.replacingOccurrences(of: "\"", with: "\"\"")
            let countSQL = "SELECT COUNT(*) FROM \"\(escaped)\";"
            let rowCount = sqliteSingleString(db: db, sql: countSQL) ?? "?"
            lines.append("## Table: \(table) (rows=\(rowCount))")

            let sampleSQL = "SELECT * FROM \"\(escaped)\" LIMIT 12;"
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sampleSQL, -1, &stmt, nil) == SQLITE_OK, let stmt else {
                lines.append("  <failed to read sample rows>")
                lines.append("")
                continue
            }

            let colCount = Int(sqlite3_column_count(stmt))
            var headers: [String] = []
            for i in 0..<colCount {
                headers.append(String(cString: sqlite3_column_name(stmt, Int32(i))))
            }
            lines.append("  Columns: \(headers.joined(separator: ", "))")

            var rowIndex = 0
            while sqlite3_step(stmt) == SQLITE_ROW, rowIndex < 12 {
                var cols: [String] = []
                for i in 0..<colCount {
                    let key = headers[i]
                    cols.append("\(key)=\(sqliteColumnValue(stmt: stmt, index: i, maxText: 240))")
                }
                lines.append("  [\(rowIndex)] \(cols.joined(separator: " | "))")
                rowIndex += 1
            }
            sqlite3_finalize(stmt)
            lines.append("")

            // Try to surface message-like text columns for chat forensics.
            let cols = sqliteColumnPairs(
                db: db,
                sql: "PRAGMA table_info(\"\(escaped)\");"
            )
            let textCols = cols
                .filter { col in
                    let name = col.name.lowercased()
                    let type = col.type.lowercased()
                    let nameHit = name.contains("message") || name.contains("body") || name == "text" || name.contains("content") || name.contains("subject")
                    let typeHit = type.contains("text") || type.contains("char") || type.contains("clob")
                    return nameHit || typeHit
                }
                .prefix(4)

            for col in textCols {
                let cEscaped = col.name.replacingOccurrences(of: "\"", with: "\"\"")
                lines.append("  Text Extract: column \(col.name)")
                let textSQL = """
                SELECT rowid, "\(cEscaped)"
                FROM "\(escaped)"
                WHERE "\(cEscaped)" IS NOT NULL
                ORDER BY rowid DESC
                LIMIT 80;
                """
                var tstmt: OpaquePointer?
                guard sqlite3_prepare_v2(db, textSQL, -1, &tstmt, nil) == SQLITE_OK, let tstmt else {
                    lines.append("    <failed>")
                    continue
                }
                var shown = 0
                while sqlite3_step(tstmt) == SQLITE_ROW, shown < 80 {
                    let rowid = sqliteColumnValue(stmt: tstmt, index: 0, maxText: 24)
                    let value = sqliteColumnValue(stmt: tstmt, index: 1, maxText: 500)
                    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
                    if !trimmed.isEmpty && trimmed != "NULL" {
                        lines.append("    [rowid=\(rowid)] \(trimmed)")
                        shown += 1
                    }
                }
                sqlite3_finalize(tstmt)
                if shown == 0 {
                    lines.append("    <no printable text rows>")
                }
            }
            if !textCols.isEmpty { lines.append("") }
        }

        return lines.joined(separator: "\n")
        #else
        _ = path
        return nil
        #endif
    }

    private func sqliteSingleString(db: OpaquePointer, sql: String) -> String? {
        #if canImport(SQLite3)
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else { return nil }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        return sqliteColumnValue(stmt: stmt, index: 0, maxText: 240)
        #else
        _ = (db, sql)
        return nil
        #endif
    }

    private func sqliteColumnStrings(db: OpaquePointer, sql: String) -> [String] {
        #if canImport(SQLite3)
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else { return [] }
        defer { sqlite3_finalize(stmt) }

        var out: [String] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let value = sqliteColumnValue(stmt: stmt, index: 0, maxText: 200)
            if !value.isEmpty {
                out.append(value)
            }
        }
        return out
        #else
        _ = (db, sql)
        return []
        #endif
    }

    private func sqliteColumnPairs(db: OpaquePointer, sql: String) -> [(name: String, type: String)] {
        #if canImport(SQLite3)
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else { return [] }
        defer { sqlite3_finalize(stmt) }

        var out: [(name: String, type: String)] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let name = sqliteColumnValue(stmt: stmt, index: 1, maxText: 120)
            let type = sqliteColumnValue(stmt: stmt, index: 2, maxText: 120)
            if !name.isEmpty {
                out.append((name: name, type: type))
            }
        }
        return out
        #else
        _ = (db, sql)
        return []
        #endif
    }

    private func sqliteColumnValue(stmt: OpaquePointer, index: Int, maxText: Int) -> String {
        #if canImport(SQLite3)
        let type = sqlite3_column_type(stmt, Int32(index))
        switch type {
        case SQLITE_INTEGER:
            return String(sqlite3_column_int64(stmt, Int32(index)))
        case SQLITE_FLOAT:
            return String(format: "%.6f", sqlite3_column_double(stmt, Int32(index)))
        case SQLITE_TEXT:
            guard let c = sqlite3_column_text(stmt, Int32(index)) else { return "" }
            let text = String(cString: c)
            if text.count > maxText {
                return String(text.prefix(maxText)) + "...<truncated>"
            }
            return text
        case SQLITE_BLOB:
            let len = Int(sqlite3_column_bytes(stmt, Int32(index)))
            guard let ptr = sqlite3_column_blob(stmt, Int32(index)), len > 0 else { return "<BLOB 0 bytes>" }
            let sample = Data(bytes: ptr, count: min(len, 16 * 1024))
            let preview = sample.prefix(64).map { String(format: "%02x", $0) }.joined()
            if let text = extractTextFromBlob(sample, maxText: maxText) {
                return "<BLOB \(len) bytes text=\(text)>"
            }
            return "<BLOB \(len) bytes preview=\(preview)>"
        case SQLITE_NULL:
            return "NULL"
        default:
            return "<unknown>"
        }
        #else
        _ = (stmt, index, maxText)
        return ""
        #endif
    }

    private func extractTextFromBlob(_ blob: Data, maxText: Int) -> String? {
        if blob.isEmpty { return nil }

        var plistFormat = PropertyListSerialization.PropertyListFormat.binary
        if let value = try? PropertyListSerialization.propertyList(from: blob, options: [], format: &plistFormat) {
            var hits: [String] = []
            collectPlistStrings(value, into: &hits, limit: 24)
            if !hits.isEmpty {
                let joined = hits.joined(separator: " | ")
                return joined.count > maxText ? String(joined.prefix(maxText)) + "...<truncated>" : joined
            }
        }

        if let utf8 = String(data: blob, encoding: .utf8) {
            let cleaned = utf8.replacingOccurrences(of: "\u{0}", with: " ").trimmingCharacters(in: .whitespacesAndNewlines)
            if cleaned.count >= 6 {
                return cleaned.count > maxText ? String(cleaned.prefix(maxText)) + "...<truncated>" : cleaned
            }
        }
        if let utf16le = String(data: blob, encoding: .utf16LittleEndian) {
            let cleaned = utf16le.replacingOccurrences(of: "\u{0}", with: " ").trimmingCharacters(in: .whitespacesAndNewlines)
            if cleaned.count >= 6 {
                return cleaned.count > maxText ? String(cleaned.prefix(maxText)) + "...<truncated>" : cleaned
            }
        }
        if let utf16be = String(data: blob, encoding: .utf16BigEndian) {
            let cleaned = utf16be.replacingOccurrences(of: "\u{0}", with: " ").trimmingCharacters(in: .whitespacesAndNewlines)
            if cleaned.count >= 6 {
                return cleaned.count > maxText ? String(cleaned.prefix(maxText)) + "...<truncated>" : cleaned
            }
        }

        return nil
    }

    private func collectPlistStrings(_ value: Any, into out: inout [String], limit: Int) {
        if out.count >= limit { return }
        if let s = value as? String {
            let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty, !out.contains(trimmed) {
                out.append(trimmed)
            }
            return
        }
        if let dict = value as? [String: Any] {
            for key in dict.keys.sorted() {
                if out.count >= limit { break }
                collectPlistStrings(dict[key] as Any, into: &out, limit: limit)
            }
            return
        }
        if let arr = value as? [Any] {
            for entry in arr {
                if out.count >= limit { break }
                collectPlistStrings(entry, into: &out, limit: limit)
            }
            return
        }
    }

    private func extractMeaningfulStrings(from path: String) -> String? {
        let url = URL(fileURLWithPath: path)
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let sizeNumber = attrs[.size] as? NSNumber else { return nil }

        let fileSize = sizeNumber.intValue
        if fileSize <= 0 { return nil }

        // Keep extraction bounded for stability on huge binaries.
        let maxBytes = 24 * 1_048_576
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe).prefix(maxBytes) else { return nil }
        if data.isEmpty { return nil }

        let minLen = 4
        let maxOutLines = 5000
        let printable = CharacterSet(charactersIn: " -~\t")
        let bytes = Array(data)

        var lines: [String] = []
        lines.reserveCapacity(1024)
        var seen = Set<String>()

        func appendLine(_ line: String) {
            if line.isEmpty || seen.contains(line) || lines.count >= maxOutLines { return }
            seen.insert(line)
            lines.append(line)
        }

        // ASCII strings
        var ascii: [UInt8] = []
        ascii.reserveCapacity(128)
        for b in bytes {
            let scalar = UnicodeScalar(Int(b))!
            if printable.contains(scalar) {
                ascii.append(b)
            } else {
                if ascii.count >= minLen, let s = String(bytes: ascii, encoding: .ascii) {
                    appendLine("[ASCII] \(s)")
                }
                ascii.removeAll(keepingCapacity: true)
            }
        }
        if lines.count < maxOutLines, ascii.count >= minLen, let s = String(bytes: ascii, encoding: .ascii) {
            appendLine("[ASCII] \(s)")
        }

        // UTF-16LE-like strings (printable byte + 0x00 pattern)
        if lines.count < maxOutLines {
            var chars: [UInt16] = []
            chars.reserveCapacity(128)
            var i = 0
            while i + 1 < bytes.count, lines.count < maxOutLines {
                let lo = bytes[i]
                let hi = bytes[i + 1]
                if hi == 0x00, lo >= 0x20, lo <= 0x7E {
                    chars.append(UInt16(lo))
                } else {
                    if chars.count >= minLen {
                        let scalars = chars.compactMap(UnicodeScalar.init).map(Character.init)
                        appendLine("[UTF16LE] " + String(scalars))
                    }
                    chars.removeAll(keepingCapacity: true)
                }
                i += 2
            }
            if lines.count < maxOutLines, chars.count >= minLen {
                let scalars = chars.compactMap(UnicodeScalar.init).map(Character.init)
                appendLine("[UTF16LE] " + String(scalars))
            }
        }

        // UTF-16BE-like strings (0x00 + printable byte pattern)
        if lines.count < maxOutLines {
            var chars: [UInt16] = []
            chars.reserveCapacity(128)
            var i = 0
            while i + 1 < bytes.count, lines.count < maxOutLines {
                let hi = bytes[i]
                let lo = bytes[i + 1]
                if hi == 0x00, lo >= 0x20, lo <= 0x7E {
                    chars.append(UInt16(lo))
                } else {
                    if chars.count >= minLen {
                        let scalars = chars.compactMap(UnicodeScalar.init).map(Character.init)
                        appendLine("[UTF16BE] " + String(scalars))
                    }
                    chars.removeAll(keepingCapacity: true)
                }
                i += 2
            }
            if lines.count < maxOutLines, chars.count >= minLen {
                let scalars = chars.compactMap(UnicodeScalar.init).map(Character.init)
                appendLine("[UTF16BE] " + String(scalars))
            }
        }

        if lines.isEmpty { return nil }

        let header = [
            "# File: \(path)",
            "# Bytes scanned: \(bytes.count)",
            "# Strings found: \(lines.count)",
            ""
        ].joined(separator: "\n")
        return header + lines.joined(separator: "\n")
    }

    private func extractPDFText(from path: String) -> String? {
        #if canImport(PDFKit)
        let url = URL(fileURLWithPath: path)
        guard let doc = PDFDocument(url: url), let raw = doc.string else { return nil }
        let collapsed = raw
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if collapsed.isEmpty { return nil }
        // Keep artifacts manageable while preserving useful evidence text.
        return String(collapsed.prefix(1_000_000))
        #else
        _ = path
        return nil
        #endif
    }

    private func renderHeatmap(sourcePath: String, detections: [ReasonDetection], destination: URL) -> Bool {
        #if canImport(CoreGraphics) && canImport(ImageIO)
        let srcURL = URL(fileURLWithPath: sourcePath)
        guard let cg = AIEngine.shared.loadCGImage(from: srcURL) else { return false }

        let width = cg.width
        let height = cg.height
        guard width > 0, height > 0 else { return false }

        let colorSpace = CGColorSpaceCreateDeviceRGB()
        guard let ctx = CGContext(
            data: nil,
            width: width,
            height: height,
            bitsPerComponent: 8,
            bytesPerRow: 0,
            space: colorSpace,
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
        ) else { return false }

        let bounds = CGRect(x: 0, y: 0, width: CGFloat(width), height: CGFloat(height))
        ctx.interpolationQuality = .high
        ctx.draw(cg, in: bounds)

        // Subtle global dim + highlighted boxes for explainability.
        ctx.setFillColor(CGColor(gray: 0, alpha: 0.22))
        ctx.fill(bounds)

        for det in detections {
            guard let bb = det.bbox else { continue }
            let r = CGRect(
                x: CGFloat(bb.x) * bounds.width,
                y: CGFloat(bb.y) * bounds.height,
                width: CGFloat(bb.w) * bounds.width,
                height: CGFloat(bb.h) * bounds.height
            ).intersection(bounds)
            if r.isNull || r.isEmpty { continue }

            let alpha = max(0.16, min(0.58, det.confidence * 0.58))
            ctx.setFillColor(CGColor(red: 1.0, green: 0.10, blue: 0.14, alpha: alpha))
            ctx.fill(r)

            ctx.setStrokeColor(CGColor(red: 1.0, green: 0.78, blue: 0.78, alpha: 0.95))
            ctx.setLineWidth(max(1.5, min(bounds.width, bounds.height) * 0.002))
            ctx.stroke(r)
        }

        guard let outCG = ctx.makeImage() else { return false }
        #if canImport(UniformTypeIdentifiers)
        let pngType = UTType.png.identifier as CFString
        #else
        let pngType = "public.png" as CFString
        #endif
        guard let dest = CGImageDestinationCreateWithURL(destination as CFURL, pngType, 1, nil) else { return false }
        CGImageDestinationAddImage(dest, outCG, nil)
        return CGImageDestinationFinalize(dest)
        #else
        _ = (sourcePath, detections, destination)
        return false
        #endif
    }

    private func isImagePath(_ path: String) -> Bool {
        let ext = URL(fileURLWithPath: path).pathExtension.lowercased()
        let imageExts: Set<String> = ["jpg","jpeg","png","gif","webp","tif","tiff","bmp","heic","heif","ico"]
        return imageExts.contains(ext)
    }

    private func sanitizedFileStem(_ path: String) -> String {
        let base = URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent
        let filtered = base.map { c -> Character in
            if c.isLetter || c.isNumber || c == "-" || c == "_" { return c }
            return "_"
        }
        return String(filtered.prefix(80))
    }

    private func writeJSON<T: Encodable>(_ value: T, to url: URL) throws {
        let data = try JSONEncoder.stable.encode(value)
        try data.write(to: url)
    }

    private func hashJSON<T: Encodable>(_ value: T) throws -> String {
        let data = try JSONEncoder.stable.encode(value)
        return Hashing.hexSHA256(data)
    }

    private func buildAIReport(run: ScanRun) -> RunAIReport {
        let modelHash = AIEngine.shared.detectorModelHash(
            modelName: run.settings.aiModelName,
            compute: run.settings.aiComputePreference
        )
        let heatmapsGenerated = run.forensic.analyzerResults.filter { $0.heatmapPath != nil }.count
        return RunAIReport(
            settingsFingerprint: run.settingsFingerprint,
            engineVersion: run.settings.engineVersion,
            aiEnabled: run.settings.enableAI,
            modelName: run.settings.aiModelName,
            modelHash: modelHash,
            computePreference: run.settings.aiComputePreference,
            scaAvailable: AIEngine.shared.scaAvailable,
            scaVersion: AIEngine.shared.scaVersionString,
            scoringVersion: 1,
            heatmapsGenerated: heatmapsGenerated,
            results: run.forensic.analyzerResults
        )
    }

    // MARK: - Utilities

    private static func dateStamp() -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyyMMdd-HHmmss"
        return f.string(from: Date())
    }
}

// MARK: - Export models

private struct RunManifest: Codable, Sendable {
    var runID: String
    var name: String
    var startedAt: Date
    var completedAt: Date
    var sourceRoots: [String]
    var outputRoot: String
    var totalItems: Int
    var warningsCount: Int
    var settingsFingerprint: String
    var schemaVersion: Int
    var engineVersion: String
    var aiEnabled: Bool
    var aiModelName: String
    var aiComputePreference: AIComputePreference
    var aiModelHash: String?

    var embeddingEnabled: Bool
    var embeddingModelID: String
    var embeddingModelIdentifier: String
    var caseMetadata: ForensicCaseMetadata
    var reportIntegrityHash: String
}

private struct IntegrityPayload: Codable, Sendable {
    var settings: ScanSettings
    var forensic: ForensicSummary
    var items: [FoundItem]
}

private struct RunAIReport: Codable, Sendable {
    var settingsFingerprint: String
    var engineVersion: String
    var aiEnabled: Bool
    var modelName: String
    var modelHash: String?
    var computePreference: AIComputePreference
    var scaAvailable: Bool
    var scaVersion: String
    var scoringVersion: Int
    var heatmapsGenerated: Int
    var results: [AnalyzerResult]
}
