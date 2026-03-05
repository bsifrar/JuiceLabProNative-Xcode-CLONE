import Foundation

#if canImport(CryptoKit)
import CryptoKit
#endif

#if canImport(ZIPFoundation)
import ZIPFoundation
#endif

public actor ScannerEngine {
    public typealias ProgressHandler = @Sendable (ScanProgress) -> Void
    public typealias ItemHandler = @Sendable (FoundItem) -> Void

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

        mutating func merge(_ other: ForensicDelta) {
            remCount += other.remCount
            mediaCount += other.mediaCount
            possibleDecryptableDBs += other.possibleDecryptableDBs
            nestedArchives += other.nestedArchives
            if !other.keyFiles.isEmpty { keyFiles.append(contentsOf: other.keyFiles) }
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
        onItem: ItemHandler? = nil
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

        run.items = dedupe(items: run.items, mode: settings.dedupeMode)
        run.completedAt = .now
        return run
    }

    // MARK: - Export (Reproducibility Mode)

    public func export(run: ScanRun) async throws -> ScanRun {
        var updated = run

        let runDirName = "\(run.name)-\(Self.dateStamp())"
        let runRoot = URL(fileURLWithPath: run.settings.outputFolder)
            .appendingPathComponent(runDirName, isDirectory: true)
        try FileManager.default.createDirectory(at: runRoot, withIntermediateDirectories: true)

        // 1) Copy files
        let exportedItems = try exportItems(run: run, to: runRoot)
        updated.items = exportedItems

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
            embeddingModelIdentifier: embeddingModelIdentifier
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

    // MARK: - Stage builder

    private func buildStages(tempRoot: URL) -> [ScanStage] {
        [
            ForensicSniffStage(),
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

            if ext == "rem" { out.forensicDelta.remCount += 1 }

            let lower = file.lastPathComponent.lowercased()
            if lower.contains("key") || lower.contains("keys") {
                out.forensicDelta.keyFiles.append(file.path)
            }

            if data.count >= 16,
               let header = String(data: data.prefix(16), encoding: .utf8),
               header.hasPrefix("SQLite format 3") {
                out.forensicDelta.possibleDecryptableDBs += 1
            }
            return out
        }
    }

    struct MediaTypeStage: ScanStage {
        let name: String = "media_type"

        func process(file: URL, data: Data, context: ScanContext) async -> StageOutput {
            var out = StageOutput()
            let ext = file.pathExtension.lowercased()

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
                outputPath: nil
            )

            out.items = [item]
            if category == .images || category == .video { out.forensicDelta.mediaCount += 1 }
            return out
        }
    }

    struct AIClassificationStage: ScanStage {
        let name: String = "ai_classification"

        func process(file: URL, data: Data, context: ScanContext) async -> StageOutput {
            guard context.enableAIClassification else { return StageOutput() }

            // Only attempt for images (and optionally videos later)
            let ext = file.pathExtension.lowercased()
            let imageExts: Set<String> = ["jpg","jpeg","png","gif","webp","tif","tiff","bmp","heic","heif","ico"]
            guard imageExts.contains(ext) else { return StageOutput() }

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
                scaSensitive: sensitive
            )
            ar.nsfwScore = score
            ar.nsfwSeverity = severity

            // Repro stamps
            ar.aiModelName = context.settings.aiModelName
            ar.aiModelHash = AIEngine.shared.detectorModelHash(
                modelName: context.settings.aiModelName,
                compute: context.settings.aiComputePreference
            )
            ar.aiEngineVersion = context.settings.engineVersion
            ar.aiSettingsFingerprint = context.settingsFingerprint
            ar.scoringVersion = 1

            out.analyzerResults = [ar]
            return out
        }

        private static func scoreDetections(detections: [ReasonDetection], scaSensitive: Bool?) -> (Double, NSFWSeverity) {
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
            if score >= 0.85 { severity = .explicit }
            else if score >= 0.45 { severity = .suggestive }
            else { severity = .none }

            // If neither model nor SCA could run, keep unknown
            if detections.isEmpty, scaSensitive == nil {
                return (0, .unknown)
            }
            return (score, severity)
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

            // Today: embed a stable, searchable string derived from file identity.
            // Next: extend to extracted strings / EXIF / decoded messages.
            let canonicalText = EmbeddingCanonicalizer.canonicalText(
                filePath: file.path,
                runID: context.runID,
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
            guard let enumerator = fm.enumerator(
                at: root,
                includingPropertiesForKeys: [.isRegularFileKey],
                options: [.skipsHiddenFiles]
            ) else { continue }

            while let next = enumerator.nextObject() as? URL {
                guard (try? next.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else { continue }
                let ext = next.pathExtension.lowercased()
                if !ext.isEmpty, !enabledTypes.contains(ext) { continue }
                results.append(next)
            }
        }
        return results
    }

    // MARK: - Dedupe

    private func dedupe(items: [FoundItem], mode: DedupeMode) -> [FoundItem] {
        guard mode != .off else { return items }

        switch mode {
        case .off:
            return items
        case .hash:
            var seen = Set<String>()
            var out: [FoundItem] = []
            for item in items {
                let key = item.sourcePath
                if seen.contains(key) { continue }
                seen.insert(key)
                out.append(item)
            }
            return out
        case .hashAndSize:
            var seen = Set<String>()
            var out: [FoundItem] = []
            for item in items {
                let size = (try? URL(fileURLWithPath: item.sourcePath)
                    .resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
                let key = "\(size)|\(item.sourcePath)"
                if seen.contains(key) { continue }
                seen.insert(key)
                out.append(item)
            }
            return out
        }
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

    private func exportItems(run: ScanRun, to root: URL) throws -> [FoundItem] {
        switch run.settings.organizationScheme {
        case .flat:
            return try exportFlat(run.items, to: root)
        case .byType:
            return try exportByType(run.items, to: root)
        case .bySource:
            return try exportBySource(run.items, to: root)
        }
    }

    private func exportFlat(_ items: [FoundItem], to root: URL) throws -> [FoundItem] {
        var exported: [FoundItem] = []
        for item in items {
            exported.append(try exportOne(item: item, to: root))
        }
        return exported
    }

    private func exportByType(_ items: [FoundItem], to root: URL) throws -> [FoundItem] {
        var exported: [FoundItem] = []
        let groups = Dictionary(grouping: items, by: { $0.category })
        for (cat, arr) in groups {
            let dir = root.appendingPathComponent(cat.rawValue, isDirectory: true)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            for item in arr {
                exported.append(try exportOne(item: item, to: dir))
            }
        }
        return exported
    }

    private func exportBySource(_ items: [FoundItem], to root: URL) throws -> [FoundItem] {
        var exported: [FoundItem] = []
        for item in items {
            let srcURL = URL(fileURLWithPath: item.sourcePath)
            let base = srcURL.deletingLastPathComponent().lastPathComponent
            let dir = root.appendingPathComponent(base, isDirectory: true)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            exported.append(try exportOne(item: item, to: dir))
        }
        return exported
    }

    private func exportOne(item: FoundItem, to dir: URL) throws -> FoundItem {
        let src = URL(fileURLWithPath: item.sourcePath)
        let dst = dir.appendingPathComponent(src.lastPathComponent)

        let finalDst: URL
        if FileManager.default.fileExists(atPath: dst.path) {
            finalDst = dir.appendingPathComponent("\(UUID().uuidString)-\(src.lastPathComponent)")
        } else {
            finalDst = dst
        }

        do { try FileManager.default.copyItem(at: src, to: finalDst) } catch { }

        var updated = item
        updated.outputPath = finalDst.path
        return updated
    }

    private func writeJSON<T: Encodable>(_ value: T, to url: URL) throws {
        let data = try JSONEncoder.stable.encode(value)
        try data.write(to: url)
    }

    private func buildAIReport(run: ScanRun) -> RunAIReport {
        let modelHash = AIEngine.shared.detectorModelHash(
            modelName: run.settings.aiModelName,
            compute: run.settings.aiComputePreference
        )
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
    var results: [AnalyzerResult]
}