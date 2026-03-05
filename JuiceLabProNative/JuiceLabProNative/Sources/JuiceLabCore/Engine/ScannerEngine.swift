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

#if canImport(UniformTypeIdentifiers)
import UniformTypeIdentifiers
#endif

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
                scaSensitive: sensitive
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

                let (score, severity) = Self.scoreDetections(detections: detections, scaSensitive: sensitive)
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
                if ext.isEmpty || enabledTypes.contains(ext) {
                    results.append(root)
                }
                continue
            }

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
                let key = item.contentHash ?? item.sourcePath
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
                let hash = item.contentHash ?? item.sourcePath
                let key = "\(size)|\(hash)"
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
