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

            let stride: Int
            switch context.settings.performanceMode {
            case .fast: stride = 16
            case .balanced: stride = 4
            case .thorough: stride = 1
            }

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
                if shouldIncludeFile(withExtension: ext, enabledTypes: enabledTypes) {
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
            processed.insert(item.sourcePath)

            let src = URL(fileURLWithPath: item.sourcePath)
            let ext = src.pathExtension.lowercased()
            let hasSQLiteHeader = hasSQLiteHeader(path: item.sourcePath)
            if !sqliteExts.contains(ext), !item.detectedType.lowercased().contains("sqlite"), !hasSQLiteHeader {
                continue
            }

            guard let report = extractSQLiteReport(from: item.sourcePath) else { continue }

            let stem = sanitizedFileStem(item.sourcePath)
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
            processed.insert(item.sourcePath)

            let sourceURL = URL(fileURLWithPath: item.sourcePath)
            let ext = sourceURL.pathExtension.lowercased()
            let hasPlistHeader = hasBPlistHeader(path: item.sourcePath)
            if ext != "plist" && ext != "bplist" && !hasPlistHeader {
                continue
            }

            guard let report = extractPlistReport(from: item.sourcePath) else { continue }

            let stem = sanitizedFileStem(item.sourcePath)
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
            let blob = Data(bytes: ptr, count: min(len, 64))
            let preview = blob.map { String(format: "%02x", $0) }.joined()
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

        let minLen = 6
        let maxOutLines = 5000
        let printable = CharacterSet(charactersIn: " -~\t")
        let bytes = Array(data)

        var lines: [String] = []
        lines.reserveCapacity(1024)

        // ASCII strings
        var ascii: [UInt8] = []
        ascii.reserveCapacity(128)
        for b in bytes {
            let scalar = UnicodeScalar(Int(b))!
            if printable.contains(scalar) {
                ascii.append(b)
            } else {
                if ascii.count >= minLen, let s = String(bytes: ascii, encoding: .ascii) {
                    lines.append("[ASCII] \(s)")
                    if lines.count >= maxOutLines { break }
                }
                ascii.removeAll(keepingCapacity: true)
            }
        }
        if lines.count < maxOutLines, ascii.count >= minLen, let s = String(bytes: ascii, encoding: .ascii) {
            lines.append("[ASCII] \(s)")
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
                        lines.append("[UTF16] " + String(scalars))
                    }
                    chars.removeAll(keepingCapacity: true)
                }
                i += 2
            }
            if lines.count < maxOutLines, chars.count >= minLen {
                let scalars = chars.compactMap(UnicodeScalar.init).map(Character.init)
                lines.append("[UTF16] " + String(scalars))
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
