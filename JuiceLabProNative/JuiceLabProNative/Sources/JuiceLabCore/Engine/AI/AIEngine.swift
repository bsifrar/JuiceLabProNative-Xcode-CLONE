import Foundation
import CoreGraphics
import ImageIO
import CoreML
import CryptoKit

#if canImport(SensitiveContentAnalysis)
import SensitiveContentAnalysis
#endif

#if canImport(Vision)
@preconcurrency import Vision
#endif

public final class AIEngine: @unchecked Sendable {
    public static let shared = AIEngine()
    private init() {}

    // Cache model per (modelName, computePreference)
    private let lock = NSLock()
    private var cachedKey: String?
    private var cachedVNModel: Any? // VNCoreMLModel
    private var cachedModelHash: String?

    // MARK: - SensitiveContentAnalysis (nudity gate)

    public var scaAvailable: Bool {
        #if canImport(SensitiveContentAnalysis)
        return true
        #else
        return false
        #endif
    }

    public var scaVersionString: String {
        #if canImport(SensitiveContentAnalysis)
        // Best-effort: framework bundle version + OS version.
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let osStr = "macOS-\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"
        let fw = Bundle(for: SCSensitivityAnalyzer.self)
        let v = (fw.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String)
            ?? (fw.object(forInfoDictionaryKey: "CFBundleVersion") as? String)
            ?? "unknown"
        return "SensitiveContentAnalysis-\(v)|\(osStr)"
        #else
        let os = ProcessInfo.processInfo.operatingSystemVersion
        return "SensitiveContentAnalysis-unavailable|macOS-\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"
        #endif
    }

    public func scaIsSensitive(cgImage: CGImage) async -> Bool? {
        #if canImport(SensitiveContentAnalysis)
        do {
            let analyzer = SCSensitivityAnalyzer()
            let result = try await analyzer.analyzeImage(cgImage)
            return result.isSensitive
        } catch {
            return nil
        }
        #else
        return nil
        #endif
    }

    // MARK: - Reasons Detector (Vision + CoreML object detection)

    public func detectReasons(
        cgImage: CGImage,
        modelName: String,
        compute: AIComputePreference
    ) async -> [ReasonDetection]? {

        #if canImport(Vision)
        let candidateNames = [modelName, "NSFWDetector", "NSFWReasons"]
        let orderedNames = Array(NSOrderedSet(array: candidateNames)) as? [String] ?? candidateNames

        var resolvedModel: VNCoreMLModel?
        for name in orderedNames {
            if let vn = loadDetectorVNModel(modelName: name, compute: compute) {
                resolvedModel = vn
                break
            }
        }

        guard let vnModel = resolvedModel else {
            return nil
        }

        return await withCheckedContinuation { cont in
            let request = VNCoreMLRequest(model: vnModel) { req, _ in
                guard let results = req.results else {
                    cont.resume(returning: nil)
                    return
                }

                let detections: [ReasonDetection] = results.compactMap { r in
                    if let o = r as? VNRecognizedObjectObservation, let top = o.labels.first {
                        let label = top.identifier
                        let conf = Double(top.confidence)
                        if Self.isBenignLabel(label) { return nil }

                        let reason = Self.mapLabelToReason(label)
                        let bb = o.boundingBox // normalized (Vision space)
                        let bbox = NormalizedRect(
                            x: Double(bb.origin.x),
                            y: Double(bb.origin.y),
                            w: Double(bb.size.width),
                            h: Double(bb.size.height)
                        )

                        return ReasonDetection(
                            reason: reason,
                            confidence: conf,
                            bbox: bbox,
                            modelLabel: label,
                            notes: nil
                        )
                    }

                    if let c = r as? VNClassificationObservation {
                        let label = c.identifier
                        let conf = Double(c.confidence)
                        if Self.isBenignLabel(label) { return nil }
                        // Ignore very weak class votes from generic classifiers.
                        if conf < 0.15 { return nil }

                        return ReasonDetection(
                            reason: Self.mapLabelToReason(label),
                            confidence: conf,
                            bbox: nil,
                            modelLabel: label,
                            notes: "classification"
                        )
                    }
                    return nil
                }

                cont.resume(returning: detections.isEmpty ? [] : detections)
            }

            request.imageCropAndScaleOption = .scaleFill

            let handler = VNImageRequestHandler(cgImage: cgImage, options: [:])
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    try handler.perform([request])
                } catch {
                    cont.resume(returning: nil)
                }
            }
        }
        #else
        return nil
        #endif
    }

    /// Generic, model-free semantic tags (object classes + OCR tokens) used for evidence search.
    /// These are appended to analyzer outputs but do not affect NSFW scoring.
    public func detectSemanticDetections(
        cgImage: CGImage,
        maxObjectLabels: Int = 8,
        maxTextTokens: Int = 10
    ) async -> [ReasonDetection] {
        #if canImport(Vision)
        var out: [ReasonDetection] = []
        var seen = Set<String>()

        if let labels = await classifyImageLabels(cgImage: cgImage, maxCount: maxObjectLabels) {
            for (label, conf) in labels {
                let normalized = normalizeSemanticToken(label)
                guard !normalized.isEmpty, !seen.contains(normalized) else { continue }
                seen.insert(normalized)
                out.append(
                    ReasonDetection(
                        reason: .other,
                        confidence: conf,
                        bbox: nil,
                        modelLabel: normalized,
                        notes: "semantic_object"
                    )
                )
            }
        }

        if let textTokens = await detectTextTokens(cgImage: cgImage, maxCount: maxTextTokens) {
            for token in textTokens {
                let normalized = normalizeSemanticToken(token)
                guard !normalized.isEmpty, !seen.contains(normalized) else { continue }
                seen.insert(normalized)
                out.append(
                    ReasonDetection(
                        reason: .other,
                        confidence: 0.70,
                        bbox: nil,
                        modelLabel: normalized,
                        notes: "semantic_ocr"
                    )
                )
            }
        }

        return out
        #else
        _ = (cgImage, maxObjectLabels, maxTextTokens)
        return []
        #endif
    }

    /// Optional: expose model hash so ScannerEngine can export it.
    public func detectorModelHash(modelName: String, compute: AIComputePreference) -> String? {
        _ = loadDetectorVNModel(modelName: modelName, compute: compute)
        lock.lock()
        defer { lock.unlock() }
        return cachedModelHash
    }

    // MARK: - Utility

    public func loadCGImage(from url: URL) -> CGImage? {
        guard let src = CGImageSourceCreateWithURL(url as CFURL, nil) else { return nil }
        return CGImageSourceCreateImageAtIndex(src, 0, nil)
    }

    // MARK: - Internal model loader

    private func loadDetectorVNModel(modelName: String, compute: AIComputePreference) -> VNCoreMLModel? {
        #if canImport(Vision)
        let key = "\(modelName)|\(compute.rawValue)"

        lock.lock()
        if cachedKey == key, let anyModel = cachedVNModel as? VNCoreMLModel {
            lock.unlock()
            return anyModel
        }
        lock.unlock()

        // IMPORTANT (Reproducibility + MAS):
        // - Bundle includes raw .mlmodel or .mlpackage as a *resource* (Copy Bundle Resources).
        // - We compile to a sandbox cache at runtime, so we never hard-code / rely on .mlmodelc in the bundle.
        guard let modelURL = Bundle.main.url(forResource: modelName, withExtension: "mlmodel")
            ?? Bundle.main.url(forResource: modelName, withExtension: "mlpackage")
            ?? Bundle.main.url(forResource: modelName, withExtension: "mlmodelc") else {
            return nil
        }

        let config = MLModelConfiguration()
        switch compute {
        case .systemDefault:
            // leave default
            break
        case .cpuOnly:
            config.computeUnits = .cpuOnly
        case .all:
            config.computeUnits = .all
        }

        do {
            let modelExt = modelURL.pathExtension.lowercased()
            let loadURL: URL
            if modelExt == "mlmodelc" {
                loadURL = modelURL
            } else {
                loadURL = try MLModel.compileModel(at: modelURL)
            }

            let mlModel = try MLModel(contentsOf: loadURL, configuration: config)
            let vn = try VNCoreMLModel(for: mlModel)

            let hash = Self.hashModelResource(modelURL)

            lock.lock()
            cachedKey = key
            cachedVNModel = vn
            cachedModelHash = hash
            lock.unlock()

            return vn
        } catch {
            return nil
        }
        #else
        return nil
        #endif
    }

    private static func mapLabelToReason(_ label: String) -> NSFWReason {
        let l = label.lowercased()

        // You can tune these mappings to your model’s label set.
        if l.contains("genital") || l.contains("penis") || l.contains("vulva") {
            return .exposedGenitals
        }
        if l.contains("breast") || l.contains("nipple") {
            return .exposedBreast
        }
        if l.contains("lingerie") || l.contains("bra") || l.contains("underwear") {
            return .lingerie
        }
        if l.contains("sex") || l.contains("intercourse") || l.contains("oral") {
            return .sexAct
        }
        if l.contains("butt") || l.contains("buttocks") {
            return .buttocks
        }
        if l.contains("nude") || l.contains("nudity") {
            return .nudity
        }
        if l.contains("porn") || l.contains("explicit") || l.contains("adult") || l.contains("nsfw") {
            return .sexAct
        }
        if l.contains("sexy") || l.contains("provocative") || l.contains("suggestive") {
            return .lingerie
        }
        return .other
    }

    private static func isBenignLabel(_ label: String) -> Bool {
        let l = label.lowercased()
        return l.contains("safe")
            || l.contains("neutral")
            || l == "clean"
            || l == "normal"
            || l == "sfw"
            || l == "non_nude"
            || l == "non-nude"
    }

    private func classifyImageLabels(cgImage: CGImage, maxCount: Int) async -> [(String, Double)]? {
        #if canImport(Vision)
        return await withCheckedContinuation { cont in
            if #available(macOS 11.0, *) {
                let request = VNClassifyImageRequest { req, _ in
                    guard let results = req.results as? [VNClassificationObservation], !results.isEmpty else {
                        cont.resume(returning: nil)
                        return
                    }
                    let labels = results
                        .filter { $0.confidence >= 0.10 }
                        .prefix(max(maxCount, 1))
                        .map { (Self.cleanLabel($0.identifier), Double($0.confidence)) }
                    cont.resume(returning: labels.isEmpty ? nil : Array(labels))
                }
                let handler = VNImageRequestHandler(cgImage: cgImage, options: [:])
                DispatchQueue.global(qos: .userInitiated).async {
                    do {
                        try handler.perform([request])
                    } catch {
                        cont.resume(returning: nil)
                    }
                }
            } else {
                cont.resume(returning: nil)
            }
        }
        #else
        _ = (cgImage, maxCount)
        return nil
        #endif
    }

    private func detectTextTokens(cgImage: CGImage, maxCount: Int) async -> [String]? {
        #if canImport(Vision)
        return await withCheckedContinuation { cont in
            let request = VNRecognizeTextRequest { req, _ in
                guard let observations = req.results as? [VNRecognizedTextObservation], !observations.isEmpty else {
                    cont.resume(returning: nil)
                    return
                }
                var out = Set<String>()
                for obs in observations {
                    guard let top = obs.topCandidates(1).first else { continue }
                    let text = top.string.lowercased()
                    for piece in text.split(whereSeparator: { !$0.isLetter && !$0.isNumber }) {
                        let token = String(piece.prefix(48))
                        if token.count < 3 { continue }
                        out.insert(token)
                        if out.count >= max(maxCount, 1) {
                            cont.resume(returning: Array(out))
                            return
                        }
                    }
                }
                cont.resume(returning: out.isEmpty ? nil : Array(out))
            }
            request.recognitionLevel = .fast
            request.usesLanguageCorrection = false
            request.minimumTextHeight = 0.03

            let handler = VNImageRequestHandler(cgImage: cgImage, options: [:])
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    try handler.perform([request])
                } catch {
                    cont.resume(returning: nil)
                }
            }
        }
        #else
        _ = (cgImage, maxCount)
        return nil
        #endif
    }

    private static func cleanLabel(_ label: String) -> String {
        label
            .replacingOccurrences(of: "_", with: " ")
            .replacingOccurrences(of: "-", with: " ")
            .lowercased()
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func normalizeSemanticToken(_ token: String) -> String {
        let cleaned = Self.cleanLabel(token)
        if cleaned == "cell phone" || cleaned == "mobile phone" || cleaned == "smartphone" {
            return "iphone"
        }
        if cleaned == "ballon" || cleaned == "baloon" {
            return "balloon"
        }
        return cleaned
    }

    private static func hashModelResource(_ url: URL) -> String? {
        // Deterministic hash of the raw .mlmodel / .mlpackage contents (names + bytes).
        // This is the identifier we export for reproducibility.
        let fm = FileManager.default

        var blob = Data()
        if (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true {
            guard let enumerator = fm.enumerator(at: url, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles]) else {
                return nil
            }
            var files: [URL] = []
            for case let f as URL in enumerator {
                if (try? f.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true {
                    files.append(f)
                }
            }
            files.sort { $0.path < $1.path }
            for f in files {
                blob.append(f.path.data(using: .utf8) ?? Data())
                if let d = try? Data(contentsOf: f) { blob.append(d) }
            }
        } else {
            blob.append(url.lastPathComponent.data(using: .utf8) ?? Data())
            if let d = try? Data(contentsOf: url) { blob.append(d) }
        }

        #if canImport(CryptoKit)
        let digest = SHA256.hash(data: blob)
        return digest.map { String(format: "%02x", $0) }.joined()
        #else
        // fallback stable checksum
        let v = blob.reduce(into: UInt64(1469598103934665603)) { h, b in
            h ^= UInt64(b)
            h &*= 1099511628211
        }
        return String(v)
        #endif
    }
}
