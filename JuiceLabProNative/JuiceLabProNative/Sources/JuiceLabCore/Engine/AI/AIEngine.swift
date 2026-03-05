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
        guard let vnModel = loadDetectorVNModel(modelName: modelName, compute: compute) else {
            return nil
        }

        return await withCheckedContinuation { cont in
            let request = VNCoreMLRequest(model: vnModel) { req, _ in
                guard let results = req.results else {
                    cont.resume(returning: nil)
                    return
                }

                let detections: [ReasonDetection] = results.compactMap { r in
                    guard let o = r as? VNRecognizedObjectObservation else { return nil }
                    guard let top = o.labels.first else { return nil }

                    let label = top.identifier
                    let conf = Double(top.confidence)

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
        guard let rawURL = Bundle.main.url(forResource: modelName, withExtension: "mlmodel")
            ?? Bundle.main.url(forResource: modelName, withExtension: "mlpackage") else {
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
            let compiledURL = try MLModel.compileModel(at: rawURL)
            let mlModel = try MLModel(contentsOf: compiledURL, configuration: config)
            let vn = try VNCoreMLModel(for: mlModel)

            let hash = Self.hashModelResource(rawURL)

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
        return .other
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