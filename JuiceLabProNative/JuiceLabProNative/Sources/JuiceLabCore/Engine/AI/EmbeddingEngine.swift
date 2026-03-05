import Foundation

#if canImport(NaturalLanguage)
import NaturalLanguage
#endif

/// MAS-safe embedding engine.
///
/// Default implementation uses Apple's on-device `NLEmbedding` (no network).
/// If you later ship your own CoreML embedding model, keep the public surface area
/// and swap implementation behind `modelID`.
public final class EmbeddingEngine: @unchecked Sendable {
    public static let shared = EmbeddingEngine()
    private init() {}

    private let lock = NSLock()

    #if canImport(NaturalLanguage)
    private var cachedModelID: String?
    private var cachedEmbedding: NLEmbedding?
    #endif

    public func embed(text: String, modelID: String) async -> [Float]? {
        #if canImport(NaturalLanguage)
        // NLEmbedding usage is serialized; concurrent calls can crash inside CoreNLP on some OS builds.
        lock.lock()
        defer { lock.unlock() }

        guard let emb = loadEmbeddingLocked(modelID: modelID) else { return nil }
        guard let v = emb.vector(for: text) else { return nil }
        return v.map { Float($0) }
        #else
        _ = (text, modelID)
        return nil
        #endif
    }

    public func modelIdentifier(modelID: String) -> String {
        // Deterministic identifier that will appear in exports.
        // When using Apple embeddings, include platform version so users can reproduce the same environment.
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let osStr = "macOS-\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"
        return "\(modelID)|\(osStr)"
    }

    #if canImport(NaturalLanguage)
    private func loadEmbeddingLocked(modelID: String) -> NLEmbedding? {
        if cachedModelID == modelID, let e = cachedEmbedding {
            return e
        }

        // Today we support only one built-in model id.
        // Future: map modelID to locale/asset/CoreML model.
        let e: NLEmbedding?
        if modelID == "apple_nlembedding_sentence_en" {
            e = NLEmbedding.sentenceEmbedding(for: .english)
        } else {
            // best effort fallback
            e = NLEmbedding.sentenceEmbedding(for: .english)
        }

        cachedModelID = modelID
        cachedEmbedding = e
        return e
    }
    #endif
}
