import Foundation

/// Produces stable, deterministic strings to embed.
///
/// Important: any change here impacts reproducibility. Bump your `engineVersion` / `schemaVersion`
/// when you change the canonicalization rules.
enum EmbeddingCanonicalizer {
    static func canonicalText(
        filePath: String,
        fileContentHash: String,
        settingsFingerprint: String,
        embeddingModelID: String
    ) -> String {

        // Keep it simple + stable. You can expand later with extracted strings, EXIF, etc.
        // Do not include timestamps or non-deterministic values.
        return [
            "v=1",
            "settings=\(settingsFingerprint)",
            "embedModel=\(embeddingModelID)",
            "contentHash=\(fileContentHash)",
            "file=\(URL(fileURLWithPath: filePath).lastPathComponent)"
        ].joined(separator: "\n")
    }
}
