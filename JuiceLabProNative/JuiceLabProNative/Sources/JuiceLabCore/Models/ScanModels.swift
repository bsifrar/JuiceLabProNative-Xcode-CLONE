import Foundation

#if canImport(CryptoKit)
import CryptoKit
#endif

// MARK: - Categories / Modes

public enum FileCategory: String, Codable, CaseIterable, Sendable {
    case images, video, audio, text, archives, uncertain
}

public enum ValidationStatus: String, Codable, Sendable {
    case valid, partial, uncertain
}

public enum PerformanceMode: String, Codable, CaseIterable, Sendable {
    case fast, balanced, thorough

    public var stride: Int {
        switch self {
        case .fast: return 4
        case .balanced: return 1
        case .thorough: return 1
        }
    }

    public var batchSize: Int {
        switch self {
        case .fast: return 64
        case .balanced: return 32
        case .thorough: return 16
        }
    }
}

public enum DedupeMode: String, Codable, CaseIterable, Sendable {
    case off, hash, hashAndSize
}

public enum OrganizationScheme: String, Codable, CaseIterable, Sendable {
    case bySource, byType, flat
}

// MARK: - Items / Progress

public struct FoundItem: Identifiable, Codable, Hashable, Sendable {
    public let id: UUID
    public let sourcePath: String
    public let offset: Int
    public let length: Int
    public let detectedType: String
    public let category: FileCategory
    public let fileExtension: String
    public let confidence: Double
    public let validationStatus: ValidationStatus
    public var contentHash: String?
    public var outputPath: String?

    public init(
        id: UUID = UUID(),
        sourcePath: String,
        offset: Int,
        length: Int,
        detectedType: String,
        category: FileCategory,
        fileExtension: String,
        confidence: Double,
        validationStatus: ValidationStatus,
        contentHash: String? = nil,
        outputPath: String? = nil
    ) {
        self.id = id
        self.sourcePath = sourcePath
        self.offset = offset
        self.length = length
        self.detectedType = detectedType
        self.category = category
        self.fileExtension = fileExtension
        self.confidence = confidence
        self.validationStatus = validationStatus
        self.contentHash = contentHash
        self.outputPath = outputPath
    }
}

public struct ScanProgress: Codable, Sendable {
    public var bytesScanned: Int64 = 0
    public var totalBytes: Int64 = 0
    public var mbPerSecond: Double = 0
    public var etaSeconds: Double = 0
    public var currentFile: String = ""

    public init(
        bytesScanned: Int64 = 0,
        totalBytes: Int64 = 0,
        mbPerSecond: Double = 0,
        etaSeconds: Double = 0,
        currentFile: String = ""
    ) {
        self.bytesScanned = bytesScanned
        self.totalBytes = totalBytes
        self.mbPerSecond = mbPerSecond
        self.etaSeconds = etaSeconds
        self.currentFile = currentFile
    }
}

// MARK: - AI Models

public enum NSFWSeverity: String, Codable, CaseIterable, Sendable {
    case none
    case suggestive
    case explicit
    case unknown
}

/// Stable “why flagged” reasons for UI + exports.
public enum NSFWReason: String, Codable, CaseIterable, Sendable {
    case exposedBreast
    case exposedGenitals
    case lingerie
    case sexAct
    case nudity
    case buttocks
    case other
}

/// Normalized rectangle (0–1 space).
public struct NormalizedRect: Codable, Hashable, Sendable {
    public var x: Double
    public var y: Double
    public var w: Double
    public var h: Double

    public init(x: Double, y: Double, w: Double, h: Double) {
        self.x = x
        self.y = y
        self.w = w
        self.h = h
    }
}

public struct ReasonDetection: Codable, Hashable, Sendable {
    public var reason: NSFWReason
    public var confidence: Double
    public var bbox: NormalizedRect?
    public var modelLabel: String
    public var notes: String?

    public init(
        reason: NSFWReason,
        confidence: Double,
        bbox: NormalizedRect? = nil,
        modelLabel: String,
        notes: String? = nil
    ) {
        self.reason = reason
        self.confidence = confidence
        self.bbox = bbox
        self.modelLabel = modelLabel
        self.notes = notes
    }
}

public enum AIComputePreference: String, Codable, CaseIterable, Sendable {
    case systemDefault
    case cpuOnly
    case all // best-effort GPU/ANE/etc.
}

// MARK: - Analyzer Results / Forensics

public struct AnalyzerResult: Codable, Sendable {
    public var sourcePath: String

    // legacy-ish forensic fields (still useful)
    public var stringsPath: String?
    public var carvedMediaCount: Int
    public var sqliteHeaderDetected: Bool

    // AI fields
    public var scaIsSensitive: Bool?
    public var nsfwSeverity: NSFWSeverity
    public var nsfwScore: Double
    public var reasonDetections: [ReasonDetection]?
    public var heatmapPath: String?

    // reproducibility stamps
    public var aiModelName: String?
    public var aiModelHash: String?
    public var aiEngineVersion: String?
    public var aiSettingsFingerprint: String?
    public var scoringVersion: Int

    public init(
        sourcePath: String,
        stringsPath: String? = nil,
        carvedMediaCount: Int = 0,
        sqliteHeaderDetected: Bool = false
    ) {
        self.sourcePath = sourcePath
        self.stringsPath = stringsPath
        self.carvedMediaCount = carvedMediaCount
        self.sqliteHeaderDetected = sqliteHeaderDetected

        self.scaIsSensitive = nil
        self.nsfwSeverity = .unknown
        self.nsfwScore = 0
        self.reasonDetections = nil
        self.heatmapPath = nil

        self.aiModelName = nil
        self.aiModelHash = nil
        self.aiEngineVersion = nil
        self.aiSettingsFingerprint = nil
        self.scoringVersion = 1
    }
}

public struct StageTiming: Codable, Sendable {
    public var stage: String
    public var files: Int
    public var totalMS: Int
    public var avgMS: Int

    public init(stage: String, files: Int, totalMS: Int, avgMS: Int) {
        self.stage = stage
        self.files = files
        self.totalMS = totalMS
        self.avgMS = avgMS
    }
}

public struct ForensicSummary: Codable, Sendable {
    public var remCount: Int = 0
    public var mediaCount: Int = 0
    public var possibleDecryptableDBs: Int = 0
    public var keyFiles: [String] = []
    public var nestedArchives: Int = 0

    public var analyzerResults: [AnalyzerResult] = []
    public var stageTimings: [StageTiming] = []

    public init() {}
}

// MARK: - Settings / Run

public struct ForensicCaseMetadata: Codable, Sendable {
    public var caseNumber: String
    public var investigator: String
    public var agency: String
    public var evidenceDescription: String
    public var acquisitionDate: Date?
    public var classification: String
    public var notes: String

    public init(
        caseNumber: String = "",
        investigator: String = "",
        agency: String = "",
        evidenceDescription: String = "",
        acquisitionDate: Date? = nil,
        classification: String = "",
        notes: String = ""
    ) {
        self.caseNumber = caseNumber
        self.investigator = investigator
        self.agency = agency
        self.evidenceDescription = evidenceDescription
        self.acquisitionDate = acquisitionDate
        self.classification = classification
        self.notes = notes
    }
}

public struct ScanSettings: Codable, Sendable {
    // versioning for reproducibility
    public var schemaVersion: Int
    public var engineVersion: String

    // core behavior
    public var outputFolder: String
    public var organizationScheme: OrganizationScheme
    public var dedupeMode: DedupeMode
    public var keepHighestQualityImage: Bool
    public var maxFileSizeMB: Int?
    public var performanceMode: PerformanceMode
    public var enabledTypes: Set<String>

    // deterministic AI switch (per-run)
    public var enableAI: Bool

    // app-bundle model name (expects <name>.mlmodel or <name>.mlpackage in Copy Bundle Resources)
    public var aiModelName: String

    // compute preference
    public var aiComputePreference: AIComputePreference

    // embedding-based semantic search
    public var enableEmbeddings: Bool
    public var embeddingModelID: String
    public var exportEmbeddingsSnapshot: Bool
    public var caseMetadata: ForensicCaseMetadata

    public init(
        schemaVersion: Int = 1,
        engineVersion: String = "1.0.0",
        outputFolder: String = {
            let downloadsURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
            let downloadsPath = downloadsURL?.path ?? (NSHomeDirectory() + "/Downloads")
            return downloadsPath + "/Extracted"
        }(),
        organizationScheme: OrganizationScheme = .bySource,
        dedupeMode: DedupeMode = .off,
        keepHighestQualityImage: Bool = true,
        maxFileSizeMB: Int? = nil,
        performanceMode: PerformanceMode = .balanced,
        enabledTypes: Set<String> = [
            "jpeg", "png", "gif", "webp",
            "pdf", "txt", "md", "rtf", "csv", "json", "xml", "html", "htm", "log",
            "zip", "rar", "7z", "tar", "tgz", "tbz2", "txz", "gz", "bz2", "xz", "lz4", "zst", "ar", "deb", "rpm",
            "mp3", "wav", "flac", "ogg", "m4a", "aac", "alac",
            "mp4", "mov", "avi", "mkv", "mpeg", "m2ts", "webm",
            "tiff", "tif", "bmp", "ico", "psd", "dds", "heic", "heif", "heifs", "heics",
            "sqlite", "sqlite3", "db", "sqlitedb", "plist", "bplist",
            "dat", "bin", "raw", "tmp", "blob", "cache", "thumb", "thumbs",
            "rem", "cod", "bbb", "ipd"
        ],
        enableAI: Bool = false,
        aiModelName: String = "NSFWReasons",
        aiComputePreference: AIComputePreference = .systemDefault,
        enableEmbeddings: Bool = true,
        embeddingModelID: String = "apple_nlembedding_sentence_en",
        exportEmbeddingsSnapshot: Bool = false,
        caseMetadata: ForensicCaseMetadata = ForensicCaseMetadata()
    ) {
        self.schemaVersion = schemaVersion
        self.engineVersion = engineVersion
        self.outputFolder = outputFolder
        self.organizationScheme = organizationScheme
        self.dedupeMode = dedupeMode
        self.keepHighestQualityImage = keepHighestQualityImage
        self.maxFileSizeMB = maxFileSizeMB
        self.performanceMode = performanceMode
        self.enabledTypes = enabledTypes
        self.enableAI = enableAI
        self.aiModelName = aiModelName
        self.aiComputePreference = aiComputePreference

        self.enableEmbeddings = enableEmbeddings
        self.embeddingModelID = embeddingModelID
        self.exportEmbeddingsSnapshot = exportEmbeddingsSnapshot
        self.caseMetadata = caseMetadata
    }
}

public struct ScanRun: Identifiable, Codable, Sendable {
    public let id: UUID
    public let startedAt: Date
    public var completedAt: Date?

    public var name: String
    public var sourceRoots: [String]

    public var settings: ScanSettings
    public var settingsFingerprint: String

    public var outputRoot: String

    public var items: [FoundItem]
    public var warnings: [String]
    public var mode: PerformanceMode
    public var forensic: ForensicSummary

    public init(
        id: UUID = UUID(),
        startedAt: Date = .now,
        completedAt: Date? = nil,
        name: String,
        sourceRoots: [String],
        settings: ScanSettings,
        settingsFingerprint: String,
        outputRoot: String,
        items: [FoundItem] = [],
        warnings: [String] = [],
        mode: PerformanceMode = .balanced,
        forensic: ForensicSummary = ForensicSummary()
    ) {
        self.id = id
        self.startedAt = startedAt
        self.completedAt = completedAt
        self.name = name
        self.sourceRoots = sourceRoots
        self.settings = settings
        self.settingsFingerprint = settingsFingerprint
        self.outputRoot = outputRoot
        self.items = items
        self.warnings = warnings
        self.mode = mode
        self.forensic = forensic
    }
}

// MARK: - Fingerprinting + Stable encoding

public extension ScanSettings {
    func fingerprint() -> String {
        do {
            let data = try JSONEncoder.stable.encode(self)
            return Hashing.hexSHA256(data)
        } catch {
            return "fingerprint_error"
        }
    }
}

public extension JSONEncoder {
    static var stable: JSONEncoder {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        enc.dateEncodingStrategy = .iso8601
        return enc
    }
}

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
