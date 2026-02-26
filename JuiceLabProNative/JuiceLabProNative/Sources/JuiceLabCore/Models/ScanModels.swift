import Foundation

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
}

public enum DedupeMode: String, Codable, CaseIterable, Sendable {
    case off, hash, hashAndSize
}

public enum OrganizationScheme: String, Codable, CaseIterable, Sendable {
    case bySource, byType, flat
}

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

public struct AnalyzerResult: Codable, Sendable {
    public var sourcePath: String
    public var stringsPath: String?
    public var carvedMediaCount: Int
    public var sqliteHeaderDetected: Bool

    public init(sourcePath: String, stringsPath: String? = nil, carvedMediaCount: Int = 0, sqliteHeaderDetected: Bool = false) {
        self.sourcePath = sourcePath
        self.stringsPath = stringsPath
        self.carvedMediaCount = carvedMediaCount
        self.sqliteHeaderDetected = sqliteHeaderDetected
    }
}

public struct ForensicSummary: Codable, Sendable {
    public var remCount: Int = 0
    public var mediaCount: Int = 0
    public var possibleDecryptableDBs: Int = 0
    public var keyFiles: [String] = []
    public var nestedArchives: Int = 0
    public var analyzerResults: [AnalyzerResult] = []

    public init() {}
}

public struct ScanRun: Identifiable, Codable, Sendable {
    public let id: UUID
    public let startedAt: Date
    public var completedAt: Date?
    public var name: String
    public var sourceRoots: [String]
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
        self.outputRoot = outputRoot
        self.items = items
        self.warnings = warnings
        self.mode = mode
        self.forensic = forensic
    }
}

public struct ScanSettings: Codable, Sendable {
    public var outputFolder: String
    public var organizationScheme: OrganizationScheme
    public var dedupeMode: DedupeMode
    public var keepHighestQualityImage: Bool
    public var maxFileSizeMB: Int?
    public var performanceMode: PerformanceMode
    public var enabledTypes: Set<String>
    public var enablePythonAnalyzers: Bool
    public var pythonPath: String
    public var scriptsFolder: String

    public init(
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
            "pdf",
            "zip", "rar", "7z", "tar", "tgz", "tbz2", "txz", "gz", "bz2", "xz", "lz4", "zst", "ar", "deb", "rpm",
            "mp3", "wav", "flac", "ogg", "m4a", "aac", "alac",
            "mp4", "mov", "avi", "mkv", "mpeg", "m2ts", "webm",
            "tiff", "tif", "bmp", "ico", "psd", "dds", "heic", "heif", "heifs", "heics"
        ],
        enablePythonAnalyzers: Bool = false,
        pythonPath: String = "/usr/bin/python3",
        scriptsFolder: String = NSHomeDirectory() + "/BlackBerryTools"
    ) {
        self.outputFolder = outputFolder
        self.organizationScheme = organizationScheme
        self.dedupeMode = dedupeMode
        self.keepHighestQualityImage = keepHighestQualityImage
        self.maxFileSizeMB = maxFileSizeMB
        self.performanceMode = performanceMode
        self.enabledTypes = enabledTypes
        self.enablePythonAnalyzers = enablePythonAnalyzers
        self.pythonPath = pythonPath
        self.scriptsFolder = scriptsFolder
    }
}

