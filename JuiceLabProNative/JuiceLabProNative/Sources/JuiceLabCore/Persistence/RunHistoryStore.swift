import Foundation

public actor RunHistoryStore {
    private let fileURL: URL
    private let maxRuns: Int

    public init(fileURL: URL? = nil, maxRuns: Int = 20) {
        let defaultURL = URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Library/Application Support/JuiceLabPro/run-history.json")
        self.fileURL = fileURL ?? defaultURL
        self.maxRuns = maxRuns
    }

    public func load() -> [ScanRun] {
        guard let data = try? Data(contentsOf: fileURL) else { return [] }
        return (try? JSONDecoder().decode([ScanRun].self, from: data)) ?? []
    }

    public func save(run: ScanRun) throws {
        var runs = load()
        runs.insert(run, at: 0)
        runs = Array(runs.prefix(maxRuns))

        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let encoded = try JSONEncoder().encode(runs)
        try encoded.write(to: fileURL)
    }
}
