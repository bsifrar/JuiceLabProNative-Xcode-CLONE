import Foundation
import SQLite3

/// SQLite-backed embedding store.
///
/// Default behavior: always store embeddings in an app DB (Application Support).
/// Optional per-run export: write a deterministic JSONL snapshot with hashes + model identifiers.
public actor EmbeddingStore {
    public static let shared = EmbeddingStore()

    private var db: OpaquePointer?
    private let dbURL: URL

    public init() {
        let fm = FileManager.default
        let base = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        let dir = base.appendingPathComponent("JuiceLabPro", isDirectory: true)
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        self.dbURL = dir.appendingPathComponent("embeddings.sqlite")

        open()
        migrate()
    }

    deinit {
        if let db { sqlite3_close(db) }
    }

    // MARK: - Public API

    public func upsert(
        runID: UUID,
        sourcePath: String,
        contentHash: String,
        modelID: String,
        settingsFingerprint: String,
        vector: [Float],
        canonicalText: String
    ) {
        guard let db else { return }

        let blob = Self.pack(vector)
        let dim = Int32(vector.count)
        let now = Date().timeIntervalSince1970

        let sql = """
        INSERT INTO embeddings (
            run_id, source_path, content_hash, model_id, settings_fingerprint,
            dim, vector, canonical_text, created_at
        ) VALUES (?,?,?,?,?,?,?,?,?)
        ON CONFLICT(content_hash, model_id) DO UPDATE SET
            run_id=excluded.run_id,
            source_path=excluded.source_path,
            settings_fingerprint=excluded.settings_fingerprint,
            dim=excluded.dim,
            vector=excluded.vector,
            canonical_text=excluded.canonical_text,
            created_at=excluded.created_at;
        """

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, (runID.uuidString as NSString).utf8String, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 2, (sourcePath as NSString).utf8String, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 3, (contentHash as NSString).utf8String, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 4, (modelID as NSString).utf8String, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 5, (settingsFingerprint as NSString).utf8String, -1, SQLITE_TRANSIENT)
        sqlite3_bind_int(stmt, 6, dim)
        blob.withUnsafeBytes { ptr in
            sqlite3_bind_blob(stmt, 7, ptr.baseAddress, Int32(ptr.count), SQLITE_TRANSIENT)
        }
        sqlite3_bind_text(stmt, 8, (canonicalText as NSString).utf8String, -1, SQLITE_TRANSIENT)
        sqlite3_bind_double(stmt, 9, now)

        _ = sqlite3_step(stmt)
    }

    /// Naive cosine-similarity search.
    ///
    /// Note: This scans rows in-process. It's fine for MVP / smaller datasets.
    /// When you grow, add ANN indexing (HNSW) or an on-disk vector index.
    public func searchSimilar(
        query: String,
        modelID: String,
        topK: Int = 20
    ) async -> [SearchHit] {
        guard let db else { return [] }
        guard let qv = await EmbeddingEngine.shared.embed(text: query, modelID: modelID) else { return [] }

        let sql = "SELECT source_path, content_hash, dim, vector FROM embeddings WHERE model_id = ?;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, (modelID as NSString).utf8String, -1, SQLITE_TRANSIENT)

        var hits: [SearchHit] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let sp = String(cString: sqlite3_column_text(stmt, 0))
            let ch = String(cString: sqlite3_column_text(stmt, 1))
            let dim = Int(sqlite3_column_int(stmt, 2))
            guard let blobPtr = sqlite3_column_blob(stmt, 3) else { continue }
            let blobLen = Int(sqlite3_column_bytes(stmt, 3))
            let data = Data(bytes: blobPtr, count: blobLen)
            let v = Self.unpack(data, dim: dim)
            let score = Self.cosine(qv, v)
            hits.append(SearchHit(sourcePath: sp, contentHash: ch, score: score))
        }

        hits.sort { $0.score > $1.score }
        if hits.count > topK { hits = Array(hits.prefix(topK)) }
        return hits
    }

    public func exportSnapshot(runID: UUID, to url: URL) async throws {
        guard let db else { return }
        let encoder = JSONEncoder.stable

        let sql = """
        SELECT run_id, source_path, content_hash, model_id, settings_fingerprint, dim, vector, created_at
        FROM embeddings
        WHERE run_id = ?
        ORDER BY source_path ASC;
        """

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, (runID.uuidString as NSString).utf8String, -1, SQLITE_TRANSIENT)

        var lines = Data()
        while sqlite3_step(stmt) == SQLITE_ROW {
            let run = String(cString: sqlite3_column_text(stmt, 0))
            let sp = String(cString: sqlite3_column_text(stmt, 1))
            let ch = String(cString: sqlite3_column_text(stmt, 2))
            let mid = String(cString: sqlite3_column_text(stmt, 3))
            let sfp = String(cString: sqlite3_column_text(stmt, 4))
            let dim = Int(sqlite3_column_int(stmt, 5))

            guard let blobPtr = sqlite3_column_blob(stmt, 6) else { continue }
            let blobLen = Int(sqlite3_column_bytes(stmt, 6))
            let vectorData = Data(bytes: blobPtr, count: blobLen)

            let created = sqlite3_column_double(stmt, 7)

            let row = EmbeddingSnapshotRow(
                runID: run,
                sourcePath: sp,
                contentHash: ch,
                modelID: mid,
                modelIdentifier: EmbeddingEngine.shared.modelIdentifier(modelID: mid),
                settingsFingerprint: sfp,
                dim: dim,
                vectorBase64: vectorData.base64EncodedString(),
                createdAt: created
            )

            let json = try encoder.encode(row)
            lines.append(json)
            lines.append(0x0A) // \n
        }

        try lines.write(to: url, options: .atomic)
    }

    // MARK: - Types

    public struct SearchHit: Sendable, Codable {
        public var sourcePath: String
        public var contentHash: String
        public var score: Double
    }

    private struct EmbeddingSnapshotRow: Codable {
        var runID: String
        var sourcePath: String
        var contentHash: String
        var modelID: String
        var modelIdentifier: String
        var settingsFingerprint: String
        var dim: Int
        var vectorBase64: String
        var createdAt: Double
    }

    // MARK: - DB Setup

    private func open() {
        if sqlite3_open(dbURL.path, &db) != SQLITE_OK {
            db = nil
        }
        _ = sqlite3_exec(db, "PRAGMA journal_mode=WAL;", nil, nil, nil)
        _ = sqlite3_exec(db, "PRAGMA synchronous=NORMAL;", nil, nil, nil)
    }

    private func migrate() {
        guard let db else { return }
        let sql = """
        CREATE TABLE IF NOT EXISTS embeddings (
            run_id TEXT NOT NULL,
            source_path TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            model_id TEXT NOT NULL,
            settings_fingerprint TEXT NOT NULL,
            dim INTEGER NOT NULL,
            vector BLOB NOT NULL,
            canonical_text TEXT NOT NULL,
            created_at REAL NOT NULL,
            PRIMARY KEY (content_hash, model_id)
        );
        CREATE INDEX IF NOT EXISTS idx_embeddings_run ON embeddings(run_id);
        CREATE INDEX IF NOT EXISTS idx_embeddings_model ON embeddings(model_id);
        """
        _ = sqlite3_exec(db, sql, nil, nil, nil)
    }

    // MARK: - Vector helpers

    private static func pack(_ v: [Float]) -> Data {
        var vv = v
        return vv.withUnsafeMutableBytes { Data($0) }
    }

    private static func unpack(_ data: Data, dim: Int) -> [Float] {
        guard data.count >= dim * MemoryLayout<Float>.size else { return [] }
        return data.withUnsafeBytes { ptr in
            let base = ptr.bindMemory(to: Float.self)
            return Array(base.prefix(dim))
        }
    }

    private static func cosine(_ a: [Float], _ b: [Float]) -> Double {
        let n = min(a.count, b.count)
        if n == 0 { return 0 }
        var dot: Double = 0
        var na: Double = 0
        var nb: Double = 0
        for i in 0..<n {
            let x = Double(a[i])
            let y = Double(b[i])
            dot += x * y
            na += x * x
            nb += y * y
        }
        let denom = (na.squareRoot() * nb.squareRoot())
        return denom > 0 ? (dot / denom) : 0
    }
}
