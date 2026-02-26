import Foundation

public actor ScannerEngine {
    public typealias ProgressHandler = @Sendable (ScanProgress) -> Void
    public typealias ItemHandler = @Sendable (FoundItem) -> Void

    private let maxArchiveDepth = 2

    public init() {}

    public func scan(paths: [URL], settings: ScanSettings, onProgress: ProgressHandler? = nil, onItem: ItemHandler? = nil) async -> ScanRun {
        let runName = "Run_\(Int(Date().timeIntervalSince1970))"
        var run = ScanRun(name: runName, sourceRoots: paths.map(\.path), outputRoot: settings.outputFolder, mode: settings.performanceMode)
        let allFiles = collectFiles(from: paths)

        let tempRoot = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(runName, isDirectory: true)
        try? FileManager.default.createDirectory(at: tempRoot, withIntermediateDirectories: true)
        var filesToScan = allFiles
        var seenArchives = Set<String>()
        var extractBudget: Int64 = 200 * 1_048_576 // 200 MB cap for extracted content
        for file in allFiles where ["zip"].contains(file.pathExtension.lowercased()) {
            let extracted = extractIfArchive(file, into: tempRoot, seen: &seenArchives, byteCap: &extractBudget)
            filesToScan.append(contentsOf: extracted)
            if extractBudget <= 0 { break }
        }

        let totalBytes = filesToScan.reduce(into: Int64(0)) { partial, url in
            partial += (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize).map(Int64.init) ?? 0
        }

        let started = Date()
        var progress = ScanProgress(totalBytes: totalBytes)

        await withTaskGroup(of: ([FoundItem], Int64, String, [String]).self) { group in
            for file in filesToScan {
                group.addTask {
                    await Self.scanFile(file, settings: settings)
                }
            }

            for await (items, bytes, currentFile, warnings) in group {
                progress.bytesScanned += bytes
                let elapsed = max(Date().timeIntervalSince(started), 0.1)
                progress.mbPerSecond = (Double(progress.bytesScanned) / 1_048_576.0) / elapsed
                let remaining = max(Double(totalBytes - progress.bytesScanned), 0)
                progress.etaSeconds = remaining / max(progress.mbPerSecond * 1_048_576.0, 1)
                progress.currentFile = currentFile
                onProgress?(progress)

                run.warnings.append(contentsOf: warnings)
                for item in items {
                    run.items.append(item)
                    onItem?(item)
                }
            }
        }

        var summary = ForensicSummary()
        summary.remCount = run.items.filter { $0.fileExtension.lowercased() == "rem" }.count
        summary.mediaCount = run.items.filter { [.images, .video, .audio].contains($0.category) }.count
        summary.nestedArchives = filesToScan.filter { ["zip", "rar", "7z"] .contains($0.pathExtension.lowercased()) }.count
        // Collect key files found among enumerated paths
        let keyPaths = filesToScan.filter { $0.pathExtension.lowercased() == "key" }.map { $0.path }
        summary.keyFiles = keyPaths
        run.forensic = summary

        // Optional analyzer stage: strings + SQLite triage on candidate files
        if settings.enablePythonAnalyzers {
            let runDirName = "\(runName)-\(Self.dateStamp())"
            let runOut = URL(fileURLWithPath: settings.outputFolder).appendingPathComponent(runDirName, isDirectory: true)
            try? FileManager.default.createDirectory(at: runOut, withIntermediateDirectories: true)
            let stringsDir = runOut.appendingPathComponent("strings", isDirectory: true)
            let triageDir = runOut.appendingPathComponent("triage", isDirectory: true)
            try? FileManager.default.createDirectory(at: stringsDir, withIntermediateDirectories: true)
            try? FileManager.default.createDirectory(at: triageDir, withIntermediateDirectories: true)

            var results: [AnalyzerResult] = []
            var analyzerWarnings: [String] = []
            let candidateURLs: [URL] = filesToScan.filter { url in
                let ext = url.pathExtension.lowercased()
                return ext == "rem" || ext == "dat"
            }
            for url in candidateURLs {
                if Task.isCancelled { break }
                let stringsPath = await analyzeStrings(for: url, into: stringsDir, settings: settings)
                if stringsPath == nil { analyzerWarnings.append("Strings failed for \(url.lastPathComponent)") }
                let data = (try? Data(contentsOf: url, options: .mappedIfSafe)) ?? Data()
                let sqliteHeader = analyzeSQLiteHeader(for: data)
                let ar = AnalyzerResult(sourcePath: url.path, stringsPath: stringsPath, carvedMediaCount: 0, sqliteHeaderDetected: sqliteHeader)
                results.append(ar)
            }
            summary.analyzerResults = results
            summary.possibleDecryptableDBs = results.filter { $0.sqliteHeaderDetected }.count
            run.forensic = summary
            run.warnings.append(contentsOf: analyzerWarnings)
        }

        run.items = dedupe(items: run.items, mode: settings.dedupeMode)
        run.completedAt = .now
        return run
    }

    private func runPython(script: String, args: [String], settings: ScanSettings, workingDir: URL) async -> (output: String, error: String, status: Int32) {
        guard settings.enablePythonAnalyzers else { return ("", "", 0) }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: settings.pythonPath)
        process.currentDirectoryURL = workingDir
        let scriptURL = URL(fileURLWithPath: settings.scriptsFolder).appendingPathComponent(script)
        process.arguments = [scriptURL.path] + args
        let outPipe = Pipe(); let errPipe = Pipe()
        process.standardOutput = outPipe; process.standardError = errPipe
        do {
            try process.run()
        } catch {
            return ("", error.localizedDescription, -1)
        }
        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (String(data: outData, encoding: .utf8) ?? "", String(data: errData, encoding: .utf8) ?? "", process.terminationStatus)
    }
    
    private func toolAvailable(_ name: String) -> Bool {
        let which = Process()
        which.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        which.arguments = [name]
        let pipe = Pipe(); which.standardOutput = pipe
        do { try which.run(); let data = pipe.fileHandleForReading.readDataToEndOfFile(); which.waitUntilExit(); return which.terminationStatus == 0 && !data.isEmpty } catch { return false }
    }

    private func extractIfArchive(_ url: URL, into tempDir: URL, depth: Int = 0, seen: inout Set<String>, byteCap: inout Int64) -> [URL] {
        guard depth < maxArchiveDepth else { return [] }
        let ext = url.pathExtension.lowercased()
        guard ["zip"].contains(ext) else { return [] }
        let canonical = (try? url.resolvingSymlinksInPath().path) ?? url.path
        if !seen.insert(canonical).inserted { return [] }

        let dest = tempDir.appendingPathComponent(url.deletingPathExtension().lastPathComponent + "_d\(depth)", isDirectory: true)
        try? FileManager.default.createDirectory(at: dest, withIntermediateDirectories: true)
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        task.arguments = ["-o", url.path, "-d", dest.path]
        do { try task.run(); task.waitUntilExit() } catch { return [] }
        guard task.terminationStatus == 0 else { return [] }
        var results: [URL] = []
        if let enumerator = FileManager.default.enumerator(at: dest, includingPropertiesForKeys: [.fileSizeKey]) {
            for case let child as URL in enumerator {
                if let size = try? child.resourceValues(forKeys: [.fileSizeKey]).fileSize { byteCap -= Int64(size) }
                if byteCap <= 0 { break }
                results.append(child)
            }
        }
        // Recurse one level deeper for newly found archives while under cap
        var more: [URL] = []
        if byteCap > 0 {
            for child in results where ["zip"].contains(child.pathExtension.lowercased()) {
                more.append(contentsOf: extractIfArchive(child, into: tempDir, depth: depth + 1, seen: &seen, byteCap: &byteCap))
                if byteCap <= 0 { break }
            }
        }
        results.append(contentsOf: more)
        return results
    }

    private func analyzeStrings(for url: URL, into outDir: URL, settings: ScanSettings) async -> String? {
        let out = outDir.appendingPathComponent(url.deletingPathExtension().lastPathComponent + "_strings.txt")
        // Prefer Python script if enabled; otherwise attempt /usr/bin/strings
        if settings.enablePythonAnalyzers {
            let res = await runPython(script: "strings.py", args: [url.path, out.path], settings: settings, workingDir: outDir)
            if res.status == 0, FileManager.default.fileExists(atPath: out.path) { return out.path }
        }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/strings")
        task.arguments = ["-a", url.path]
        let pipe = Pipe(); task.standardOutput = pipe
        do { try task.run(); let data = pipe.fileHandleForReading.readDataToEndOfFile(); task.waitUntilExit(); try data.write(to: out) } catch { return nil }
        return out.path
    }

    private func analyzeSQLiteHeader(for data: Data) -> Bool {
        // SQLite header is: "SQLite format 3\0" at start
        if data.count >= 16 {
            let sig = Data("SQLite format 3\0".utf8)
            return data.prefix(sig.count) == sig
        }
        return false
    }

    private static func scanFile(_ file: URL, settings: ScanSettings) async -> ([FoundItem], Int64, String, [String]) {
        var warnings: [String] = []
        #if canImport(AppKit)
        let hasScopedAccess = file.startAccessingSecurityScopedResource()
        defer {
            if hasScopedAccess {
                file.stopAccessingSecurityScopedResource()
            }
        }
        #endif

        do {
            let values = try? file.resourceValues(forKeys: [.isRegularFileKey])
            if values?.isRegularFile == false {
                return ([], 0, file.path, warnings)
            }

            let data = try Data(contentsOf: file, options: .mappedIfSafe)
            if let max = settings.maxFileSizeMB, data.count > max * 1_048_576 {
                warnings.append("Skipped \(file.lastPathComponent): larger than configured threshold")
                return ([], Int64(data.count), file.path, warnings)
            }

            var items: [FoundItem] = []
            var offset = 0
            while offset < data.count {
                for found in SignatureRegistry.detect(in: data, offset: offset) where settings.enabledTypes.contains(found.detectedType) {
                    if settings.performanceMode == .thorough {
                        var best: FoundItem? = nil
                        for candidate in SignatureRegistry.detect(in: data, offset: found.offset) where settings.enabledTypes.contains(candidate.detectedType) {
                            if best == nil || candidate.length > best!.length {
                                best = candidate
                            }
                        }
                        if let best {
                            var length = best.length
                            if settings.performanceMode == .thorough {
                                length = await ScannerEngine().refineLengthIfPossible(data: data, item: best)
                            }
                            let enriched = FoundItem(
                                sourcePath: file.path,
                                offset: best.offset,
                                length: length,
                                detectedType: best.detectedType,
                                category: best.category,
                                fileExtension: best.fileExtension,
                                confidence: best.confidence,
                                validationStatus: best.validationStatus
                            )
                            items.append(enriched)
                        }
                    } else {
                        var enriched = found
                        enriched = FoundItem(
                            sourcePath: file.path,
                            offset: found.offset,
                            length: found.length,
                            detectedType: found.detectedType,
                            category: found.category,
                            fileExtension: found.fileExtension,
                            confidence: found.confidence,
                            validationStatus: found.validationStatus
                        )
                        items.append(enriched)
                    }
                }
                offset += settings.performanceMode.stride
            }
            return (items, Int64(data.count), file.path, warnings)
        } catch {
            warnings.append("Could not scan \(file.path): \(error.localizedDescription)")
            return ([], 0, file.path, warnings)
        }
    }

    public func export(items: [FoundItem], runName: String, settings: ScanSettings) throws -> [FoundItem] {
        let runFolder = URL(fileURLWithPath: settings.outputFolder)
            .appendingPathComponent("\(runName)-\(Self.dateStamp())", isDirectory: true)
        try FileManager.default.createDirectory(at: runFolder, withIntermediateDirectories: true)

        var exported: [FoundItem] = []
        for (idx, item) in items.enumerated() {
            let sourceURL = URL(fileURLWithPath: item.sourcePath)
            let sourceData = try Data(contentsOf: sourceURL, options: .mappedIfSafe)
            guard item.offset + item.length <= sourceData.count else { continue }
            let carved = sourceData[item.offset..<(item.offset + item.length)]

            let categoryFolder: URL
            switch settings.organizationScheme {
            case .bySource:
                categoryFolder = runFolder
                    .appendingPathComponent(sourceURL.deletingPathExtension().lastPathComponent, isDirectory: true)
                    .appendingPathComponent(item.category.rawValue.capitalized, isDirectory: true)
            case .byType:
                categoryFolder = runFolder.appendingPathComponent(item.category.rawValue.capitalized, isDirectory: true)
            case .flat:
                categoryFolder = runFolder
            }
            try FileManager.default.createDirectory(at: categoryFolder, withIntermediateDirectories: true)

            // Sanitize base name for safe filename usage
            func sanitizedFileName(_ name: String) -> String {
                let invalidChars = CharacterSet(charactersIn: "/\\?%*|\"<>:")
                return name.components(separatedBy: invalidChars).joined(separator: "_")
            }

            let safeBase = sanitizedFileName("\(sourceURL.deletingPathExtension().lastPathComponent)_0x\(String(item.offset, radix: 16))_\(item.detectedType)_\(idx)")

            var fileURL = categoryFolder.appendingPathComponent(safeBase).appendingPathExtension(item.fileExtension)
            var counter = 1
            while FileManager.default.fileExists(atPath: fileURL.path) {
                let alt = sanitizedFileName("\(safeBase)_\(counter)")
                fileURL = categoryFolder.appendingPathComponent(alt).appendingPathExtension(item.fileExtension)
                counter += 1
            }
            try Data(carved).write(to: fileURL)

            var mutable = item
            mutable.outputPath = fileURL.path
            exported.append(mutable)
        }

        // Write run summary JSON
        struct RunSummary: Codable {
            let runName: String
            let startedAt: String
            let completedAt: String
            let itemCount: Int
            let warnings: [String]
            let outputRoot: String
            let remCount: Int
            let mediaCount: Int
            let possibleDecryptableDBs: Int
        }
        let df = ISO8601DateFormatter()
        let summary = RunSummary(
            runName: runName,
            startedAt: Self.dateStamp(),
            completedAt: Self.dateStamp(),
            itemCount: exported.count,
            warnings: [],
            outputRoot: runFolder.path,
            remCount: 0,
            mediaCount: 0,
            possibleDecryptableDBs: 0
        )
        let sumURL = runFolder.appendingPathComponent("run-summary.json")
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .withoutEscapingSlashes]
        if let json = try? enc.encode(summary) {
            try? json.write(to: sumURL)
        }

        return exported
    }

    private func dedupe(items: [FoundItem], mode: DedupeMode) -> [FoundItem] {
        guard mode != .off else { return items }
        var seen = Set<String>()
        return items.compactMap { item in
            let key: String
            switch mode {
            case .hash:
                key = digest(item)
            case .hashAndSize:
                key = "\(digest(item))::\(item.length)"
            case .off:
                key = UUID().uuidString
            }
            return seen.insert(key).inserted ? item : nil
        }
    }

    private func digest(_ item: FoundItem) -> String {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: item.sourcePath), options: .mappedIfSafe), item.offset + item.length <= data.count else {
            return UUID().uuidString
        }
        let slice = Data(data[item.offset..<(item.offset + item.length)])
        var hash: UInt64 = 1469598103934665603
        for b in slice {
            hash ^= UInt64(b)
            hash &*= 1099511628211
        }
        return String(hash, radix: 16)
    }

    private func collectFiles(from roots: [URL]) -> [URL] {
        var files: [URL] = []
        for root in roots {
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: root.path, isDirectory: &isDir) else { continue }

            if isDir.boolValue {
                if let enumerator = FileManager.default.enumerator(
                    at: root,
                    includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey],
                    options: [.skipsHiddenFiles]
                ) {
                    for case let url as URL in enumerator {
                        if (try? url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true {
                            files.append(url)
                            continue
                        }

                        var childIsDir: ObjCBool = false
                        if FileManager.default.fileExists(atPath: url.path, isDirectory: &childIsDir), !childIsDir.boolValue {
                            files.append(url)
                        }
                    }
                } else if let subpaths = FileManager.default.subpaths(atPath: root.path) {
                    for subpath in subpaths {
                        let child = URL(fileURLWithPath: root.path).appendingPathComponent(subpath)
                        var childIsDir: ObjCBool = false
                        if FileManager.default.fileExists(atPath: child.path, isDirectory: &childIsDir), !childIsDir.boolValue {
                            files.append(child)
                        }
                    }
                }
            } else {
                files.append(root)
            }
        }
        return files
    }

    private static func dateStamp() -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyyMMdd-HHmmss"
        return f.string(from: .now)
    }

    private func refineLengthIfPossible(data: Data, item: FoundItem) -> Int {
        switch item.detectedType {
        case "mp4", "mov", "m4a", "heic", "heif", "heifs", "heics":
            // Minimal ISO BMFF walk: sum top-level box sizes until invalid; requires big-endian UInt32 at each box
            var pos = item.offset
            let end = data.count
            var total = 0
            while pos + 8 <= end {
                let size = data[pos..<(pos+4)].reduce(0) { ($0 << 8) | Int($1) }
                let typData = data[(pos+4)..<(pos+8)]
                if size < 8 { break }
                total += size
                pos += size
                // Stop if we exceed original slice
                if total > item.length { break }
                // Bail out if too big
                if total > 64_000_000 { break }
                // Optional: if type is 'mdat' and we've seen 'moov', we might stop; omitted for simplicity
                _ = typData
            }
            return max(item.length, total)
        case "mkv", "webm":
            // EBML is variable-length; use a conservative bump when a valid EBML header is present
            return max(item.length, min(item.length + 1_000_000, data.count - item.offset))
        case "flac":
            // Walk FLAC metadata blocks starting after 4-byte marker
            var pos = item.offset + 4
            let end = data.count
            while pos + 4 <= end {
                let header = data[pos]
                let isLast = (header & 0x80) != 0
                let len = Int(data[pos+1]) << 16 | Int(data[pos+2]) << 8 | Int(data[pos+3])
                pos += 4 + len
                if isLast { break }
                if pos - item.offset > 32_000_000 { break }
            }
            return max(item.length, min(pos - item.offset, data.count - item.offset))
        default:
            return item.length
        }
    }
}

