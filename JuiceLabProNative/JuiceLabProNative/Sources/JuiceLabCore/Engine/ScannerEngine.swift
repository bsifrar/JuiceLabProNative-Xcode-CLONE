import Foundation

public actor ScannerEngine {
    public typealias ProgressHandler = @Sendable (ScanProgress) -> Void
    public typealias ItemHandler = @Sendable (FoundItem) -> Void

    public init() {}

    public func scan(paths: [URL], settings: ScanSettings, onProgress: ProgressHandler? = nil, onItem: ItemHandler? = nil) async -> ScanRun {
        let runName = "Run_\(Int(Date().timeIntervalSince1970))"
        var run = ScanRun(name: runName, sourceRoots: paths.map(\.path), outputRoot: settings.outputFolder, mode: settings.performanceMode)
        let allFiles = collectFiles(from: paths)
        let totalBytes = allFiles.reduce(into: Int64(0)) { partial, url in
            partial += (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize).map(Int64.init) ?? 0
        }

        let started = Date()
        var progress = ScanProgress(totalBytes: totalBytes)

        await withTaskGroup(of: ([FoundItem], Int64, String, [String]).self) { group in
            for file in allFiles {
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

        run.items = dedupe(items: run.items, mode: settings.dedupeMode)
        run.completedAt = .now
        return run
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

            let name = "\(sourceURL.deletingPathExtension().lastPathComponent)_0x\(String(item.offset, radix: 16))_\(item.detectedType)_\(idx).\(item.fileExtension)"
            let fileURL = categoryFolder.appendingPathComponent(name)
            try Data(carved).write(to: fileURL)

            var mutable = item
            mutable.outputPath = fileURL.path
            exported.append(mutable)
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
}
