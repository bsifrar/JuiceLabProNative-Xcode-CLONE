import Foundation
import Combine

@MainActor
final class EngineRunner: ObservableObject {

    @Published var isRunning: Bool = false
    @Published var lastOutputLine: String = ""
    @Published var outputBuffer: String = ""

    private var task: Task<Void, Never>?
    private var cancelled = false // main-actor only
    private var cancelledSnapshot = false // background-safe snapshot

    // MARK: - Public API

    /// Compatibility entry point: call sites can keep building the same `arguments` array
    /// they used for the Python CLI (e.g. ["ping"] or ["scan","--input",...,"--out",...]).
    func startBundledPythonEngine(arguments: [String], workingDirectory: URL? = nil) {
        // Keep the signature and call-site contract unchanged.
        startNativeEngine(arguments: arguments, workingDirectory: workingDirectory)
    }

    func stop() {
        guard isRunning else { return }
        appendOutput(EngineCLIContract.Event.log("Stopping engine…").jsonLine() + "\n")
        cancelled = true
        cancelledSnapshot = true
        task?.cancel()
        task = nil
        isRunning = false
        appendOutput(EngineCLIContract.Event.log("Engine stopped.").jsonLine() + "\n")
    }

    // MARK: - Native Engine

    private func startNativeEngine(arguments: [String], workingDirectory: URL?) {
        if isRunning {
            appendOutput(EngineCLIContract.Event.log("Engine already running (stop it before starting again).").jsonLine() + "\n")
            return
        }

        cancelled = false
        cancelledSnapshot = false
        isRunning = true

        // Identify engine
        appendOutput(EngineCLIContract.Event.hello(engine: "JuiceLabProNativeEngine", version: "1.0").jsonLine() + "\n")

        task = Task { [weak self] in
            guard let self else { return }
            do {
                let cmd = try EngineCLIContract.Command.parse(arguments)
                switch cmd {
                case .ping:
                    await self.handlePing()

                case .scan(let input, let out):
                    await self.handleScan(input: input, out: out, workingDirectory: workingDirectory)
                }
            } catch {
                await self.emit(.error(error.localizedDescription))
            }

            await MainActor.run {
                self.isRunning = false
            }
        }
    }

    private func handlePing() async {
        await emit(.pong(version: "1.0"))
    }

    private func handleScan(input: String, out: String, workingDirectory: URL?) async {
        let inputURL = URL(fileURLWithPath: input)
        let outURL = URL(fileURLWithPath: out)

        // Run name matches your existing style
        let runName = "Run_\(Int(Date().timeIntervalSince1970))"
        await emit(.scanStarted(runName: runName, input: inputURL.path, out: outURL.path))

        // Create settings that match your "scan-and-report contract"
        var settings = ScanSettings(enableAI: true, enableEmbeddings: true)
        settings.outputFolder = outURL.path

        // (Optional) Use workingDirectory to influence relative paths later if you want
        _ = workingDirectory

        // Cancellation helper that is safe to read from background closures
        let localCancelled: () -> Bool = { [weak self] in
            return self?.cancelledSnapshot == true || Task.isCancelled
        }

        let engine = ScannerEngine()

        // Scan roots:
        let roots: [URL] = [inputURL]

        let run = await engine.scan(
            paths: roots,
            settings: settings,
            onProgress: { [weak self] p in
                guard let self else { return }
                if localCancelled() { return }
                Task { @MainActor in
                    let evt = EngineCLIContract.Event.progress(
                        bytesScanned: p.bytesScanned,
                        totalBytes: p.totalBytes,
                        mbPerSecond: p.mbPerSecond,
                        etaSeconds: p.etaSeconds,
                        currentFile: p.currentFile
                    )
                    self.appendOutput(evt.jsonLine() + "\n")
                }
            },
            onItem: { [weak self] item in
                guard let self else { return }
                if localCancelled() { return }
                Task { @MainActor in
                    self.appendOutput(self.jsonForFoundItem(item).jsonLine() + "\n")
                }
            }
        )

        if Task.isCancelled || cancelledSnapshot {
            await emit(.log("Scan cancelled."))
            return
        }

        // Export carved/report outputs
        var exportedCount = run.items.count
        var warnings = run.warnings
        var runNameForOutput = run.name
        do {
            let exportedRun = try await engine.export(run: run)
            exportedCount = exportedRun.items.count
            warnings = exportedRun.warnings
            runNameForOutput = exportedRun.name
        } catch {
            await emit(.log("Export failed: \(error.localizedDescription)"))
        }

        await emit(.scanCompleted(runName: runNameForOutput, outRoot: settings.outputFolder, itemCount: exportedCount, warnings: warnings))
    }

    // MARK: - JSON helpers

    private func jsonForFoundItem(_ item: FoundItem) -> EngineCLIContract.Event {
        // Keep this stable; UI can depend on it.
        var dict: [String: Any] = [
            "source_path": item.sourcePath,
            "offset": item.offset,
            "length": item.length,
            "detected_type": item.detectedType,
            "category": item.category.rawValue,
            "file_ext": item.fileExtension,
            "confidence": item.confidence,
            "validation": item.validationStatus.rawValue
        ]
        if let out = item.outputPath {
            dict["output_path"] = out
        }
        return .item(dict)
    }

    private func emit(_ event: EngineCLIContract.Event) async {
        await MainActor.run {
            self.appendOutput(event.jsonLine() + "\n")
        }
    }

    // MARK: - Output buffer

    private func appendOutput(_ text: String) {
        let normalized = text.replacingOccurrences(of: "\r\n", with: "\n")
        outputBuffer += normalized
        if let last = normalized.split(separator: "\n", omittingEmptySubsequences: true).last {
            lastOutputLine = String(last)
        } else if !normalized.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            lastOutputLine = normalized.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }
}
