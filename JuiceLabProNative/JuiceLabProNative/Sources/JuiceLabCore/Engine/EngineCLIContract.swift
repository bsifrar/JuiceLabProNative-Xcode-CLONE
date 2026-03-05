import Foundation

enum EngineCLIContract {

    // MARK: - Commands

    enum Command: Equatable {
        case ping
        case scan(input: String, out: String)

        // Parse the old Python-style argv list (e.g. ["scan","--input","/x","--out","/y"])
        static func parse(_ argv: [String]) throws -> Command {
            guard let first = argv.first else {
                throw CLIError.missingCommand
            }

            switch first {
            case "ping":
                return .ping

            case "scan":
                let dict = try parseFlags(Array(argv.dropFirst()))
                guard let input = dict["--input"], !input.isEmpty else { throw CLIError.missingFlag("--input") }
                guard let out = dict["--out"], !out.isEmpty else { throw CLIError.missingFlag("--out") }
                return .scan(input: input, out: out)

            default:
                throw CLIError.unknownCommand(first)
            }
        }
    }

    // MARK: - Errors

    enum CLIError: LocalizedError {
        case missingCommand
        case unknownCommand(String)
        case missingFlag(String)

        var errorDescription: String? {
            switch self {
            case .missingCommand:
                return "No command provided."
            case .unknownCommand(let c):
                return "Unknown command: \(c)"
            case .missingFlag(let f):
                return "Missing required flag: \(f)"
            }
        }
    }

    // MARK: - JSONL Events

    struct Event {
        let payload: [String: Any]

        func jsonLine() -> String {
            // Always one line per JSON object (JSONL)
            guard JSONSerialization.isValidJSONObject(payload),
                  let data = try? JSONSerialization.data(withJSONObject: payload, options: []),
                  let s = String(data: data, encoding: .utf8)
            else {
                return #"{"event":"error","message":"invalid_json_payload"}"#
            }
            return s
        }

        static func hello(engine: String, version: String) -> Event {
            Event(payload: [
                "event": "hello",
                "engine": engine,
                "version": version,
                "ts": isoNow()
            ])
        }

        static func pong(version: String) -> Event {
            Event(payload: [
                "event": "pong",
                "version": version,
                "ts": isoNow()
            ])
        }

        static func scanStarted(runName: String, input: String, out: String) -> Event {
            Event(payload: [
                "event": "scan_started",
                "run": runName,
                "input": input,
                "out": out,
                "ts": isoNow()
            ])
        }

        static func progress(bytesScanned: Int64, totalBytes: Int64, mbPerSecond: Double, etaSeconds: Double, currentFile: String) -> Event {
            Event(payload: [
                "event": "progress",
                "bytes_scanned": bytesScanned,
                "total_bytes": totalBytes,
                "mb_per_sec": mbPerSecond,
                "eta_sec": etaSeconds,
                "current_file": currentFile,
                "ts": isoNow()
            ])
        }

        static func item(_ dict: [String: Any]) -> Event {
            var p = dict
            p["event"] = "item"
            p["ts"] = isoNow()
            return Event(payload: p)
        }

        static func scanCompleted(runName: String, outRoot: String, itemCount: Int, warnings: [String]) -> Event {
            Event(payload: [
                "event": "scan_completed",
                "run": runName,
                "out_root": outRoot,
                "item_count": itemCount,
                "warnings": warnings,
                "ts": isoNow()
            ])
        }

        static func log(_ message: String) -> Event {
            Event(payload: [
                "event": "log",
                "message": message,
                "ts": isoNow()
            ])
        }

        static func error(_ message: String) -> Event {
            Event(payload: [
                "event": "error",
                "message": message,
                "ts": isoNow()
            ])
        }

        private static func isoNow() -> String {
            ISO8601DateFormatter().string(from: Date())
        }
    }

    // MARK: - Helpers

    private static func parseFlags(_ args: [String]) throws -> [String: String] {
        var i = 0
        var result: [String: String] = [:]
        while i < args.count {
            let a = args[i]
            if a.hasPrefix("--") {
                let key = a
                let value = (i + 1 < args.count && !args[i + 1].hasPrefix("--")) ? args[i + 1] : ""
                result[key] = value
                i += (value.isEmpty ? 1 : 2)
            } else {
                // ignore positional/unexpected tokens for forward-compat
                i += 1
            }
        }
        return result
    }
}
