#if canImport(SwiftUI)
import Foundation
import SwiftUI
import Combine
import JuiceLabCore

@MainActor
final class AppViewModel: ObservableObject {
    enum Route: String, CaseIterable {
        case runs = "Runs"
        case results = "Results"
        case forensic = "Forensic"
        case settings = "Settings"
    }

    @Published var route: Route? = .results
    @Published var settings = ScanSettings(enableAI: false)
    @Published var runs: [ScanRun] = []
    @Published var selectedRunID: UUID?
    @Published var selectedItem: FoundItem?
    @Published var query = ""
    @Published var selectedCategories = Set(FileCategory.allCases)
    @Published var progress = ScanProgress()
    @Published var isScanning = false
    @Published var droppedURLs: [URL] = []

    /// UI refresh signal (throttled)
    @Published private(set) var itemTick: Int = 0

    private let engine = ScannerEngine()
    private let history = RunHistoryStore()

    /// ✅ cancellation handle
    private var scanTask: Task<Void, Never>?

    /// ✅ throttle state
    private var lastTickTime: CFAbsoluteTime = 0
    private var pendingTick: Bool = false

    init() {
        Task { runs = await history.load() }
    }

    var activeRun: ScanRun? {
        if let selectedRunID {
            return runs.first(where: { $0.id == selectedRunID })
        }
        return runs.first
    }

    var filteredItems: [FoundItem] {
        guard let run = activeRun else { return [] }
        _ = itemTick // drive reevaluation
        return run.items.filter { item in
            selectedCategories.contains(item.category) &&
            (query.isEmpty ||
             item.sourcePath.localizedCaseInsensitiveContains(query) ||
             item.detectedType.localizedCaseInsensitiveContains(query))
        }
    }

    func addSources(_ urls: [URL]) {
        for url in urls where !droppedURLs.contains(url) {
            droppedURLs.append(url)
        }
    }

    func clearSources() {
        droppedURLs.removeAll()
    }

    func startScan() {
        guard !droppedURLs.isEmpty, !isScanning else { return }
        isScanning = true

        scanTask?.cancel()

        scanTask = Task { @MainActor in
            let scopedRoots = droppedURLs.map { url in
                (url, url.startAccessingSecurityScopedResource())
            }
            defer {
                for (url, isScoped) in scopedRoots where isScoped {
                    url.stopAccessingSecurityScopedResource()
                }
            }

            let run = await engine.scan(
                paths: droppedURLs,
                settings: settings,
                onProgress: { update in
                    Task { @MainActor in
                        self.progress = update
                    }
                },
                onItem: { _ in
                    Task { @MainActor in
                        self.throttledTick()
                    }
                }
            )

            if Task.isCancelled {
                self.isScanning = false
                return
            }

            let doneRun: ScanRun
            do {
                doneRun = try await engine.export(run: run)
            } catch {
                doneRun = run
            }

            if Task.isCancelled {
                self.isScanning = false
                return
            }

            runs.insert(doneRun, at: 0)
            selectedRunID = doneRun.id
            try? await history.save(run: doneRun)
            isScanning = false
        }
    }

    func stopScan() {
        scanTask?.cancel()
        scanTask = nil
        isScanning = false
    }

    /// ✅ throttles UI refresh to ~10Hz to prevent churn on huge scans
    private func throttledTick() {
        let now = CFAbsoluteTimeGetCurrent()
        let minInterval: CFAbsoluteTime = 0.10 // 10 Hz

        if now - lastTickTime >= minInterval {
            lastTickTime = now
            itemTick &+= 1
            pendingTick = false
        } else if !pendingTick {
            pendingTick = true
            let delay = minInterval - (now - lastTickTime)
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: UInt64(max(delay, 0) * 1_000_000_000))
                self.lastTickTime = CFAbsoluteTimeGetCurrent()
                self.itemTick &+= 1
                self.pendingTick = false
            }
        }
    }
}
#endif