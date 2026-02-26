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
        case settings = "Settings"
    }

    @Published var route: Route? = .results
    @Published var settings = ScanSettings()
    @Published var runs: [ScanRun] = []
    @Published var selectedRunID: UUID?
    @Published var selectedItem: FoundItem?
    @Published var query = ""
    @Published var selectedCategories = Set(FileCategory.allCases)
    @Published var progress = ScanProgress()
    @Published var isScanning = false
    @Published var droppedURLs: [URL] = []

    private let engine = ScannerEngine()
    private let history = RunHistoryStore()

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
        return run.items.filter { item in
            selectedCategories.contains(item.category) &&
            (query.isEmpty || item.sourcePath.localizedCaseInsensitiveContains(query) || item.detectedType.localizedCaseInsensitiveContains(query))
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

        Task { @MainActor in
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
                        self.objectWillChange.send()
                    }
                }
            )

            var doneRun = run
            if let exported = try? await engine.export(items: run.items, runName: run.name, settings: settings) {
                doneRun.items = exported
            }

            runs.insert(doneRun, at: 0)
            selectedRunID = doneRun.id
            try? await history.save(run: doneRun)
            isScanning = false
        }
    }

    func stopScan() {
        // Placeholder until ScannerEngine cancellation is wired.
        isScanning = false
    }
}
#endif
