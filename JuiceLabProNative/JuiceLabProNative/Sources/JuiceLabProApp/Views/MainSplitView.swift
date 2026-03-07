#if canImport(SwiftUI) && canImport(AppKit)
import SwiftUI
import AppKit
import UniformTypeIdentifiers
import JuiceLabCore
import AVKit
import PDFKit
import WebKit

struct MainSplitView: View {
    @EnvironmentObject private var vm: AppViewModel

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [
                    AppTheme.background,
                    Color.black
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            NavigationSplitView {
                SidebarView()
            } content: {
                Group {
                    if vm.route == .settings {
                        SettingsPanelView()
                    } else if vm.route == .timeline {
                        TimelineView()
                    } else if vm.route == .graph {
                        EvidenceGraphView()
                    } else if vm.route == .cases {
                        CaseBuilderView()
                    } else if vm.route == .forensic {
                        ForensicDashboardView()
                    } else {
                        VStack(spacing: 12) {
                            ToolbarView()
                            DropAndStatsView()
                            ResultsTableView(items: vm.filteredItems)
                        }
                    }
                }
                .padding()
            } detail: {
                ZStack(alignment: .leading) {
                    InspectorView(item: vm.selectedItem)
                        .padding()
                        .navigationSplitViewColumnWidth(min: 300, ideal: 360, max: 540)

                    RoundedRectangle(cornerRadius: 999)
                        .fill(AppTheme.primary.opacity(0.65))
                        .frame(width: 4, height: 86)
                        .overlay(
                            RoundedRectangle(cornerRadius: 999)
                                .stroke(Color.white.opacity(0.35), lineWidth: 0.5)
                        )
                        .shadow(color: AppTheme.primary.opacity(0.35), radius: 6, x: 0, y: 0)
                        .padding(.leading, 2)
                }
            }
        }
        .tint(AppTheme.primary)
        .preferredColorScheme(.dark)
        .searchable(text: $vm.query, placement: .toolbar)
        .sheet(isPresented: $vm.commandPalettePresented) {
            CommandPaletteView(commands: commandPaletteCommands())
                .environmentObject(vm)
                .frame(minWidth: 560, minHeight: 420)
        }
    }

    private func commandPaletteCommands() -> [CommandPaletteItem] {
        [
            CommandPaletteItem(title: "Start Scan", subtitle: "Run scanner on current sources", keywords: ["scan", "start"]) {
                if vm.droppedURLs.isEmpty {
                    pickSourcesForPalette()
                } else {
                    vm.startScan()
                }
            },
            CommandPaletteItem(title: "Stop Scan", subtitle: "Stop active scan", keywords: ["scan", "stop"]) {
                vm.stopScan()
            },
            CommandPaletteItem(title: "Add Sources", subtitle: "Choose files and folders", keywords: ["add", "source", "files"]) {
                pickSourcesForPalette()
            },
            CommandPaletteItem(title: "Clear Sources", subtitle: "Remove all staged sources", keywords: ["clear", "source"]) {
                vm.clearSources()
            },
            CommandPaletteItem(title: "Reveal Run Folder", subtitle: "Open current output in Finder", keywords: ["finder", "output", "folder"]) {
                if let run = vm.activeRun {
                    NSWorkspace.shared.open(URL(fileURLWithPath: run.outputRoot))
                } else {
                    NSWorkspace.shared.open(URL(fileURLWithPath: vm.settings.outputFolder))
                }
            },
            CommandPaletteItem(title: "Open Results", subtitle: "Go to results workspace", keywords: ["results", "workspace"]) {
                vm.route = .results
            },
            CommandPaletteItem(title: "Open Timeline", subtitle: "Go to timeline view", keywords: ["timeline", "events"]) {
                vm.route = .timeline
            },
            CommandPaletteItem(title: "Open Evidence Graph", subtitle: "Go to evidence relationship graph", keywords: ["graph", "relationships"]) {
                vm.route = .graph
            },
            CommandPaletteItem(title: "Open Cases", subtitle: "Go to case builder workspace", keywords: ["case", "workspace"]) {
                vm.route = .cases
            },
            CommandPaletteItem(title: "Open Forensic Summary", subtitle: "Go to forensic dashboard", keywords: ["forensic", "summary"]) {
                vm.route = .forensic
            },
            CommandPaletteItem(title: "Open Settings", subtitle: "Go to settings", keywords: ["settings", "preferences"]) {
                vm.route = .settings
            },
            CommandPaletteItem(title: "Run Agents", subtitle: "Generate forensic agent outputs", keywords: ["agents", "analysis"]) {
                vm.runAgents()
                vm.route = .forensic
            },
            CommandPaletteItem(title: "Run Recommended Actions", subtitle: "Execute agent recommended actions", keywords: ["actions", "recommended"]) {
                vm.runRecommendedActions()
                vm.route = .forensic
            }
        ]
    }

    private func pickSourcesForPalette() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.canCreateDirectories = false
        panel.prompt = "Add"
        if panel.runModal() == .OK {
            vm.addSources(panel.urls)
        }
    }
}

private struct SidebarView: View {
    @EnvironmentObject private var vm: AppViewModel
    @State private var lastScrolledRunKey: String?

    var body: some View {
        VStack(spacing: 10) {
            headerView

            ScrollViewReader { proxy in
                List(selection: $vm.route) {
                    navigationSection
                    runHistorySection
                }
                .onChange(of: vm.selectedRunKey) { _, newKey in
                    guard let newKey else { return }
                    scrollToRun(newKey, using: proxy)
                }
                .onAppear {
                    guard let selected = vm.selectedRunKey ?? vm.runs.first.map(vm.runKey) else { return }
                    scrollToRun(selected, using: proxy)
                }
            }
        }
    }

    private var headerView: some View {
        HStack(spacing: 10) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .interpolation(.high)
                .scaledToFit()
                .frame(width: 28, height: 28)
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(AppTheme.primary.opacity(0.45), lineWidth: 1)
                )
            Text("JuiceLabPro")
                .font(.headline.weight(.semibold))
            Spacer()
        }
        .padding(.horizontal, 8)
        .padding(.top, 4)
    }

    private var navigationSection: some View {
        Section("Navigate") {
            ForEach(AppViewModel.Route.allCases, id: \.self) { route in
                Label(route.rawValue, systemImage: icon(for: route)).tag(route)
            }
        }
    }

    private var runHistorySection: some View {
        Section("Run History") {
            ForEach(vm.runs.indices, id: \.self) { idx in
                let run = vm.runs[idx]
                let runKey = vm.runKey(run)
                let isSelected = isRunSelected(run)
                SidebarRunRow(
                    run: run,
                    isSelected: isSelected,
                    onTap: {
                        vm.selectedRunID = run.id
                        vm.selectedRunKey = runKey
                        vm.clearForensicFacet()
                        vm.query = ""
                        vm.route = .results
                    }
                )
                .id("\(run.id.uuidString)-\(idx)")
                .listRowInsets(EdgeInsets(top: 3, leading: 6, bottom: 3, trailing: 6))
                .listRowBackground(
                    RoundedRectangle(cornerRadius: 10)
                        .fill(isSelected ? AppTheme.primary.opacity(0.22) : Color.clear)
                )
            }
        }
    }

    private func isRunSelected(_ run: ScanRun) -> Bool {
        if let selectedRunID = vm.selectedRunID {
            return run.id == selectedRunID
        }
        guard let first = vm.runs.first else { return false }
        return run.id == first.id
    }

    private func scrollToRun(_ runKey: String, using proxy: ScrollViewProxy) {
        guard lastScrolledRunKey != runKey else { return }
        lastScrolledRunKey = runKey
        guard let idx = vm.runs.firstIndex(where: { vm.runKey($0) == runKey }) else { return }
        let rowID = "\(vm.runs[idx].id.uuidString)-\(idx)"
        DispatchQueue.main.async {
            proxy.scrollTo(rowID, anchor: .center)
        }
    }

    private func icon(for route: AppViewModel.Route) -> String {
        switch route {
        case .runs: return "clock.arrow.circlepath"
        case .results: return "tray.full"
        case .timeline: return "clock"
        case .graph: return "point.3.connected.trianglepath.dotted"
        case .cases: return "folder.badge.person.crop"
        case .forensic: return "shield.lefthalf.filled"
        case .settings: return "gearshape"
        }
    }
}

private struct SidebarRunRow: View {
    let run: ScanRun
    let isSelected: Bool
    let onTap: () -> Void

    var body: some View {
        Button(action: onTap) {
            VStack(alignment: .leading) {
                Text(run.name).bold().lineLimit(1)
                Text("\(run.items.count) items")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.vertical, 4)
            .padding(.horizontal, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(isSelected ? AppTheme.primary.opacity(0.30) : Color.clear)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(isSelected ? AppTheme.primary.opacity(0.80) : Color.clear, lineWidth: 1)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

private struct ToolbarView: View {
    @EnvironmentObject private var vm: AppViewModel
    @State private var showClearResultsDialog = false

    var body: some View {
        VStack(spacing: 10) {
            HStack(spacing: 10) {
                HStack(spacing: 6) {
                    modeButton("Fast", .fast)
                    modeButton("Balanced", .balanced)
                    modeButton("Thorough", .thorough)
                }
                .padding(4)
                .background(
                    RoundedRectangle(cornerRadius: 12)
                        .fill(AppTheme.input.opacity(0.85))
                        .overlay(
                            RoundedRectangle(cornerRadius: 12)
                                .stroke(AppTheme.primary.opacity(0.32), lineWidth: 1)
                        )
                )
                .frame(width: 286)

                Toggle("AI", isOn: $vm.settings.enableAI)
                    .toggleStyle(.switch)
                    .fixedSize()
                    .help("Enable AI classification")

                Toggle(
                    "Dedupe",
                    isOn: Binding(
                        get: { vm.settings.dedupeMode != .off },
                        set: { vm.settings.dedupeMode = $0 ? .exactBytes : .off }
                    )
                )
                .toggleStyle(.switch)
                .fixedSize()
                .help("Remove exact byte-identical duplicates only")

                Button("Add Sources…") { pickSources() }

                Button("Clear Sources") { vm.clearSources() }
                    .disabled(vm.isScanning || vm.droppedURLs.isEmpty)

                Spacer(minLength: 0)
            }

            HStack(spacing: 8) {
                Button {
                    if vm.droppedURLs.isEmpty {
                        pickSources()
                    } else {
                        vm.startScan()
                    }
                } label: {
                    Label("Start Scan", systemImage: "play.fill")
                }
                .buttonStyle(.borderedProminent)
                .disabled(vm.isScanning)

                Button("Stop") { vm.stopScan() }
                    .disabled(!vm.isScanning)

                Button("Reveal Run Folder") {
                    if let run = vm.activeRun {
                        let url = URL(fileURLWithPath: run.outputRoot)
                        NSWorkspace.shared.open(url)
                    } else {
                        let url = URL(fileURLWithPath: vm.settings.outputFolder)
                        NSWorkspace.shared.open(url)
                    }
                }

                Menu {
                    Button("Clear Results", role: .destructive) {
                        showClearResultsDialog = true
                    }
                    .disabled(vm.isScanning || vm.runs.isEmpty)
                } label: {
                    HStack(spacing: 6) {
                        Text("More")
                        Image(systemName: "chevron.down")
                            .font(.caption.weight(.semibold))
                    }
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(AppTheme.text)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(
                        RoundedRectangle(cornerRadius: 10)
                            .fill(AppTheme.input.opacity(0.88))
                            .overlay(
                                RoundedRectangle(cornerRadius: 10)
                                    .stroke(AppTheme.primary.opacity(0.42), lineWidth: 1)
                            )
                    )
                }

                Spacer(minLength: 0)
            }
        }
        .confirmationDialog("Clear all results and run history?", isPresented: $showClearResultsDialog, titleVisibility: .visible) {
            Button("Clear Results", role: .destructive) {
                vm.clearResults(removeFiles: true)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This removes results from the app and deletes exported run folders.")
        }
        .cardSurface()
    }

    private func pickSources() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.canCreateDirectories = false
        panel.prompt = "Add"

        if panel.runModal() == .OK {
            vm.addSources(panel.urls)
        }
    }

    @ViewBuilder
    private func modeButton(_ title: String, _ mode: PerformanceMode) -> some View {
        let selected = vm.settings.performanceMode == mode
        Button(title) {
            vm.settings.performanceMode = mode
        }
        .buttonStyle(.plain)
        .font(.subheadline.weight(.semibold))
        .foregroundStyle(selected ? AppTheme.text : AppTheme.mutedText)
        .padding(.horizontal, 12)
        .padding(.vertical, 7)
        .frame(maxWidth: .infinity)
        .background(
            RoundedRectangle(cornerRadius: 9)
                .fill(selected ? AppTheme.primary.opacity(0.32) : Color.clear)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 9)
                .stroke(selected ? AppTheme.primary.opacity(0.68) : Color.clear, lineWidth: 1)
        )
    }
}

private struct DropAndStatsView: View {
    @EnvironmentObject private var vm: AppViewModel

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 8) {
                Text("Drop files or folders to carve embedded content")
                    .font(.headline)
                Text("Sources: \(vm.droppedURLs.count)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button {
                    if vm.droppedURLs.isEmpty {
                        pickSources()
                    } else {
                        vm.startScan()
                    }
                } label: {
                    Label("Start Scan", systemImage: "play.fill")
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .buttonStyle(.borderedProminent)
                .disabled(vm.isScanning)
                if vm.droppedURLs.isEmpty {
                    Text("No sources selected.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(vm.droppedURLs, id: \.self) { url in
                                HStack(spacing: 8) {
                                    Text(url.lastPathComponent)
                                        .font(.caption)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                    Spacer(minLength: 4)
                                    Button {
                                        vm.removeSource(url)
                                    } label: {
                                        Image(systemName: "xmark.circle.fill")
                                            .foregroundStyle(.secondary)
                                    }
                                    .buttonStyle(.plain)
                                    .help("Remove source")
                                    .disabled(vm.isScanning)
                                }
                            }
                        }
                    }
                    .frame(maxHeight: 90)
                }
                Text("Output: \(vm.settings.outputFolder)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, minHeight: 120, alignment: .leading)
            .cardSurface()
            .onDrop(of: [.fileURL], isTargeted: nil) { providers in
                providers.forEach { provider in
                    _ = provider.loadObject(ofClass: URL.self) { url, _ in
                        guard let url else { return }
                        DispatchQueue.main.async { vm.addSources([url]) }
                    }
                }
                return true
            }

            VStack(alignment: .leading, spacing: 6) {
                let rawProgress = vm.progress.totalBytes == 0 ? 0 : (Double(vm.progress.bytesScanned) / Double(vm.progress.totalBytes))
                let clampedProgress = min(1, max(0, rawProgress))
                let displayProgress = vm.isScanning ? min(clampedProgress, 0.995) : clampedProgress
                ScanRadarView(progress: displayProgress, isScanning: vm.isScanning)
                    .frame(maxWidth: .infinity, minHeight: 170, maxHeight: 170, alignment: .center)
                Text("Scanned: \(ByteCountFormatter.string(fromByteCount: vm.progress.bytesScanned, countStyle: .file))")
                Text(String(format: "%.1f MB/s", vm.progress.mbPerSecond))
                Text("ETA: \(Int(vm.progress.etaSeconds))s")
                if !vm.stageMessage.isEmpty {
                    Text(vm.stageMessage)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
                ProgressView(value: displayProgress, total: 1.0)
                if !vm.statusMessage.isEmpty {
                    Text(vm.statusMessage)
                        .font(.caption)
                        .foregroundStyle(vm.statusMessage.localizedCaseInsensitiveContains("warning") ||
                                         vm.statusMessage.localizedCaseInsensitiveContains("unreadable") ? .orange : .secondary)
                        .lineLimit(3)
                }
                if let run = vm.activeRun, !run.warnings.isEmpty {
                    DisclosureGroup("Warnings (\(run.warnings.count))") {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(Array(run.warnings.prefix(10).enumerated()), id: \.offset) { _, warning in
                                Text("• \(warning)")
                                    .font(.caption2)
                                    .foregroundStyle(.orange)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            if run.warnings.count > 10 {
                                Text("…and \(run.warnings.count - 10) more")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                        .padding(.top, 2)
                    }
                    .font(.caption)
                    .tint(.orange)
                }
            }
            .frame(width: 260)
            .cardSurface()
        }
    }

    private func pickSources() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.canCreateDirectories = false
        panel.prompt = "Add"

        if panel.runModal() == .OK {
            vm.addSources(panel.urls)
        }
    }
}

private struct ResultsTableView: View {
    @EnvironmentObject private var vm: AppViewModel
    let items: [FoundItem]
    @State private var sortedItems: [FoundItem] = []
    @State private var selectedItemID: UUID?
    @State private var selectionCommitTask: Task<Void, Never>?
    @State private var sortOrder: [KeyPathComparator<FoundItem>] = [
        .init(\.detectedType, order: .forward)
    ]
    @State private var quickFilter: MediaQuickFilter = .all
    @State private var validationFilter: ValidationFacet = .all
    @State private var minConfidence: Double = 0
    @State private var sourceFolderFilter: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if hasActiveSearchFilters {
                HStack(spacing: 8) {
                    if let facetLabel = vm.activeForensicFacetLabel {
                        Label("Forensic: \(facetLabel)", systemImage: "line.3.horizontal.decrease.circle")
                            .font(.caption.weight(.semibold))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(Capsule().fill(AppTheme.primary.opacity(0.24)))
                    }
                    if !vm.query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        Label("Search: \"\(vm.query)\"", systemImage: "magnifyingglass")
                            .font(.caption.weight(.semibold))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(Capsule().fill(Color.gray.opacity(0.20)))
                    }
                    if let graphPivot = vm.activeGraphPivotLabel {
                        Label("Graph: \(graphPivot)", systemImage: "point.3.connected.trianglepath.dotted")
                            .font(.caption.weight(.semibold))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(Capsule().fill(Color.orange.opacity(0.20)))
                    }
                    Button("Clear Forensic Filter") {
                        vm.clearForensicFacet()
                    }
                    .buttonStyle(.bordered)
                    .disabled(vm.activeForensicFacet == nil)

                    Button("Clear Search") {
                        vm.clearSearch()
                    }
                    .buttonStyle(.bordered)
                    .disabled(vm.query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                    Button("Clear Pivot") {
                        vm.clearGraphPivot()
                    }
                    .buttonStyle(.bordered)
                    .disabled(vm.activeGraphPivotLabel == nil)

                    Button("Clear All") {
                        vm.clearAllFilters()
                    }
                    .buttonStyle(.borderedProminent)
                    Spacer(minLength: 0)
                }
            }
            ScrollView(.horizontal, showsIndicators: false) {
                HStack {
                    ForEach(FileCategory.allCases, id: \.self) { category in
                        let selected = vm.selectedCategories.contains(category)
                        Text(category.rawValue.capitalized)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(Capsule().fill(selected ? Color.accentColor.opacity(0.22) : Color.gray.opacity(0.15)))
                            .onTapGesture {
                                if selected { vm.selectedCategories.remove(category) } else { vm.selectedCategories.insert(category) }
                            }
                    }
                }
            }
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(MediaQuickFilter.allCases, id: \.self) { filter in
                        let active = quickFilter == filter
                        Text(filter.rawValue)
                            .font(.caption.weight(.semibold))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(
                                Capsule()
                                    .fill(active ? AppTheme.primary.opacity(0.28) : Color.gray.opacity(0.14))
                            )
                            .overlay(
                                Capsule()
                                    .stroke(active ? AppTheme.primary.opacity(0.8) : Color.clear, lineWidth: 1)
                            )
                            .onTapGesture { quickFilter = filter }
                    }
                }
            }
            HStack(spacing: 12) {
                Picker("Validation", selection: $validationFilter) {
                    ForEach(ValidationFacet.allCases, id: \.self) { facet in
                        Text(facet.rawValue).tag(facet)
                    }
                }
                .pickerStyle(.menu)
                .frame(width: 150)

                HStack(spacing: 6) {
                    Text("Min confidence")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Slider(value: $minConfidence, in: 0...1, step: 0.05)
                    Text("\(Int(minConfidence * 100))%")
                        .font(.caption.monospacedDigit())
                        .frame(width: 44, alignment: .trailing)
                }
                .frame(maxWidth: 280)

                TextField("Filter source folder…", text: $sourceFolderFilter)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 260)
            }
            resultsTable
        }
        .cardSurface()
    }

    private var hasActiveSearchFilters: Bool {
        vm.activeForensicFacet != nil
            || !vm.query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            || vm.activeGraphPivotLabel != nil
    }

    private var resultsTable: some View {
        Table(filteredSortedItems, selection: $selectedItemID, sortOrder: $sortOrder) {
            TableColumn("Type", value: \.detectedType) { item in
                Text(item.detectedType.uppercased())
            }
            TableColumn("Source", value: \.sourceDisplayName) { item in
                Text(item.sourceDisplayName)
            }
            TableColumn("Source Folder", value: \.sourceFolderPath) { item in
                Text(item.sourceFolderPath)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            TableColumn("Offset", value: \.offset) { item in
                Text(String(format: "0x%X", item.offset))
            }
            TableColumn("Validation", value: \.validationText) { item in
                Text(item.validationText.capitalized)
            }
            TableColumn("Size", value: \.length) { item in
                Text(ByteCountFormatter.string(fromByteCount: Int64(item.length), countStyle: .file))
            }
        }
        .onAppear {
            applySort()
            selectedItemID = vm.selectedItem?.id
            scheduleSelectionCommit(immediate: true)
        }
        .onChange(of: items) { _, _ in
            applySort()
            validateSelection()
        }
        .onChange(of: sortOrder) { _, _ in
            applySort()
            validateSelection()
        }
        .onChange(of: selectedItemID) { _, _ in
            scheduleSelectionCommit()
        }
    }

    private var filteredSortedItems: [FoundItem] {
        let severityByPath: [String: NSFWSeverity] = Dictionary(
            uniqueKeysWithValues: (vm.activeRun?.forensic.analyzerResults ?? []).map { ($0.sourcePath, $0.nsfwSeverity) }
        )
        let sourceNeedle = sourceFolderFilter.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        return sortedItems.filter { item in
            if validationFilter != .all && item.validationStatus.rawValue != validationFilter.rawValue.lowercased() {
                return false
            }
            if item.confidence < minConfidence {
                return false
            }
            if !sourceNeedle.isEmpty && !item.sourceFolderPath.lowercased().contains(sourceNeedle) {
                return false
            }
            switch quickFilter {
            case .all:
                return true
            case .images:
                return item.category == .images
            case .video:
                return item.category == .video
            case .gif:
                return item.fileExtension.lowercased() == "gif" || item.detectedType.lowercased() == "gif"
            case .explicit:
                return severityByPath[item.sourcePath] == .explicit
            case .suggestive:
                return severityByPath[item.sourcePath] == .suggestive
            }
        }
    }

    private func applySort() {
        var copy = items
        copy.sort(using: sortOrder)
        sortedItems = copy
    }

    private func validateSelection() {
        guard let selectedItemID else {
            scheduleSelectionCommit(immediate: true)
            return
        }
        guard filteredSortedItems.contains(where: { $0.id == selectedItemID }) else {
            self.selectedItemID = nil
            scheduleSelectionCommit(immediate: true)
            return
        }
        scheduleSelectionCommit()
    }

    private func scheduleSelectionCommit(immediate: Bool = false) {
        selectionCommitTask?.cancel()
        let selected = selectedItemID
        selectionCommitTask = Task { @MainActor in
            if !immediate {
                try? await Task.sleep(nanoseconds: 120_000_000)
                guard !Task.isCancelled else { return }
            }
            guard let selected else {
                if vm.selectedItem != nil { vm.selectedItem = nil }
                return
            }
            if let current = filteredSortedItems.first(where: { $0.id == selected }) {
                if vm.selectedItem?.id != current.id {
                    vm.selectedItem = current
                }
            } else if vm.selectedItem != nil {
                vm.selectedItem = nil
            }
        }
    }
}

private enum MediaQuickFilter: String, CaseIterable {
    case all = "All"
    case images = "Images"
    case video = "Video"
    case gif = "GIF"
    case suggestive = "Suggestive"
    case explicit = "Explicit"
}

private enum ValidationFacet: String, CaseIterable {
    case all = "All"
    case valid = "Valid"
    case partial = "Partial"
    case uncertain = "Uncertain"
}

private extension FoundItem {
    var sourceDisplayName: String { URL(fileURLWithPath: sourcePath).lastPathComponent }
    var sourceFolderPath: String { URL(fileURLWithPath: sourcePath).deletingLastPathComponent().path }
    var validationText: String { validationStatus.rawValue }
}

private struct InspectorView: View {
    @EnvironmentObject private var vm: AppViewModel
    let item: FoundItem?
    @State private var showFullscreenPreview = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Inspector").font(.title3.bold())
            if let item {
                GroupBox("Metadata") {
                    VStack(alignment: .leading) {
                        Text("Type: \(item.detectedType)")
                        Text("Confidence: \(Int(item.confidence * 100))%")
                        Text("Offset: 0x\(String(item.offset, radix: 16))")
                        Text("Status: \(item.validationStatus.rawValue)")
                        Text("Source file: \(URL(fileURLWithPath: item.sourcePath).lastPathComponent)")
                        Text("Source folder: \(URL(fileURLWithPath: item.sourcePath).deletingLastPathComponent().path)")
                            .lineLimit(2)
                            .truncationMode(.middle)
                        Text("Source path: \(item.sourcePath)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                            .truncationMode(.middle)
                        if let ar = analyzerResult(for: item) {
                            Divider().padding(.vertical, 2)
                            Text("AI Severity: \(ar.nsfwSeverity.rawValue.capitalized)")
                            Text(String(format: "AI Score: %.2f", ar.nsfwScore))
                            if let reasonSummary = flagReasonSummary(for: ar) {
                                Text("Flag reasons: \(reasonSummary)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(3)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                GroupBox("Preview") {
                    PreviewView(
                        item: item,
                        runOutputRoot: vm.activeRun?.outputRoot,
                        showExpandedPreview: $showFullscreenPreview
                    )
                        .frame(maxWidth: .infinity, minHeight: 180, maxHeight: 320)
                        .background(Color.gray.opacity(0.08))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                }
                GroupBox("Actions") {
                    HStack {
                        Button("Reveal in Finder") {
                            revealInFinder(path: item.outputPath ?? item.sourcePath)
                        }
                        Button("Copy Path") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(item.outputPath ?? item.sourcePath, forType: .string)
                        }
                        Button("Open") {
                            let path = item.outputPath ?? item.sourcePath
                            if FileManager.default.fileExists(atPath: path) {
                                NSWorkspace.shared.open(URL(fileURLWithPath: path))
                            }
                        }
                        Button("Open Fullscreen Preview") {
                            showFullscreenPreview = true
                        }
                    }
                }
            } else {
                Text("Select a recovered item to preview metadata and quick actions.")
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .cardSurface()
    }

    private func analyzerResult(for item: FoundItem) -> AnalyzerResult? {
        vm.analyzerResult(for: item)
    }

    private func flagReasonSummary(for result: AnalyzerResult) -> String? {
        if let detections = result.reasonDetections, !detections.isEmpty {
            let top = detections
                .sorted { $0.confidence > $1.confidence }
                .prefix(3)
                .map { "\($0.modelLabel) (\(Int($0.confidence * 100))%)" }
                .joined(separator: ", ")
            return top.isEmpty ? nil : top
        }
        if result.scaIsSensitive == true {
            return "SensitiveContentAnalysis marked this media as sensitive."
        }
        return nil
    }
}

private struct PreviewView: View {
    let item: FoundItem
    let runOutputRoot: String?
    @Binding var showExpandedPreview: Bool

    @State private var nsImage: NSImage?
    @State private var previewText: String = ""
    @State private var htmlRawText: String = ""
    @State private var htmlRenderedText: String = ""
    @State private var pdfDocument: PDFDocument?
    @State private var avPlayer: AVPlayer?
    @State private var htmlPreview: HTMLPreviewContent?
    @State private var previewLoadID: UUID = UUID()

    var body: some View {
        Group {
            if htmlPreview != nil {
                VStack(spacing: 8) {
                    if !htmlRenderedText.isEmpty {
                        ScrollView {
                            Text(htmlRenderedText)
                                .font(.system(size: 12))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(6)
                        }
                        .frame(minHeight: 180, maxHeight: 260)
                    }
                    if !htmlRawText.isEmpty {
                        Divider()
                        ScrollView {
                            Text(htmlRawText)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(6)
                        }
                        .frame(minHeight: 110, maxHeight: 200)
                    }
                }
            } else if let doc = pdfDocument {
                PDFKitView(document: doc)
            } else if let player = avPlayer {
                AVPlayerViewWrapper(player: player)
            } else if let img = nsImage {
                Image(nsImage: img)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if !previewText.isEmpty {
                ScrollView { Text(previewText).font(.system(.caption, design: .monospaced)).textSelection(.enabled).padding(6) }
            } else {
                ProgressView().controlSize(.small)
            }
        }
        .contextMenu {
            Button("Expand Preview") { showExpandedPreview = true }
            Button("Reveal in Finder") {
                let path = item.outputPath ?? item.sourcePath
                revealInFinder(path: path)
            }
        }
        .onTapGesture(count: 2) {
            showExpandedPreview = true
        }
        .sheet(isPresented: $showExpandedPreview) {
            VStack(spacing: 10) {
                HStack {
                    Text(URL(fileURLWithPath: item.sourcePath).lastPathComponent)
                        .font(.headline)
                        .lineLimit(1)
                    Spacer()
                    Button("Reveal in Finder") {
                        revealInFinder(path: item.outputPath ?? item.sourcePath)
                    }
                    Button("Close") { showExpandedPreview = false }
                }
                .padding(.horizontal, 12)
                .padding(.top, 10)

                previewPane
                    .padding(8)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(Color.black.opacity(0.2))
            }
            .frame(minWidth: 980, minHeight: 680)
        }
        .task(id: item.id) {
            let loadID = UUID()
            await MainActor.run { previewLoadID = loadID }
            // Debounce rapid keyboard selection changes to avoid preview churn/crashes.
            try? await Task.sleep(nanoseconds: 140_000_000)
            guard !Task.isCancelled else { return }
            await loadPreview(loadID: loadID)
        }
    }

    @ViewBuilder
    private var previewPane: some View {
        if htmlPreview != nil {
            VStack(spacing: 8) {
                if !htmlRenderedText.isEmpty {
                    ScrollView {
                        Text(htmlRenderedText)
                            .font(.system(size: 12))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(6)
                    }
                    .frame(minHeight: 180, maxHeight: 260)
                }
                if !htmlRawText.isEmpty {
                    Divider()
                    ScrollView {
                        Text(htmlRawText)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(6)
                    }
                    .frame(minHeight: 110, maxHeight: 200)
                }
            }
        } else if let doc = pdfDocument {
            PDFKitView(document: doc)
        } else if let player = avPlayer {
            AVPlayerViewWrapper(player: player)
        } else if let img = nsImage {
            Image(nsImage: img)
                .resizable()
                .scaledToFit()
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if !previewText.isEmpty {
            ScrollView {
                Text(previewText)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(6)
            }
        } else {
            ProgressView().controlSize(.small)
        }
    }

    private func loadPreview(loadID: UUID) async {
        guard !Task.isCancelled else { return }
        await applyIfCurrent(loadID) {
            self.nsImage = nil
            self.previewText = ""
            self.htmlRawText = ""
            self.htmlRenderedText = ""
            self.pdfDocument = nil
            self.avPlayer = nil
            self.htmlPreview = nil
        }

        let candidates = previewCandidatePaths()
        var loaded: (URL, Data)?
        var lastError: Error?

        for candidate in candidates {
            if Task.isCancelled { return }
            let url = URL(fileURLWithPath: candidate)
            guard FileManager.default.fileExists(atPath: candidate) else { continue }

            #if canImport(AppKit)
            let scoped = url.startAccessingSecurityScopedResource()
            #endif

            do {
                let data = try Data(contentsOf: url, options: .mappedIfSafe)
                #if canImport(AppKit)
                if scoped { url.stopAccessingSecurityScopedResource() }
                #endif
                if Task.isCancelled { return }
                loaded = (url, data)
                break
            } catch {
                #if canImport(AppKit)
                if scoped { url.stopAccessingSecurityScopedResource() }
                #endif
                lastError = error
            }
        }

        guard let (url, data) = loaded else {
            if let lastError {
                let message = "Preview failed: \(lastError.localizedDescription). Use Reveal in Finder to open exported artifacts."
                await applyIfCurrent(loadID) { self.previewText = message }
            } else {
                await applyIfCurrent(loadID) { self.previewText = "File not found in source or exported output." }
            }
            return
        }

        // Priority: PDF, AV (video/audio), Image, Text, Hex
        let ext = url.pathExtension.lowercased()
        if ext == "pdf", let doc = PDFDocument(data: data) {
            await applyIfCurrent(loadID) { self.pdfDocument = doc }
            return
        }

        let htmlExts: Set<String> = ["html", "htm"]
        let declaredExt = item.fileExtension.lowercased()
        let declaredType = item.detectedType.lowercased()
        let htmlCandidate = data.prefix(256_000)
        if (htmlExts.contains(ext) || htmlExts.contains(declaredExt) || declaredType == "html" || looksLikeHTML(data: htmlCandidate)),
           let decoded = decodeText(data: htmlCandidate) {
           let rendered = wrapHTMLForPreview(decoded)
            await applyIfCurrent(loadID) {
                self.htmlPreview = .inline(html: rendered, baseURL: url.deletingLastPathComponent())
                self.htmlRawText = decoded
                self.htmlRenderedText = extractReadableHTMLText(from: decoded) ?? ""
            }
            return
        }

        let videoExts: Set<String> = ["mp4", "mov", "mkv", "avi", "webm", "mpeg", "m2ts", "3gp", "3gpp", "gp"]
        let audioExts: Set<String> = ["mp3", "wav", "flac", "ogg", "m4a", "aac", "alac"]
        if videoExts.contains(ext) || audioExts.contains(ext) || item.category == .video || item.category == .audio {
            let player = AVPlayer(url: url)
            await applyIfCurrent(loadID) { self.avPlayer = player }
            return
        }

        if item.category == .images || looksLikeImageData(data), let img = NSImage(data: data) {
            let size = img.size
            let invalidSize = !size.width.isFinite || !size.height.isFinite || size.width <= 0 || size.height <= 0
            let absurdSize = size.width > 20_000 || size.height > 20_000
            if invalidSize || absurdSize {
                await applyIfCurrent(loadID) {
                    self.previewText = "Image decode returned invalid dimensions; preview skipped for safety."
                }
                return
            }
            await applyIfCurrent(loadID) { self.nsImage = img }
            return
        }

        let textExts: Set<String> = ["txt", "csv", "json", "xml", "md", "log", "vcf"]
        if textExts.contains(ext) {
            if let s = decodeText(data: data.prefix(64_000)) {
                await applyIfCurrent(loadID) { self.previewText = s }
                return
            }
        }

        let plistExts: Set<String> = ["plist", "bplist"]
        if plistExts.contains(ext),
           let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
           let pretty = prettyPrintPropertyList(obj) {
            await applyIfCurrent(loadID) { self.previewText = pretty }
            return
        }

        if let strings = extractPrintableStrings(from: data.prefix(64_000), minRunLength: 4),
           !strings.isEmpty {
            let header = "Extracted strings preview:\n\n"
            await applyIfCurrent(loadID) { self.previewText = header + strings }
            return
        }

        // Fallback: hex dump of the first up to 4KB
        let sample = data.prefix(4096)
        var lines: [String] = []
        var offset = 0
        let bytes = Array(sample)
        while offset < bytes.count {
            let chunk = bytes[offset..<min(offset+16, bytes.count)]
            let hex = chunk.map { String(format: "%02X", $0) }.joined(separator: " ")
            lines.append(String(format: "%08X  %@", offset, hex))
            offset += 16
        }
        await applyIfCurrent(loadID) { self.previewText = lines.joined(separator: "\n") }
    }

    private func applyIfCurrent(_ loadID: UUID, _ update: @escaping @MainActor () -> Void) async {
        await MainActor.run {
            guard self.previewLoadID == loadID else { return }
            update()
        }
    }

    private func extractPrintableStrings(from data: Data.SubSequence, minRunLength: Int) -> String? {
        var lines: [String] = []
        var run: [UInt8] = []

        for b in data {
            let isPrintable = (32...126).contains(Int(b)) || b == 9 || b == 10 || b == 13
            if isPrintable {
                run.append(b)
            } else {
                if run.count >= minRunLength, let s = String(bytes: run, encoding: .utf8) {
                    lines.append(s)
                }
                run.removeAll(keepingCapacity: true)
            }
            if lines.count >= 220 { break }
        }
        if run.count >= minRunLength, let s = String(bytes: run, encoding: .utf8) {
            lines.append(s)
        }
        guard !lines.isEmpty else { return nil }
        return lines.joined(separator: "\n")
    }

    private func prettyPrintPropertyList(_ object: Any) -> String? {
        guard JSONSerialization.isValidJSONObject(object),
              let data = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]),
              let text = String(data: data, encoding: .utf8) else {
            return String(describing: object)
        }
        return text
    }

    private func decodeText(data: Data.SubSequence) -> String? {
        let bytes = Data(data)
        if bytes.count >= 2 {
            let b0 = bytes[bytes.startIndex]
            let b1 = bytes[bytes.startIndex.advanced(by: 1)]
            if b0 == 0xFF && b1 == 0xFE {
                return String(data: bytes, encoding: .utf16LittleEndian)
            }
            if b0 == 0xFE && b1 == 0xFF {
                return String(data: bytes, encoding: .utf16BigEndian)
            }
        }
        if bytes.count >= 32 {
            let sample = bytes.prefix(512)
            let evenZeros = stride(from: 0, to: sample.count, by: 2).reduce(0) { acc, idx in
                acc + (sample[sample.startIndex.advanced(by: idx)] == 0 ? 1 : 0)
            }
            let oddZeros = stride(from: 1, to: sample.count, by: 2).reduce(0) { acc, idx in
                acc + (sample[sample.startIndex.advanced(by: idx)] == 0 ? 1 : 0)
            }
            let evenPairs = max(1, sample.count / 2)
            if oddZeros * 3 > evenPairs {
                if let s = String(data: bytes, encoding: .utf16LittleEndian) { return s }
            } else if evenZeros * 3 > evenPairs {
                if let s = String(data: bytes, encoding: .utf16BigEndian) { return s }
            }
        }
        return String(data: bytes, encoding: .utf8)
            ?? String(data: bytes, encoding: .utf16LittleEndian)
            ?? String(data: bytes, encoding: .utf16BigEndian)
            ?? String(data: bytes, encoding: .ascii)
    }

    private func looksLikeHTML(data: Data.SubSequence) -> Bool {
        guard let text = decodeText(data: data.prefix(4096))?.lowercased() else { return false }
        return text.contains("<!doctype html")
            || text.contains("<html")
            || text.contains("<head")
            || text.contains("<body")
    }

    private func wrapHTMLForPreview(_ html: String) -> String {
        let lower = html.lowercased()
        if lower.contains("<html") {
            return html
        }
        return """
        <!doctype html>
        <html>
        <head>
        <meta charset="utf-8">
        <style>
        :root { color-scheme: light; }
        body { background: #ffffff; color: #111111; font: 13px -apple-system, BlinkMacSystemFont, sans-serif; margin: 12px; white-space: pre-wrap; }
        </style>
        </head>
        <body>\(escapeForHTML(html))</body>
        </html>
        """
    }

    private func escapeForHTML(_ text: String) -> String {
        text
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
    }

    private func extractReadableHTMLText(from html: String) -> String? {
        guard let data = html.data(using: .utf8),
              let attributed = try? NSAttributedString(
                data: data,
                options: [
                    .documentType: NSAttributedString.DocumentType.html,
                    .characterEncoding: String.Encoding.utf8.rawValue
                ],
                documentAttributes: nil
              ) else {
            return nil
        }
        let cleaned = attributed.string
            .replacingOccurrences(of: "\r\n", with: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.isEmpty ? nil : cleaned
    }

    private func looksLikeImageData(_ data: Data) -> Bool {
        guard data.count >= 12 else { return false }
        if data[0] == 0x89, data[1] == 0x50, data[2] == 0x4E, data[3] == 0x47 { return true } // PNG
        if data[0] == 0xFF, data[1] == 0xD8 { return true } // JPEG
        if data[0] == 0x47, data[1] == 0x49, data[2] == 0x46 { return true } // GIF
        if data[0] == 0x42, data[1] == 0x4D { return true } // BMP
        if data[0] == 0x52, data[1] == 0x49, data[2] == 0x46, data[3] == 0x46,
           data[8] == 0x57, data[9] == 0x45, data[10] == 0x42, data[11] == 0x50 { return true } // WEBP
        return false
    }

    private func looksLikeVideoData(_ data: Data) -> Bool {
        guard data.count >= 12 else { return false }
        // MP4/MOV/3GP family via ftyp box
        if data[4] == 0x66, data[5] == 0x74, data[6] == 0x79, data[7] == 0x70 { return true }
        // Matroska/WebM
        if data[0] == 0x1A, data[1] == 0x45, data[2] == 0xDF, data[3] == 0xA3 { return true }
        // AVI (RIFF....AVI )
        if data[0] == 0x52, data[1] == 0x49, data[2] == 0x46, data[3] == 0x46,
           data[8] == 0x41, data[9] == 0x56, data[10] == 0x49 { return true }
        return false
    }

    private func previewCandidatePaths() -> [String] {
        var candidates: [String] = []
        if let output = item.outputPath { candidates.append(output) }
        candidates.append(item.sourcePath)

        if let runOutputRoot,
           let fallback = findByBasename(root: runOutputRoot, name: URL(fileURLWithPath: item.sourcePath).lastPathComponent) {
            candidates.append(fallback)
        }
        var seen = Set<String>()
        var deduped: [String] = []
        for path in candidates where !seen.contains(path) {
            seen.insert(path)
            deduped.append(path)
        }
        return deduped
    }

    private func findByBasename(root: String, name: String) -> String? {
        let rootURL = URL(fileURLWithPath: root, isDirectory: true)
        guard let enumerator = FileManager.default.enumerator(
            at: rootURL,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else { return nil }

        var scanned = 0
        while let next = enumerator.nextObject() as? URL {
            scanned += 1
            if scanned > 5000 { return nil }
            if next.lastPathComponent == name,
               (try? next.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true {
                return next.path
            }
        }
        return nil
    }
}

private struct PDFKitView: NSViewRepresentable {
    let document: PDFDocument
    func makeNSView(context: Context) -> PDFView {
        let v = PDFView()
        v.autoScales = true
        v.displayMode = .singlePageContinuous
        v.document = document
        return v
    }
    func updateNSView(_ nsView: PDFView, context: Context) {
        nsView.document = document
    }
}

private struct AVPlayerViewWrapper: NSViewRepresentable {
    let player: AVPlayer
    func makeNSView(context: Context) -> AVPlayerView {
        let v = AVPlayerView()
        v.controlsStyle = .minimal
        v.player = player
        return v
    }
    func updateNSView(_ nsView: AVPlayerView, context: Context) {
        nsView.player = player
    }
}

private enum HTMLPreviewContent {
    case file(URL)
    case inline(html: String, baseURL: URL?)
}

private struct HTMLPreviewView: NSViewRepresentable {
    let content: HTMLPreviewContent

    func makeNSView(context: Context) -> WKWebView {
        let webView = WKWebView(frame: .zero)
        webView.setValue(true, forKey: "drawsBackground")
        load(content, into: webView)
        return webView
    }

    func updateNSView(_ nsView: WKWebView, context: Context) {
        load(content, into: nsView)
    }

    private func load(_ content: HTMLPreviewContent, into webView: WKWebView) {
        switch content {
        case .file(let url):
            webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        case .inline(let html, let baseURL):
            webView.loadHTMLString(html, baseURL: baseURL)
        }
    }
}

private struct SettingsPanelView: View {
    @EnvironmentObject private var vm: AppViewModel

    var body: some View {
        Form {
            HStack {
                TextField("Output Folder", text: $vm.settings.outputFolder)
                Button("Choose…") {
                    chooseOutputFolder()
                }
            }
            Section("Case Metadata (Chain of Custody)") {
                TextField("Case Number", text: $vm.settings.caseMetadata.caseNumber)
                TextField("Investigator", text: $vm.settings.caseMetadata.investigator)
                TextField("Agency", text: $vm.settings.caseMetadata.agency)
                TextField("Evidence Description", text: $vm.settings.caseMetadata.evidenceDescription, axis: .vertical)
                    .lineLimit(2...4)
                DatePicker(
                    "Acquisition Date",
                    selection: Binding(
                        get: { vm.settings.caseMetadata.acquisitionDate ?? Date() },
                        set: { vm.settings.caseMetadata.acquisitionDate = $0 }
                    ),
                    displayedComponents: [.date, .hourAndMinute]
                )
                TextField("Classification", text: $vm.settings.caseMetadata.classification)
                TextField("Notes", text: $vm.settings.caseMetadata.notes, axis: .vertical)
                    .lineLimit(2...5)
            }
            Section("Quick Categories") {
                let forensicExtras: Set<String> = [
                    "sqlite", "sqlite3", "db", "sqlitedb", "plist", "bplist",
                    "dat", "bin", "raw", "tmp", "blob", "cache", "thumb", "thumbs",
                    "rem", "cod", "bbb", "ipd",
                    "txt", "md", "rtf", "csv", "json", "xml", "html", "htm", "log"
                ]
                let all = Set(SignatureRegistry.signatures.map { $0.type }).union(forensicExtras)
                let images = Set(SignatureRegistry.signatures.filter { $0.category == .images }.map { $0.type })
                let audio = Set(SignatureRegistry.signatures.filter { $0.category == .audio }.map { $0.type })
                let video = Set(SignatureRegistry.signatures.filter { $0.category == .video }.map { $0.type })
                let archives = Set(SignatureRegistry.signatures.filter { $0.category == .archives }.map { $0.type })

                HStack {
                    quickCategoryButton("Images", active: vm.settings.enabledTypes.isSuperset(of: images)) {
                        vm.settings.enabledTypes.formUnion(images)
                    }
                    quickCategoryButton("Audio", active: vm.settings.enabledTypes.isSuperset(of: audio)) {
                        vm.settings.enabledTypes.formUnion(audio)
                    }
                    quickCategoryButton("Video", active: vm.settings.enabledTypes.isSuperset(of: video)) {
                        vm.settings.enabledTypes.formUnion(video)
                    }
                    quickCategoryButton("Archives", active: vm.settings.enabledTypes.isSuperset(of: archives)) {
                        vm.settings.enabledTypes.formUnion(archives)
                    }
                    quickCategoryButton("All", active: vm.settings.enabledTypes == all) {
                        vm.settings.enabledTypes = all
                    }
                }

                HStack {
                    quickCategoryButton("Only Images", active: vm.settings.enabledTypes == images) {
                        vm.settings.enabledTypes = images
                    }
                    quickCategoryButton("Only Audio", active: vm.settings.enabledTypes == audio) {
                        vm.settings.enabledTypes = audio
                    }
                    quickCategoryButton("Only Video", active: vm.settings.enabledTypes == video) {
                        vm.settings.enabledTypes = video
                    }
                    quickCategoryButton("Only Archives", active: vm.settings.enabledTypes == archives) {
                        vm.settings.enabledTypes = archives
                    }
                }
            }
            Picker("Organization", selection: $vm.settings.organizationScheme) {
                Text("By source").tag(OrganizationScheme.bySource)
                Text("By type").tag(OrganizationScheme.byType)
                Text("Flat").tag(OrganizationScheme.flat)
            }
            Picker("Dedupe", selection: $vm.settings.dedupeMode) {
                Text("Off").tag(DedupeMode.off)
                Text("Exact Bytes (Recommended)").tag(DedupeMode.exactBytes)
                Text("Legacy Hash").tag(DedupeMode.hash)
                Text("Legacy Hash + Size").tag(DedupeMode.hashAndSize)
            }
            Toggle("Keep highest quality image duplicates", isOn: $vm.settings.keepHighestQualityImage)
            TextField("Max file size MB (optional)", value: Binding(
                get: { vm.settings.maxFileSizeMB ?? 0 },
                set: { vm.settings.maxFileSizeMB = $0 == 0 ? nil : $0 }
            ), format: .number)

            Section("AI Classification") {
                Toggle("Enable AI Classification", isOn: $vm.settings.enableAI)
                Picker("Threshold Preset", selection: Binding(
                    get: { vm.settings.resolvedAIThresholdPreset },
                    set: { vm.settings.aiThresholdPreset = $0.rawValue }
                )) {
                    Text("Forensic Balanced (Recommended)").tag(NSFWThresholdPreset.forensicBalanced)
                    Text("High Recall").tag(NSFWThresholdPreset.highRecall)
                    Text("High Precision").tag(NSFWThresholdPreset.highPrecision)
                }

                Text(presetHelpText(vm.settings.resolvedAIThresholdPreset))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .scrollContentBackground(.hidden)
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(AppTheme.card.opacity(0.94))
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(
                            LinearGradient(
                                colors: [
                                    AppTheme.primary.opacity(0.38),
                                    Color.white.opacity(0.08)
                                ],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            ),
                            lineWidth: 1
                        )
                )
        )
        .shadow(color: AppTheme.primary.opacity(0.18), radius: 12, x: 0, y: 6)
        .shadow(color: .black.opacity(0.42), radius: 18, x: 0, y: 12)
    }

    private func chooseOutputFolder() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Select Output Folder"

        if panel.runModal() == .OK, let selectedURL = panel.url {
            vm.settings.outputFolder = selectedURL.path
        }
    }

    @ViewBuilder
    private func quickCategoryButton(_ title: String, active: Bool, action: @escaping () -> Void) -> some View {
        if active {
            Button(title, action: action)
                .buttonStyle(.borderedProminent)
        } else {
            Button(title, action: action)
                .buttonStyle(.bordered)
        }
    }

    private func presetHelpText(_ preset: NSFWThresholdPreset) -> String {
        switch preset {
        case .forensicBalanced:
            return "Best default for mixed evidence: keeps strong detections while limiting false positives."
        case .highRecall:
            return "Flags more borderline content; best when missing sensitive content is unacceptable."
        case .highPrecision:
            return "Stricter thresholds for cleaner output; may miss weaker/partial exposures."
        }
    }
}

private func revealInFinder(path: String) {
    let fileURL = URL(fileURLWithPath: path)
    if FileManager.default.fileExists(atPath: path) {
        NSWorkspace.shared.activateFileViewerSelecting([fileURL])
    } else {
        NSWorkspace.shared.open(fileURL.deletingLastPathComponent())
    }
}

private struct ForensicDashboardView: View {
    @EnvironmentObject private var vm: AppViewModel
    @State private var showDedupedItems = false
    @State private var showAnalyzerOutputs = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Forensic Summary").font(.title3.bold())
                if let run = vm.activeRun {
                    let f = run.forensic
                    HStack {
                        SummaryCard(title: ".REM Files", value: "\(vm.forensicCount(for: .remFiles))") {
                            applyDashboardFilter(.remFiles, label: ".REM Files")
                        }
                        SummaryCard(title: "Media Recovered", value: "\(vm.forensicCount(for: .mediaRecovered))") {
                            applyDashboardFilter(.mediaRecovered, label: "Media Recovered")
                        }
                        SummaryCard(title: "Possible Decryptable DBs", value: "\(vm.forensicCount(for: .possibleDecryptableDBs))") {
                            applyDashboardFilter(.possibleDecryptableDBs, label: "Possible Decryptable DBs")
                        }
                        SummaryCard(title: "Nested Archives", value: "\(vm.forensicCount(for: .nestedArchives))") {
                            applyDashboardFilter(.nestedArchives, label: "Nested Archives")
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    HStack {
                        SummaryCard(title: "Decryptable Signals", value: "\(vm.forensicCount(for: .decryptableSignals))") {
                            applyDashboardFilter(.decryptableSignals, label: "Decryptable Signals")
                        }
                        SummaryCard(title: "Thumbnails", value: "\(vm.forensicCount(for: .thumbnails))") {
                            applyDashboardFilter(.thumbnails, label: "Thumbnails")
                        }
                        SummaryCard(title: "Message Signals", value: "\(vm.forensicCount(for: .messageSignals))") {
                            applyDashboardFilter(.messageSignals, label: "Message Signals")
                        }
                        SummaryCard(title: "Keys", value: "\(vm.forensicCount(for: .keys))") {
                            applyDashboardFilter(.keys, label: "Keys")
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    HStack {
                        SummaryCard(title: "Emails", value: "\(vm.forensicCount(for: .emails))") {
                            applyDashboardFilter(.emails, label: "Emails")
                        }
                        SummaryCard(title: "URLs", value: "\(vm.forensicCount(for: .urls))") {
                            applyDashboardFilter(.urls, label: "URLs")
                        }
                        SummaryCard(title: "Phone Numbers", value: "\(vm.forensicCount(for: .phoneNumbers))") {
                            applyDashboardFilter(.phoneNumbers, label: "Phone Numbers")
                        }
                        SummaryCard(title: "Language Text", value: "\(vm.forensicCount(for: .languageText))") {
                            applyDashboardFilter(.languageText, label: "Language Text")
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    HStack {
                        SummaryCard(title: "Hash Candidates", value: "\(vm.forensicCount(for: .hashCandidates))") {
                            applyDashboardFilter(.hashCandidates, label: "Hash Candidates")
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    HStack {
                        SummaryCard(title: "AI Safe", value: "\(vm.forensicCount(for: .aiSafe))") {
                            applyDashboardFilter(.aiSafe, label: "AI Safe")
                        }
                        SummaryCard(title: "AI Suggestive", value: "\(vm.forensicCount(for: .aiSuggestive))") {
                            applyDashboardFilter(.aiSuggestive, label: "AI Suggestive")
                        }
                        SummaryCard(title: "AI Explicit", value: "\(vm.forensicCount(for: .aiExplicit))") {
                            applyDashboardFilter(.aiExplicit, label: "AI Explicit")
                        }
                        SummaryCard(title: "AI Unknown", value: "\(vm.forensicCount(for: .aiUnknown))") {
                            applyDashboardFilter(.aiUnknown, label: "AI Unknown")
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    GroupBox("Forensic Artifacts") {
                        LazyVGrid(columns: [GridItem(.adaptive(minimum: 180), spacing: 8)], spacing: 8) {
                            Button("Open Recovered URLs") {
                                openIfExists(path: pathInRun(run.outputRoot, "URLs/URLs.html"))
                            }
                            .disabled(!fileExists(pathInRun(run.outputRoot, "URLs/URLs.html")))
                            .frame(maxWidth: .infinity, alignment: .leading)

                            Button("Open All Text") {
                                openIfExists(path: pathInRun(run.outputRoot, "txt/All The Text.txt"))
                            }
                            .disabled(!fileExists(pathInRun(run.outputRoot, "txt/All The Text.txt")))
                            .frame(maxWidth: .infinity, alignment: .leading)

                            Button("Open Run Report") {
                                openIfExists(path: pathInRun(run.outputRoot, "index.html"))
                            }
                            .disabled(!fileExists(pathInRun(run.outputRoot, "index.html")))
                            .frame(maxWidth: .infinity, alignment: .leading)

                            Button("Open Hash Candidates") {
                                openIfExists(path: pathInRun(run.outputRoot, "hash_candidates/hashcat_candidates.txt"))
                            }
                            .disabled(!fileExists(pathInRun(run.outputRoot, "hash_candidates/hashcat_candidates.txt")))
                            .frame(maxWidth: .infinity, alignment: .leading)

                            Button("Open Intelligence Report") {
                                openIfExists(path: pathInRun(run.outputRoot, "evidence_intelligence/intelligence_report.md"))
                            }
                            .disabled(!fileExists(pathInRun(run.outputRoot, "evidence_intelligence/intelligence_report.md")))
                            .frame(maxWidth: .infinity, alignment: .leading)

                            Button("Run Agents") {
                                vm.runAgents()
                            }
                            .disabled(vm.isScanning || vm.isRunningAgents || vm.isRunningAgentActions || run.outputRoot.isEmpty)
                            .frame(maxWidth: .infinity, alignment: .leading)

                            Button("Open Agent Summary") {
                                openIfExists(path: pathInRun(run.outputRoot, "evidence_intelligence/agents_summary.md"))
                            }
                            .disabled(!fileExists(pathInRun(run.outputRoot, "evidence_intelligence/agents_summary.md")))
                            .frame(maxWidth: .infinity, alignment: .leading)

                            Button("Run Recommended Actions") {
                                vm.runRecommendedActions()
                            }
                            .disabled(vm.isScanning || vm.isRunningAgents || vm.isRunningAgentActions || run.outputRoot.isEmpty)
                            .frame(maxWidth: .infinity, alignment: .leading)

                            Button("Open Agent Actions") {
                                openIfExists(path: pathInRun(run.outputRoot, "evidence_intelligence/actions/actions_report.md"))
                            }
                            .disabled(!fileExists(pathInRun(run.outputRoot, "evidence_intelligence/actions/actions_report.md")))
                            .frame(maxWidth: .infinity, alignment: .leading)

                            Button("Open Messages Extracted") {
                                openIfExists(path: pathInRun(run.outputRoot, "evidence_intelligence/actions/messages_extracted.txt"))
                            }
                            .disabled(!fileExists(pathInRun(run.outputRoot, "evidence_intelligence/actions/messages_extracted.txt")))
                            .frame(maxWidth: .infinity, alignment: .leading)

                            Button("Open Hash Wordlist") {
                                openIfExists(path: pathInRun(run.outputRoot, "evidence_intelligence/actions/hash_wordlist.txt"))
                            }
                            .disabled(!fileExists(pathInRun(run.outputRoot, "evidence_intelligence/actions/hash_wordlist.txt")))
                            .frame(maxWidth: .infinity, alignment: .leading)

                            Button("Open URL Clusters") {
                                openIfExists(path: pathInRun(run.outputRoot, "evidence_intelligence/actions/url_clusters.md"))
                            }
                            .disabled(!fileExists(pathInRun(run.outputRoot, "evidence_intelligence/actions/url_clusters.md")))
                            .frame(maxWidth: .infinity, alignment: .leading)

                            Button("Open Decryptability Checks") {
                                openIfExists(path: pathInRun(run.outputRoot, "evidence_intelligence/actions/decryptability_checks.md"))
                            }
                            .disabled(!fileExists(pathInRun(run.outputRoot, "evidence_intelligence/actions/decryptability_checks.md")))
                            .frame(maxWidth: .infinity, alignment: .leading)

                            Button("Open Coverage Audit") {
                                openIfExists(path: pathInRun(run.outputRoot, "coverage/coverage_report.md"))
                            }
                            .disabled(!fileExists(pathInRun(run.outputRoot, "coverage/coverage_report.md")))
                            .frame(maxWidth: .infinity, alignment: .leading)

                            Button("Open Binary Intelligence") {
                                openIfExists(path: pathInRun(run.outputRoot, "binary_intelligence/index.md"))
                            }
                            .disabled(!fileExists(pathInRun(run.outputRoot, "binary_intelligence/index.md")))
                            .frame(maxWidth: .infinity, alignment: .leading)

                            Button("Open Dedupe Report") {
                                openIfExists(path: pathInRun(run.outputRoot, "dedupe/dedupe_report.md"))
                            }
                            .disabled(!fileExists(pathInRun(run.outputRoot, "dedupe/dedupe_report.md")))
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .buttonStyle(ActionButtonStyle())
                    }

                    GroupBox {
                        DisclosureGroup("Deduped Items (\(run.dedupeRemoved.count))", isExpanded: $showDedupedItems) {
                            if run.dedupeRemoved.isEmpty {
                                Text("No deduped items in this run.")
                                    .foregroundStyle(.secondary)
                            } else {
                                VStack(alignment: .leading, spacing: 8) {
                                    Text("Grouped by dedupe key so you can audit what was kept vs removed.")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)

                                    ScrollView {
                                        VStack(alignment: .leading, spacing: 8) {
                                            ForEach(groupedDedupeRemovals(run.dedupeRemoved), id: \.dedupeKey) { group in
                                                DisclosureGroup {
                                                    VStack(alignment: .leading, spacing: 6) {
                                                        Text("Kept: \(group.keptPath)")
                                                            .font(.caption)
                                                            .textSelection(.enabled)
                                                            .lineLimit(2)
                                                            .truncationMode(.middle)
                                                        ForEach(group.removedPaths, id: \.self) { removed in
                                                            Text("Removed: \(removed)")
                                                                .font(.caption)
                                                                .foregroundStyle(.secondary)
                                                                .textSelection(.enabled)
                                                                .lineLimit(2)
                                                                .truncationMode(.middle)
                                                        }
                                                    }
                                                    .padding(.top, 2)
                                                } label: {
                                                    HStack {
                                                        Text(URL(fileURLWithPath: group.keptPath).lastPathComponent)
                                                            .lineLimit(1)
                                                            .truncationMode(.middle)
                                                        Spacer()
                                                        Text("\(group.removedPaths.count) removed")
                                                            .font(.caption.weight(.semibold))
                                                            .foregroundStyle(.orange)
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    .frame(maxHeight: 220)
                                }
                            }
                        }
                    }

                    GroupBox("Keys Found") {
                        if f.keyFiles.isEmpty { Text("None").foregroundStyle(.secondary) }
                        else { ForEach(f.keyFiles, id: \.self) { Text($0).lineLimit(1) } }
                    }

                    GroupBox("AI Reason Tags") {
                        let tags = vm.reasonTags()
                        if tags.isEmpty {
                            Text("No reason tags yet.").foregroundStyle(.secondary)
                        } else {
                            FlowTagView(
                                tags: tags,
                                selectedTag: selectedReasonTag(from: vm.query),
                                onTagTap: applyReasonTagFilter
                            )
                        }
                    }

                    GroupBox {
                        DisclosureGroup("Analyzer Outputs (\(f.analyzerResults.count))", isExpanded: $showAnalyzerOutputs) {
                            if f.analyzerResults.isEmpty {
                                Text("No analyzer results yet.").foregroundStyle(.secondary)
                            } else {
                                ForEach(f.analyzerResults, id: \.sourcePath) { r in
                                    VStack(alignment: .leading, spacing: 6) {
                                        HStack {
                                            Text(URL(fileURLWithPath: r.sourcePath).lastPathComponent).bold()
                                            Spacer()
                                            Text(r.nsfwSeverity.rawValue.capitalized)
                                                .font(.caption.weight(.semibold))
                                                .padding(.horizontal, 8)
                                                .padding(.vertical, 3)
                                                .background(Capsule().fill(r.nsfwSeverity == .explicit ? Color.red.opacity(0.2) : Color.orange.opacity(0.2)))
                                        }
                                        HStack(spacing: 12) {
                                            Text(String(format: "Score %.2f", r.nsfwScore))
                                            Text("Reasons: \(r.reasonDetections?.count ?? 0)")
                                            Text("Media: \(r.carvedMediaCount)")
                                            if r.sqliteHeaderDetected { Text("SQLite").foregroundStyle(.green) }
                                            if let h = r.heatmapPath {
                                                Button("Heatmap") { NSWorkspace.shared.open(URL(fileURLWithPath: h)) }
                                            }
                                            if let p = r.stringsPath {
                                                Button("Strings") { NSWorkspace.shared.open(URL(fileURLWithPath: p)) }
                                            }
                                        }
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                        if let reasonSummary = flagReasonSummary(for: r) {
                                            Text("Why flagged: \(reasonSummary)")
                                                .font(.caption)
                                                .foregroundStyle(.secondary)
                                                .lineLimit(3)
                                        }
                                    }
                                    .padding(.vertical, 2)
                                }
                            }
                        }
                    }
                } else {
                    Text("Run a scan to see forensic summaries.").foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical)
        }
        .cardSurface()
    }

    private func pathInRun(_ runRoot: String, _ relative: String) -> String {
        URL(fileURLWithPath: runRoot, isDirectory: true)
            .appendingPathComponent(relative).path
    }

    private func fileExists(_ path: String) -> Bool {
        FileManager.default.fileExists(atPath: path)
    }

    private func openIfExists(path: String) {
        guard fileExists(path) else { return }
        NSWorkspace.shared.open(URL(fileURLWithPath: path))
    }

    private func flagReasonSummary(for result: AnalyzerResult) -> String? {
        if let detections = result.reasonDetections, !detections.isEmpty {
            let top = detections
                .sorted { $0.confidence > $1.confidence }
                .prefix(3)
                .map { "\($0.modelLabel) (\(Int($0.confidence * 100))%)" }
                .joined(separator: ", ")
            return top.isEmpty ? nil : top
        }
        if result.scaIsSensitive == true {
            return "SensitiveContentAnalysis marked this media as sensitive."
        }
        return nil
    }

    private func groupedDedupeRemovals(_ removed: [DedupeRemoval]) -> [DedupeGroup] {
        var grouped: [String: DedupeGroup] = [:]
        for row in removed {
            if grouped[row.dedupeKey] == nil {
                grouped[row.dedupeKey] = DedupeGroup(
                    dedupeKey: row.dedupeKey,
                    keptPath: row.keptSourcePath,
                    removedPaths: []
                )
            }
            grouped[row.dedupeKey]?.removedPaths.append(row.removedSourcePath)
        }
        return grouped.values.sorted { lhs, rhs in
            if lhs.removedPaths.count == rhs.removedPaths.count {
                return lhs.keptPath < rhs.keptPath
            }
            return lhs.removedPaths.count > rhs.removedPaths.count
        }
    }

    private func selectedReasonTag(from query: String) -> String? {
        let normalized = query
            .lowercased()
            .replacingOccurrences(of: " ", with: "_")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return normalized.isEmpty ? nil : normalized
    }

    private func applyReasonTagFilter(_ tag: String) {
        let normalized = tag.lowercased().replacingOccurrences(of: "_", with: " ")
        if vm.query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == normalized {
            vm.query = ""
            return
        }
        vm.query = normalized
        vm.route = .results
        vm.statusMessage = "Filtering results by AI reason: \(normalized)"
    }

    private func applyDashboardFilter(_ facet: ForensicFacet, label: String) {
        if vm.activeForensicFacet == facet {
            vm.activeForensicFacet = nil
            vm.statusMessage = "Cleared forensic filter."
            return
        }
        vm.activeForensicFacet = facet
        vm.clearSearch()
        vm.clearGraphPivot()
        vm.route = .results
        vm.statusMessage = "Filtering results by \(label) facet."
    }
}

private struct DedupeGroup {
    let dedupeKey: String
    let keptPath: String
    var removedPaths: [String]
}

private struct FlowTagView: View {
    let tags: [(String, Int)]
    var selectedTag: String? = nil
    var onTagTap: ((String) -> Void)? = nil

    var body: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 120), spacing: 8)], spacing: 8) {
            ForEach(tags, id: \.0) { tag, count in
                let isSelected = selectedTag == tag.lowercased()
                Button {
                    onTagTap?(tag)
                } label: {
                    HStack(spacing: 6) {
                        Text(tag.replacingOccurrences(of: "_", with: " ").capitalized)
                        Text("\(count)")
                            .font(.caption2.bold())
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Capsule().fill(Color.gray.opacity(isSelected ? 0.28 : 0.18)))
                    }
                    .font(.caption)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 6)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        RoundedRectangle(cornerRadius: 8)
                            .fill(isSelected ? AppTheme.primary.opacity(0.24) : Color.gray.opacity(0.10))
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(isSelected ? AppTheme.primary.opacity(0.58) : Color.clear, lineWidth: 1)
                    )
                }
                .buttonStyle(.plain)
                .help("Filter results by this reason tag")
            }
        }
    }
}

private struct SummaryCard: View {
    let title: String
    let value: String
    var onTap: (() -> Void)? = nil

    @ViewBuilder
    private var content: some View {
        VStack {
            Text(title)
                .font(.caption)
                .foregroundStyle(AppTheme.mutedText)
            Text(value)
                .font(.title2.bold())
                .foregroundStyle(AppTheme.text)
        }
    }

    var body: some View {
        Group {
            if let onTap {
                Button(action: onTap) {
                    content
                }
                .buttonStyle(.plain)
                .contentShape(RoundedRectangle(cornerRadius: 12))
                .help("Filter results by \(title)")
            } else {
                content
            }
        }
            .frame(width: 180, height: 80)
            .forensicSummaryCardStyle()
    }
}

private struct ScanRadarView: View {
    let progress: Double
    let isScanning: Bool

    @State private var glowOpacity: Double = 0.55
    @State private var scanStart = Date()

    private var percentLabel: String {
        if isScanning {
            return "\(min(Int((progress * 100).rounded(.down)), 99))%"
        }
        return "\(Int((progress * 100).rounded()))%"
    }

    var body: some View {
        Group {
            if isScanning {
                SwiftUI.TimelineView(.periodic(from: .now, by: 1.0 / 30.0)) { timeline in
                    radarContent(at: timeline.date)
                }
            } else {
                radarContent(at: Date())
            }
        }
        .onAppear { updateAnimation() }
        .onChange(of: isScanning) { _, _ in
            updateAnimation()
        }
    }

    @ViewBuilder
    private func radarContent(at time: Date) -> some View {
        GeometryReader { geo in
            let size = min(geo.size.width, geo.size.height)
            let ringLine = max(3, size * 0.02)
            let innerSize = size * 0.50
            let elapsed = time.timeIntervalSince(scanStart)
            let sweepRotation = isScanning ? ((elapsed / 1.6) * 360.0) - 100.0 : -100.0

            ZStack {
                Circle()
                    .stroke(AppTheme.primary.opacity(0.14), lineWidth: ringLine)

                Circle()
                    .stroke(
                        LinearGradient(
                            colors: [AppTheme.primary.opacity(0.22), AppTheme.primary.opacity(0.03)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        lineWidth: ringLine * 2.5
                    )
                    .blur(radius: 1)

                RadarSweepShape(startAngle: .degrees(-24), endAngle: .degrees(44))
                    .fill(
                        LinearGradient(
                            colors: [AppTheme.primary.opacity(0.05), AppTheme.primary.opacity(0.35)],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )
                    .rotationEffect(.degrees(sweepRotation))
                    .opacity(isScanning ? glowOpacity : 0.2)

                Circle()
                    .stroke(AppTheme.primary.opacity(0.85), lineWidth: ringLine)
                    .frame(width: innerSize, height: innerSize)

                Text(percentLabel)
                    .font(.system(size: size * 0.17, weight: .bold, design: .rounded))
                    .foregroundStyle(AppTheme.primary)
            }
            .frame(width: size, height: size)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .center)
            .shadow(color: AppTheme.primary.opacity(0.20), radius: 12, x: 0, y: 0)
        }
    }

    private func updateAnimation() {
        if isScanning {
            scanStart = Date()
            glowOpacity = 0.92
        } else {
            withAnimation(.easeOut(duration: 0.25)) {
                glowOpacity = 0.35
            }
        }
    }
}

private struct RadarSweepShape: Shape {
    var startAngle: Angle
    var endAngle: Angle

    func path(in rect: CGRect) -> Path {
        var path = Path()
        let center = CGPoint(x: rect.midX, y: rect.midY)
        let radius = min(rect.width, rect.height) / 2
        path.move(to: center)
        path.addArc(center: center, radius: radius, startAngle: startAngle, endAngle: endAngle, clockwise: false)
        path.closeSubpath()
        return path
    }
}

private struct CommandPaletteItem: Identifiable {
    let id = UUID()
    let title: String
    let subtitle: String
    let keywords: [String]
    let action: () -> Void
}

private struct CommandPaletteView: View {
    @EnvironmentObject private var vm: AppViewModel
    let commands: [CommandPaletteItem]
    @State private var query = ""
    @State private var selectedID: UUID?

    private var filtered: [CommandPaletteItem] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return commands }
        return commands.filter { cmd in
            cmd.title.lowercased().contains(needle) ||
            cmd.subtitle.lowercased().contains(needle) ||
            cmd.keywords.contains(where: { $0.lowercased().contains(needle) })
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            TextField("Type a command…", text: $query)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 15, weight: .semibold))

            List(filtered, selection: $selectedID) { command in
                VStack(alignment: .leading, spacing: 4) {
                    Text(command.title)
                        .font(.headline)
                    Text(command.subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .tag(command.id)
                .contentShape(Rectangle())
                .onTapGesture {
                    command.action()
                    vm.commandPalettePresented = false
                }
            }
            .onAppear {
                selectedID = filtered.first?.id
            }
        }
        .padding(14)
        .cardSurface()
        .onSubmit {
            guard let selectedID,
                  let command = filtered.first(where: { $0.id == selectedID }) else { return }
            command.action()
            vm.commandPalettePresented = false
        }
    }
}

private struct TimelineView: View {
    @EnvironmentObject private var vm: AppViewModel

    private struct TimelineEvent: Identifiable {
        let id: UUID
        let date: Date
        let title: String
        let subtitle: String
        let category: FileCategory
        let item: FoundItem
    }

    private var events: [TimelineEvent] {
        vm.timelineItems().map { row in
            TimelineEvent(
                id: row.item.id,
                date: row.date,
                title: URL(fileURLWithPath: row.item.sourcePath).lastPathComponent,
                subtitle: row.item.detectedType.uppercased(),
                category: row.item.category,
                item: row.item
            )
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Forensic Timeline")
                .font(.title2.bold())
            if events.isEmpty {
                Text("No timeline events yet. Run a scan and select this tab again.")
                    .foregroundStyle(.secondary)
            } else {
                List(events) { event in
                    HStack(alignment: .top, spacing: 10) {
                        Circle()
                            .fill(color(for: event.category))
                            .frame(width: 10, height: 10)
                            .padding(.top, 6)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(event.title).font(.subheadline.weight(.semibold))
                            Text(event.subtitle).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(event.date, style: .date)
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    .contentShape(Rectangle())
                    .onTapGesture {
                        vm.selectedItem = event.item
                        vm.route = .results
                    }
                }
                .scrollContentBackground(.hidden)
                .background(
                    RoundedRectangle(cornerRadius: 12)
                        .fill(AppTheme.input.opacity(0.86))
                        .overlay(
                            RoundedRectangle(cornerRadius: 12)
                                .stroke(AppTheme.primary.opacity(0.24), lineWidth: 1)
                        )
                )
            }
        }
        .padding()
        .cardSurface()
    }

    private func color(for category: FileCategory) -> Color {
        switch category {
        case .images: return AppTheme.primary
        case .video: return .orange
        case .audio: return .green
        case .text: return .yellow
        case .archives: return .pink
        case .uncertain: return .gray
        }
    }
}

private struct EvidenceGraphView: View {
    @EnvironmentObject private var vm: AppViewModel

    var body: some View {
        let (nodes, edges) = vm.evidenceGraphData()
        VStack(alignment: .leading, spacing: 12) {
            Text("Evidence Graph")
                .font(.title2.bold())
            Text("Relationship map of source folders and artifact types from the current run.")
                .font(.caption)
                .foregroundStyle(.secondary)
            if nodes.isEmpty {
                Text("No graph data yet. Run a scan and open Evidence Graph.")
                    .foregroundStyle(.secondary)
            } else {
                HStack(spacing: 12) {
                    GraphCanvasView(nodes: nodes, edges: edges)
                        .frame(minHeight: 360)
                        .cardSurface()
                    List(edges.prefix(24)) { edge in
                        let src = edge.from.replacingOccurrences(of: "src:", with: "")
                        let dst = edge.to.replacingOccurrences(of: "type:", with: "")
                        VStack(alignment: .leading, spacing: 2) {
                            Text("\(src) → \(dst)")
                                .font(.caption.weight(.semibold))
                            Text("\(edge.weight) artifacts")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        .contentShape(Rectangle())
                        .onTapGesture {
                            vm.applyGraphPivot(sourceFolder: src, detectedType: dst)
                        }
                    }
                    .frame(width: 280)
                    .cardSurface()
                }
            }
        }
        .padding()
        .cardSurface()
    }
}

private struct GraphCanvasView: View {
    let nodes: [EvidenceGraphNodeModel]
    let edges: [EvidenceGraphEdgeModel]

    var body: some View {
        GeometryReader { geo in
            let positions = layout(in: geo.size)
            ZStack {
                ForEach(edges) { edge in
                    if let a = positions[edge.from], let b = positions[edge.to] {
                        Path { p in
                            p.move(to: a)
                            p.addLine(to: b)
                        }
                        .stroke(AppTheme.primary.opacity(0.18 + min(Double(edge.weight) / 200.0, 0.45)), lineWidth: 1.2)
                    }
                }
                ForEach(nodes) { node in
                    if let point = positions[node.id] {
                        VStack(spacing: 4) {
                            Circle()
                                .fill(node.kind == "source" ? AppTheme.primary.opacity(0.85) : Color.orange.opacity(0.85))
                                .frame(width: 16, height: 16)
                            Text(node.title)
                                .font(.caption2)
                                .lineLimit(1)
                                .frame(maxWidth: 90)
                                .truncationMode(.tail)
                            Text("\(node.count)")
                                .font(.caption2.monospacedDigit())
                                .foregroundStyle(.secondary)
                        }
                        .position(point)
                    }
                }
            }
        }
    }

    private func layout(in size: CGSize) -> [String: CGPoint] {
        var map: [String: CGPoint] = [:]
        let center = CGPoint(x: size.width / 2, y: size.height / 2)
        let radiusSource = min(size.width, size.height) * 0.33
        let radiusType = min(size.width, size.height) * 0.20

        let sources = nodes.filter { $0.kind == "source" }
        let types = nodes.filter { $0.kind == "type" }

        for (idx, node) in sources.enumerated() {
            let angle = (Double(idx) / Double(max(sources.count, 1))) * (Double.pi * 2)
            map[node.id] = CGPoint(
                x: center.x + cos(angle) * radiusSource,
                y: center.y + sin(angle) * radiusSource
            )
        }
        for (idx, node) in types.enumerated() {
            let angle = (Double(idx) / Double(max(types.count, 1))) * (Double.pi * 2)
            map[node.id] = CGPoint(
                x: center.x + cos(angle) * radiusType,
                y: center.y + sin(angle) * radiusType
            )
        }
        return map
    }
}

private struct CaseBuilderView: View {
    @EnvironmentObject private var vm: AppViewModel
    @State private var caseName = "Untitled Case"
    @State private var notes = ""
    @State private var selectedIDs = Set<UUID>()
    @State private var filter = ""

    private var runItems: [FoundItem] {
        vm.filteredItems
    }

    private var candidateItems: [FoundItem] {
        let q = filter.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return Array(runItems.prefix(1500)) }
        return runItems.filter {
            $0.sourcePath.lowercased().contains(q) ||
            $0.detectedType.lowercased().contains(q) ||
            $0.fileExtension.lowercased().contains(q)
        }
        .prefix(1500)
        .map { $0 }
    }

    private var selectedItems: [FoundItem] {
        runItems.filter { selectedIDs.contains($0.id) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("AI Case Builder")
                .font(.title2.bold())
            HStack(spacing: 10) {
                TextField("Case Name", text: $caseName)
                    .textFieldStyle(.roundedBorder)
                Button("Save Case") {
                    vm.saveInvestigationCase(name: caseName, notes: notes, artifactIDs: selectedIDs)
                    vm.statusMessage = "Saved case \"\(caseName)\" with \(selectedIDs.count) artifacts."
                }
                Button("Clear Selection") {
                    selectedIDs.removeAll()
                }
            }
            TextEditor(text: $notes)
                .frame(minHeight: 72, maxHeight: 120)
                .scrollContentBackground(.hidden)
                .background(RoundedRectangle(cornerRadius: 10).fill(AppTheme.input.opacity(0.88)))
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(AppTheme.primary.opacity(0.20), lineWidth: 1))

            HStack(alignment: .top, spacing: 12) {
                VStack(alignment: .leading, spacing: 8) {
                    TextField("Search run artifacts…", text: $filter)
                        .textFieldStyle(.roundedBorder)
                    List(candidateItems, selection: $selectedIDs) { item in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(URL(fileURLWithPath: item.sourcePath).lastPathComponent)
                                .font(.caption.weight(.semibold))
                            Text("\(item.detectedType.uppercased()) • \(URL(fileURLWithPath: item.sourcePath).deletingLastPathComponent().lastPathComponent)")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        .tag(item.id)
                    }
                    .scrollContentBackground(.hidden)
                    .background(
                        RoundedRectangle(cornerRadius: 10)
                            .fill(AppTheme.input.opacity(0.88))
                            .overlay(
                                RoundedRectangle(cornerRadius: 10)
                                    .stroke(AppTheme.primary.opacity(0.24), lineWidth: 1)
                            )
                    )
                }
                .cardSurface()

                VStack(alignment: .leading, spacing: 8) {
                    Text("Case Evidence (\(selectedItems.count))")
                        .font(.headline)
                    List(selectedItems) { item in
                        HStack {
                            Text(item.detectedType.uppercased())
                                .font(.caption.monospaced())
                                .foregroundStyle(AppTheme.primary)
                            Text(URL(fileURLWithPath: item.sourcePath).lastPathComponent)
                                .font(.caption)
                        }
                    }
                    .scrollContentBackground(.hidden)
                    .background(
                        RoundedRectangle(cornerRadius: 10)
                            .fill(AppTheme.input.opacity(0.88))
                            .overlay(
                                RoundedRectangle(cornerRadius: 10)
                                    .stroke(AppTheme.primary.opacity(0.24), lineWidth: 1)
                            )
                    )
                }
                .frame(width: 320)
                .cardSurface()
            }
        }
        .padding()
        .cardSurface()
    }
}

#endif
