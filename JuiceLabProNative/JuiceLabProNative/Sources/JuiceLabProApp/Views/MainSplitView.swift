#if canImport(SwiftUI) && canImport(AppKit)
import SwiftUI
import AppKit
import UniformTypeIdentifiers
import JuiceLabCore

struct MainSplitView: View {
    @EnvironmentObject private var vm: AppViewModel

    var body: some View {
        NavigationSplitView {
            SidebarView()
        } content: {
            Group {
                if vm.route == .settings {
                    SettingsPanelView()
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
            InspectorView(item: vm.selectedItem)
                .padding()
        }
        .searchable(text: $vm.query, placement: .toolbar)
    }
}

private struct SidebarView: View {
    @EnvironmentObject private var vm: AppViewModel

    var body: some View {
        List(selection: $vm.route) {
            Section("Navigate") {
                ForEach(AppViewModel.Route.allCases, id: \.self) { route in
                    Label(route.rawValue, systemImage: icon(for: route)).tag(route)
                }
            }
            Section("Run History") {
                ForEach(vm.runs) { run in
                    VStack(alignment: .leading) {
                        Text(run.name).bold().lineLimit(1)
                        Text("\(run.items.count) items").font(.caption).foregroundStyle(.secondary)
                    }
                    .tag(run.id)
                    .onTapGesture { vm.selectedRunID = run.id }
                }
            }
        }
    }

    private func icon(for route: AppViewModel.Route) -> String {
        switch route {
        case .runs: return "clock.arrow.circlepath"
        case .results: return "tray.full"
        case .settings: return "gearshape"
        }
    }
}

private struct ToolbarView: View {
    @EnvironmentObject private var vm: AppViewModel

    var body: some View {
        HStack {
            Picker("Mode", selection: $vm.settings.performanceMode) {
                Text("Fast").tag(PerformanceMode.fast)
                Text("Balanced").tag(PerformanceMode.balanced)
                Text("Thorough").tag(PerformanceMode.thorough)
            }
            .pickerStyle(.segmented)
            .frame(width: 320)

            Spacer()

            Button("Add Sources…") {
                pickSources()
            }

            Button("Start") { vm.startScan() }
                .buttonStyle(.borderedProminent)
                .disabled(vm.isScanning || vm.droppedURLs.isEmpty)

            Button("Stop") { vm.stopScan() }
                .disabled(!vm.isScanning)
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
                Text("Scanned: \(ByteCountFormatter.string(fromByteCount: vm.progress.bytesScanned, countStyle: .file))")
                Text(String(format: "%.1f MB/s", vm.progress.mbPerSecond))
                Text("ETA: \(Int(vm.progress.etaSeconds))s")
                ProgressView(
                    value: vm.progress.totalBytes == 0 ? 0 : Double(vm.progress.bytesScanned),
                    total: Double(max(vm.progress.totalBytes, 1))
                )
            }
            .frame(width: 260)
            .cardSurface()
        }
    }
}

private struct ResultsTableView: View {
    @EnvironmentObject private var vm: AppViewModel
    let items: [FoundItem]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
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

            Table(items, selection: Binding(get: {
                vm.selectedItem.map { Set([$0.id]) } ?? []
            }, set: { ids in
                vm.selectedItem = items.first(where: { ids.contains($0.id) })
            })) {
                TableColumn("Type") { Text($0.detectedType.uppercased()) }
                TableColumn("Source") { Text(URL(fileURLWithPath: $0.sourcePath).lastPathComponent) }
                TableColumn("Offset") { Text(String(format: "0x%X", $0.offset)) }
                TableColumn("Validation") { Text($0.validationStatus.rawValue.capitalized) }
                TableColumn("Size") { Text(ByteCountFormatter.string(fromByteCount: Int64($0.length), countStyle: .file)) }
            }
        }
        .cardSurface()
    }
}

private struct InspectorView: View {
    let item: FoundItem?

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
                        Text("Source: \(item.sourcePath)").lineLimit(2)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
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
            Picker("Organization", selection: $vm.settings.organizationScheme) {
                Text("By source").tag(OrganizationScheme.bySource)
                Text("By type").tag(OrganizationScheme.byType)
                Text("Flat").tag(OrganizationScheme.flat)
            }
            Picker("Dedupe", selection: $vm.settings.dedupeMode) {
                Text("Off").tag(DedupeMode.off)
                Text("Hash").tag(DedupeMode.hash)
                Text("Hash + Size").tag(DedupeMode.hashAndSize)
            }
            Toggle("Keep highest quality image duplicates", isOn: $vm.settings.keepHighestQualityImage)
            TextField("Max file size MB (optional)", value: Binding(
                get: { vm.settings.maxFileSizeMB ?? 0 },
                set: { vm.settings.maxFileSizeMB = $0 == 0 ? nil : $0 }
            ), format: .number)
        }
        .formStyle(.grouped)
        .cardSurface()
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
}

private func revealInFinder(path: String) {
    let fileURL = URL(fileURLWithPath: path)
    if FileManager.default.fileExists(atPath: path) {
        NSWorkspace.shared.activateFileViewerSelecting([fileURL])
    } else {
        NSWorkspace.shared.open(fileURL.deletingLastPathComponent())
    }
}

#endif
