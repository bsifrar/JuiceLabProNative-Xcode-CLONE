#if canImport(SwiftUI) && canImport(AppKit)
import SwiftUI
import AppKit
import UniformTypeIdentifiers
import JuiceLabCore
import AVKit
import PDFKit

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
    }
}

private struct SidebarView: View {
    @EnvironmentObject private var vm: AppViewModel

    var body: some View {
        VStack(spacing: 10) {
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
    }

    private func icon(for route: AppViewModel.Route) -> String {
        switch route {
        case .runs: return "clock.arrow.circlepath"
        case .results: return "tray.full"
        case .forensic: return "shield.lefthalf.filled"
        case .settings: return "gearshape"
        }
    }
}

private struct ToolbarView: View {
    @EnvironmentObject private var vm: AppViewModel
    @State private var showClearResultsDialog = false

    var body: some View {
        HStack(spacing: 10) {
            ViewThatFits(in: .horizontal) {
                expandedControls
                compactControls
            }
            .frame(maxWidth: .infinity, alignment: .leading)

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

                Menu {
                    Button("Reveal Run Folder") {
                        if let run = vm.activeRun {
                            let url = URL(fileURLWithPath: run.outputRoot)
                            NSWorkspace.shared.open(url)
                        } else {
                            let url = URL(fileURLWithPath: vm.settings.outputFolder)
                            NSWorkspace.shared.open(url)
                        }
                    }
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

    private var expandedControls: some View {
        HStack(spacing: 10) {
            Picker("Mode", selection: $vm.settings.performanceMode) {
                Text("Fast").tag(PerformanceMode.fast)
                Text("Balanced").tag(PerformanceMode.balanced)
                Text("Thorough").tag(PerformanceMode.thorough)
            }
            .pickerStyle(.segmented)
            .frame(width: 260)

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
        }
    }

    private var compactControls: some View {
        HStack(spacing: 8) {
            Picker("Mode", selection: $vm.settings.performanceMode) {
                Text("Fast").tag(PerformanceMode.fast)
                Text("Balanced").tag(PerformanceMode.balanced)
                Text("Thorough").tag(PerformanceMode.thorough)
            }
            .pickerStyle(.segmented)
            .frame(width: 210)

            Menu {
                Toggle("Enable AI", isOn: $vm.settings.enableAI)
                Toggle(
                    "Dedupe",
                    isOn: Binding(
                        get: { vm.settings.dedupeMode != .off },
                        set: { vm.settings.dedupeMode = $0 ? .exactBytes : .off }
                    )
                )
                Divider()
                Button("Add Sources…") { pickSources() }
                Button("Clear Sources") { vm.clearSources() }
                    .disabled(vm.isScanning || vm.droppedURLs.isEmpty)
            } label: {
                HStack(spacing: 6) {
                    Text("Controls")
                    Image(systemName: "slider.horizontal.3")
                }
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
                let normalizedProgress = vm.progress.totalBytes == 0 ? 0 : min(1, max(0, Double(vm.progress.bytesScanned) / Double(vm.progress.totalBytes)))
                ScanRadarView(progress: normalizedProgress, isScanning: vm.isScanning)
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
                ProgressView(
                    value: vm.progress.totalBytes == 0 ? 0 : Double(vm.progress.bytesScanned),
                    total: Double(max(vm.progress.totalBytes, 1))
                )
                if !vm.statusMessage.isEmpty {
                    Text(vm.statusMessage)
                        .font(.caption)
                        .foregroundStyle(vm.statusMessage.localizedCaseInsensitiveContains("warning") ||
                                         vm.statusMessage.localizedCaseInsensitiveContains("unreadable") ? .orange : .secondary)
                        .lineLimit(3)
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
    @State private var sortOrder: [KeyPathComparator<FoundItem>] = [
        .init(\.detectedType, order: .forward)
    ]

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
            resultsTable
        }
        .cardSurface()
    }

    private var resultsTable: some View {
        Table(sortedItems, selection: Binding(
            get: { vm.selectedItem?.id },
            set: { selectedID in
                vm.selectedItem = sortedItems.first(where: { $0.id == selectedID })
            })
        , sortOrder: $sortOrder
        ) {
            TableColumn("Type", value: \.detectedType) { item in
                Text(item.detectedType.uppercased())
            }
            TableColumn("Source", value: \.sourceDisplayName) { item in
                Text(item.sourceDisplayName)
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
        .onAppear { applySort() }
        .onChange(of: items) { _, _ in applySort() }
        .onChange(of: sortOrder) { _, _ in applySort() }
    }

    private func applySort() {
        var copy = items
        copy.sort(using: sortOrder)
        sortedItems = copy
    }
}

private extension FoundItem {
    var sourceDisplayName: String { URL(fileURLWithPath: sourcePath).lastPathComponent }
    var validationText: String { validationStatus.rawValue }
}

private struct InspectorView: View {
    @EnvironmentObject private var vm: AppViewModel
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
                GroupBox("Preview") {
                    PreviewView(item: item, runOutputRoot: vm.activeRun?.outputRoot)
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

private struct PreviewView: View {
    let item: FoundItem
    let runOutputRoot: String?

    @State private var nsImage: NSImage?
    @State private var previewText: String = ""
    @State private var pdfDocument: PDFDocument?
    @State private var avPlayer: AVPlayer?

    var body: some View {
        ZStack {
            if let doc = pdfDocument {
                PDFKitView(document: doc)
            } else if let player = avPlayer {
                AVPlayerViewWrapper(player: player)
            } else if let img = nsImage {
                GeometryReader { geo in
                    Image(nsImage: img)
                        .resizable()
                        .scaledToFit()
                        .frame(width: geo.size.width, height: geo.size.height)
                }
            } else if !previewText.isEmpty {
                ScrollView { Text(previewText).font(.system(.caption, design: .monospaced)).textSelection(.enabled).padding(6) }
            } else {
                ProgressView().controlSize(.small)
            }
        }
        .task(id: item.id) { await loadPreview() }
    }

    private func loadPreview() async {
        await MainActor.run {
            self.nsImage = nil
            self.previewText = ""
            self.pdfDocument = nil
            self.avPlayer = nil
        }

        let candidates = previewCandidatePaths()
        var loaded: (URL, Data)?
        var lastError: Error?

        for candidate in candidates {
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
                await MainActor.run { self.previewText = message }
            } else {
                await MainActor.run { self.previewText = "File not found in source or exported output." }
            }
            return
        }

        // Priority: PDF, AV (video/audio), Image, Text, Hex
        let ext = url.pathExtension.lowercased()
        if ext == "pdf", let doc = PDFDocument(data: data) {
            await MainActor.run { self.pdfDocument = doc }
            return
        }

        let videoExts: Set<String> = ["mp4", "mov", "mkv", "avi", "webm", "mpeg", "m2ts"]
        let audioExts: Set<String> = ["mp3", "wav", "flac", "ogg", "m4a", "aac", "alac"]
        if videoExts.contains(ext) || audioExts.contains(ext) {
            let player = AVPlayer(url: url)
            await MainActor.run { self.avPlayer = player }
            return
        }

        if item.category == .images, let img = NSImage(data: data) {
            let maxSide: CGFloat = 512
            let size = img.size
            let scale = min(maxSide / max(size.width, size.height), 1)
            let target = NSSize(width: size.width * scale, height: size.height * scale)
            let thumb = NSImage(size: target)
            thumb.lockFocus()
            img.draw(in: NSRect(origin: .zero, size: target), from: NSRect(origin: .zero, size: size), operation: .copy, fraction: 1.0)
            thumb.unlockFocus()
            await MainActor.run { self.nsImage = thumb }
            return
        }

        let textExts: Set<String> = ["txt", "csv", "json", "xml", "html", "md"]
        if textExts.contains(ext) {
            if let s = String(data: data.prefix(32_768), encoding: .utf8) ?? String(data: data.prefix(32_768), encoding: .ascii) {
                await MainActor.run { self.previewText = s }
                return
            }
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
        await MainActor.run { self.previewText = lines.joined(separator: "\n") }
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
                    Button("Images") { vm.settings.enabledTypes.formUnion(images) }
                    Button("Audio") { vm.settings.enabledTypes.formUnion(audio) }
                    Button("Video") { vm.settings.enabledTypes.formUnion(video) }
                    Button("Archives") { vm.settings.enabledTypes.formUnion(archives) }
                    Button("All") { vm.settings.enabledTypes = all }
                }
                .buttonStyle(.bordered)

                HStack {
                    Button("Only Images") { vm.settings.enabledTypes = images }
                    Button("Only Audio") { vm.settings.enabledTypes = audio }
                    Button("Only Video") { vm.settings.enabledTypes = video }
                    Button("Only Archives") { vm.settings.enabledTypes = archives }
                }
                .buttonStyle(.bordered)
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

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Forensic Summary").font(.title3.bold())
                if let run = vm.activeRun {
                    let f = run.forensic
                    let metrics = f.metrics ?? [:]
                    HStack {
                        SummaryCard(title: ".REM Files", value: "\(f.remCount)")
                        SummaryCard(title: "Media Recovered", value: "\(f.mediaCount)")
                        SummaryCard(title: "Possible Decryptable DBs", value: "\(f.possibleDecryptableDBs)")
                        SummaryCard(title: "Nested Archives", value: "\(f.nestedArchives)")
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    HStack {
                        SummaryCard(title: "Decryptable Signals", value: "\(metrics["decryptable"] ?? 0)")
                        SummaryCard(title: "Thumbnails", value: "\(metrics["thumbnails"] ?? 0)")
                        SummaryCard(title: "Message Signals", value: "\(metrics["messages"] ?? 0)")
                        SummaryCard(title: "Keys", value: "\(max(metrics["keys"] ?? 0, f.keyFiles.count))")
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    HStack {
                        SummaryCard(title: "Emails", value: "\(metrics["emails"] ?? 0)")
                        SummaryCard(title: "URLs", value: "\(metrics["urls"] ?? 0)")
                        SummaryCard(title: "Phones", value: "\(metrics["phones"] ?? 0)")
                        SummaryCard(title: "Language Text", value: "\(metrics["language_signals"] ?? 0)")
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    HStack {
                        SummaryCard(title: "Hash Candidates", value: "\(metrics["hash_candidates"] ?? 0)")
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    HStack {
                        SummaryCard(title: "AI Safe", value: "\(aiCount(.none, in: f.analyzerResults))")
                        SummaryCard(title: "AI Suggestive", value: "\(aiCount(.suggestive, in: f.analyzerResults))")
                        SummaryCard(title: "AI Explicit", value: "\(aiCount(.explicit, in: f.analyzerResults))")
                        SummaryCard(title: "AI Unknown", value: "\(aiCount(.unknown, in: f.analyzerResults))")
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

                    GroupBox("Keys Found") {
                        if f.keyFiles.isEmpty { Text("None").foregroundStyle(.secondary) }
                        else { ForEach(f.keyFiles, id: \.self) { Text($0).lineLimit(1) } }
                    }

                    GroupBox("AI Reason Tags") {
                        let tags = topReasonTags(in: f.analyzerResults)
                        if tags.isEmpty {
                            Text("No reason tags yet.").foregroundStyle(.secondary)
                        } else {
                            FlowTagView(tags: tags)
                        }
                    }

                    GroupBox("Analyzer Outputs") {
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
                                }
                                .padding(.vertical, 2)
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

    private func aiCount(_ severity: NSFWSeverity, in results: [AnalyzerResult]) -> Int {
        results.filter { $0.nsfwSeverity == severity }.count
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

    private func topReasonTags(in results: [AnalyzerResult]) -> [(String, Int)] {
        var counts: [String: Int] = [:]
        for result in results {
            for det in result.reasonDetections ?? [] {
                let key = det.reason.rawValue
                counts[key, default: 0] += 1
            }
        }
        return counts
            .sorted { lhs, rhs in
                if lhs.value == rhs.value { return lhs.key < rhs.key }
                return lhs.value > rhs.value
            }
            .prefix(18)
            .map { ($0.key, $0.value) }
    }
}

private struct FlowTagView: View {
    let tags: [(String, Int)]

    var body: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 120), spacing: 8)], spacing: 8) {
            ForEach(tags, id: \.0) { tag, count in
                HStack(spacing: 6) {
                    Text(tag.replacingOccurrences(of: "_", with: " ").capitalized)
                    Text("\(count)")
                        .font(.caption2.bold())
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(Color.gray.opacity(0.18)))
                }
                .font(.caption)
                .padding(.horizontal, 8)
                .padding(.vertical, 6)
                .background(RoundedRectangle(cornerRadius: 8).fill(Color.gray.opacity(0.10)))
            }
        }
    }
}

private struct SummaryCard: View {
    let title: String
    let value: String
    var body: some View {
        VStack {
            Text(title)
                .font(.caption)
                .foregroundStyle(AppTheme.mutedText)
            Text(value)
                .font(.title2.bold())
                .foregroundStyle(AppTheme.text)
        }
            .frame(width: 180, height: 80)
            .forensicSummaryCardStyle()
    }
}

private struct ScanRadarView: View {
    let progress: Double
    let isScanning: Bool

    @State private var sweepDegrees: Double = 0
    @State private var glowOpacity: Double = 0.55

    private var percentLabel: String {
        "\(Int((progress * 100).rounded()))%"
    }

    var body: some View {
        GeometryReader { geo in
            let size = min(geo.size.width, geo.size.height)
            let ringLine = max(3, size * 0.02)
            let innerSize = size * 0.50
            let sweepRotation = sweepDegrees - 100

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
        .onAppear { updateAnimation() }
        .onChange(of: isScanning) { _, _ in
            updateAnimation()
        }
    }

    private func updateAnimation() {
        if isScanning {
            sweepDegrees = 0
            withAnimation(.linear(duration: 2.4).repeatForever(autoreverses: false)) {
                sweepDegrees = 360
            }
            withAnimation(.easeInOut(duration: 1.1).repeatForever(autoreverses: true)) {
                glowOpacity = 0.92
            }
        } else {
            sweepDegrees = 0
            glowOpacity = 0.35
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

#endif
