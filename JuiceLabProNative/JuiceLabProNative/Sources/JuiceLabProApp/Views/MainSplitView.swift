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
        case .forensic: return "shield.lefthalf.filled"
        case .settings: return "gearshape"
        }
    }
}

private struct ToolbarView: View {
    @EnvironmentObject private var vm: AppViewModel
    @State private var showClearResultsDialog = false

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

            Button("Clear Sources") {
                vm.clearSources()
            }
            .disabled(vm.isScanning || vm.droppedURLs.isEmpty)

            Button("Start") { vm.startScan() }
                .buttonStyle(.borderedProminent)
                .disabled(vm.isScanning || vm.droppedURLs.isEmpty)

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

            Button("Clear Results") {
                showClearResultsDialog = true
            }
            .disabled(vm.isScanning || vm.runs.isEmpty)
            .foregroundStyle(.red)
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
}

private struct ResultsTableView: View {
    @EnvironmentObject private var vm: AppViewModel
    let items: [FoundItem]
    @State private var sortedItems: [FoundItem] = []
    @State private var sortField: SortField = .type
    @State private var sortAscending: Bool = true

    private enum SortField: String, CaseIterable, Identifiable {
        case type
        case source
        case offset
        case validation
        case size

        var id: String { rawValue }

        var title: String {
            switch self {
            case .type: return "Type"
            case .source: return "Source"
            case .offset: return "Offset"
            case .validation: return "Validation"
            case .size: return "Size"
            }
        }
    }

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
            HStack(spacing: 8) {
                Text("Sort by:")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Picker("Sort by", selection: $sortField) {
                    ForEach(SortField.allCases) { field in
                        Text(field.title).tag(field)
                    }
                }
                .pickerStyle(.menu)
                Toggle("Ascending", isOn: $sortAscending)
                    .toggleStyle(.checkbox)
                    .font(.caption)
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
        ) {
            TableColumn("Type") { item in
                Text(item.detectedType.uppercased())
            }
            TableColumn("Source") { item in
                Text(item.sourceDisplayName)
            }
            TableColumn("Offset") { item in
                Text(String(format: "0x%X", item.offset))
            }
            TableColumn("Validation") { item in
                Text(item.validationText.capitalized)
            }
            TableColumn("Size") { item in
                Text(ByteCountFormatter.string(fromByteCount: Int64(item.length), countStyle: .file))
            }
        }
        .onAppear {
            applySort()
        }
        .onChange(of: items) { _, _ in
            applySort()
        }
        .onChange(of: sortField) { _, _ in
            applySort()
        }
        .onChange(of: sortAscending) { _, _ in
            applySort()
        }
    }

    private func applySort() {
        let sorted = items.sorted { lhs, rhs in
            let result: Bool
            switch sortField {
            case .type:
                result = lhs.detectedType.localizedCaseInsensitiveCompare(rhs.detectedType) == .orderedAscending
            case .source:
                result = lhs.sourceDisplayName.localizedCaseInsensitiveCompare(rhs.sourceDisplayName) == .orderedAscending
            case .offset:
                result = lhs.offset < rhs.offset
            case .validation:
                result = lhs.validationText.localizedCaseInsensitiveCompare(rhs.validationText) == .orderedAscending
            case .size:
                result = lhs.length < rhs.length
            }
            return sortAscending ? result : !result
        }
        sortedItems = sorted
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
                Text("Hash").tag(DedupeMode.hash)
                Text("Hash + Size").tag(DedupeMode.hashAndSize)
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
                        }
                        .buttonStyle(.bordered)
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
        VStack { Text(title).font(.caption).foregroundStyle(.secondary); Text(value).font(.title2.bold()) }
            .frame(width: 180, height: 80)
            .background(RoundedRectangle(cornerRadius: 12).fill(Color.gray.opacity(0.12)))
    }
}

#endif
