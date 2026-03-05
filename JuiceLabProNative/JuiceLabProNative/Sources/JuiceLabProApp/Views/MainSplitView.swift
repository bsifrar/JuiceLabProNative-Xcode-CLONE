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
            
            Button("Reveal Run Folder") {
                if let run = vm.activeRun {
                    let url = URL(fileURLWithPath: run.outputRoot)
                    NSWorkspace.shared.open(url)
                } else {
                    let url = URL(fileURLWithPath: vm.settings.outputFolder)
                    NSWorkspace.shared.open(url)
                }
            }
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
                GroupBox("Preview") {
                    PreviewView(item: item)
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
        .task { await loadPreview() }
    }

    private func loadPreview() async {
        let path = item.outputPath ?? item.sourcePath
        let url = URL(fileURLWithPath: path)
        guard FileManager.default.fileExists(atPath: path) else {
            await MainActor.run { self.previewText = "File not found" }
            return
        }
        #if canImport(AppKit)
        let scoped = url.startAccessingSecurityScopedResource()
        defer {
            if scoped { url.stopAccessingSecurityScopedResource() }
        }
        #endif
        do {
            let data = try Data(contentsOf: url, options: .mappedIfSafe)

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
        } catch {
            let message = "Preview failed: \(error.localizedDescription). If this is a source file, try exporting the item first and previewing the exported file."
            await MainActor.run { self.previewText = message }
        }
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
                let all = Set(SignatureRegistry.signatures.map { $0.type })
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

private struct ForensicDashboardView: View {
    @EnvironmentObject private var vm: AppViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Forensic Summary").font(.title3.bold())
            if let run = vm.activeRun {
                let f = run.forensic
                HStack {
                    SummaryCard(title: ".REM Files", value: "\(f.remCount)")
                    SummaryCard(title: "Media Recovered", value: "\(f.mediaCount)")
                    SummaryCard(title: "Possible Decryptable DBs", value: "\(f.possibleDecryptableDBs)")
                    SummaryCard(title: "Nested Archives", value: "\(f.nestedArchives)")
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                GroupBox("Keys Found") {
                    if f.keyFiles.isEmpty { Text("None").foregroundStyle(.secondary) }
                    else { ForEach(f.keyFiles, id: \.self) { Text($0).lineLimit(1) } }
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
            Spacer()
        }
        .cardSurface()
        .padding(.vertical)
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
