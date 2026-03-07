import SwiftUI
import AppKit
#if canImport(CoreML)
import CoreML
#endif

@main
struct JuiceLabProApp: App {
    @StateObject private var viewModel = AppViewModel()

    var body: some Scene {
        WindowGroup {
            StartupHostView()
                .environmentObject(viewModel)
                .frame(minWidth: 1200, minHeight: 760)
        }
        .windowStyle(.automatic)
        .commands {
            CommandMenu("JuiceLabPro") {
                Button("Command Palette") {
                    viewModel.commandPalettePresented = true
                }
                .keyboardShortcut("k", modifiers: [.command])
            }
        }
    }
}

private struct StartupHostView: View {
    @EnvironmentObject private var vm: AppViewModel
    @State private var bootPhase: BootPhase = .splash
    @State private var progress: Double = 0.0
    @State private var statusText = "Initializing workspace…"
    @State private var spin = false
    @State private var pulse = false
    @State private var sweep = false
    private let hasSplashAsset = NSImage(named: "JuiceLabPro_splash") != nil

    private enum BootPhase {
        case splash
        case loadingModels
        case ready
    }

    var body: some View {
        Group {
            if bootPhase == .ready {
                MainSplitView()
            } else {
                ZStack {
                    LinearGradient(
                        colors: [Color.black, Color(red: 0.03, green: 0.03, blue: 0.09)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                    .ignoresSafeArea()

                    VStack(spacing: 20) {
                        if hasSplashAsset {
                            ZStack {
                                Circle()
                                    .stroke(
                                        AngularGradient(
                                            colors: [
                                                AppTheme.primary.opacity(0.0),
                                                AppTheme.primary.opacity(0.78),
                                                Color.cyan.opacity(0.62),
                                                AppTheme.primary.opacity(0.0)
                                            ],
                                            center: .center
                                        ),
                                        lineWidth: 5
                                    )
                                    .frame(width: 250, height: 250)
                                    .rotationEffect(.degrees(spin ? 360 : 0))
                                    .blur(radius: 0.5)

                                Circle()
                                    .stroke(
                                        AngularGradient(
                                            colors: [
                                                Color.cyan.opacity(0.0),
                                                Color.cyan.opacity(0.58),
                                                AppTheme.primary.opacity(0.42),
                                                Color.cyan.opacity(0.0)
                                            ],
                                            center: .center
                                        ),
                                        lineWidth: 2
                                    )
                                    .frame(width: 236, height: 236)
                                    .rotationEffect(.degrees(spin ? -360 : 0))

                                Circle()
                                    .stroke(AppTheme.primary.opacity(0.22), lineWidth: 1.5)
                                    .frame(width: 266, height: 266)
                                    .scaleEffect(pulse ? 1.028 : 0.972)
                                    .opacity(pulse ? 0.66 : 0.38)

                                Image("JuiceLabPro_splash")
                                    .resizable()
                                    .scaledToFit()
                                    .frame(width: 260, height: 260)
                                    .scaleEffect(pulse ? 1.015 : 0.985)
                                    .overlay(
                                        GeometryReader { geo in
                                            let w = geo.size.width
                                            Rectangle()
                                                .fill(
                                                    LinearGradient(
                                                        colors: [
                                                            Color.clear,
                                                            Color.white.opacity(0.18),
                                                            Color.cyan.opacity(0.14),
                                                            Color.clear
                                                        ],
                                                        startPoint: .top,
                                                        endPoint: .bottom
                                                    )
                                                )
                                                .frame(width: max(34, w * 0.21))
                                                .rotationEffect(.degrees(-16))
                                                .offset(x: sweep ? w * 0.95 : -w * 0.95)
                                                .blendMode(.screen)
                                        }
                                        .mask(
                                            Image("JuiceLabPro_splash")
                                                .resizable()
                                                .scaledToFit()
                                        )
                                    )
                            }
                            .animation(.linear(duration: 13.5).repeatForever(autoreverses: false), value: spin)
                            .animation(.easeInOut(duration: 2.6).repeatForever(autoreverses: true), value: pulse)
                            .animation(.linear(duration: 1.55).repeatForever(autoreverses: false), value: sweep)
                        } else {
                            ZStack {
                                Circle()
                                    .stroke(AppTheme.primary.opacity(0.35), lineWidth: 5)
                                    .frame(width: 160, height: 160)
                                    .rotationEffect(.degrees(spin ? 360 : 0))
                                    .animation(.linear(duration: 18).repeatForever(autoreverses: false), value: spin)
                                Image(nsImage: NSApp.applicationIconImage)
                                    .resizable()
                                    .scaledToFit()
                                    .frame(width: 84, height: 84)
                            }
                        }

                        Text("JuiceLabPro")
                            .font(.system(size: 54, weight: .bold, design: .rounded))
                            .foregroundStyle(.white)
                        Text("AI Forensics Intelligence")
                            .font(.title3)
                            .foregroundStyle(.secondary)

                        if bootPhase == .loadingModels {
                            VStack(spacing: 8) {
                                ProgressView(value: progress, total: 1)
                                    .progressViewStyle(.linear)
                                    .frame(width: 360)
                                Text(statusText)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                .task {
                    spin = true
                    pulse = true
                    sweep = true
                    await runStartupSequence()
                }
            }
        }
    }

    private func runStartupSequence() async {
        try? await Task.sleep(nanoseconds: 950_000_000)
        bootPhase = .loadingModels

        let modelChecks: [(String, String)] = [
            ("NSFWDetector", "mlmodelc"),
            ("NSFWReasons", "mlmodelc")
        ]

        let step = 1.0 / Double(max(modelChecks.count + 1, 1))
        for (name, ext) in modelChecks {
            statusText = "Warming \(name)…"
            let ok = await Self.warmupModel(name: name, ext: ext)
            if !ok {
                statusText = "Model \(name) not found or failed to warm."
            }
            progress = min(progress + step, 0.95)
            try? await Task.sleep(nanoseconds: 220_000_000)
        }

        statusText = "Preparing studio interface…"
        progress = 1.0
        try? await Task.sleep(nanoseconds: 260_000_000)

        bootPhase = .ready
        vm.route = .results
    }

    private nonisolated static func warmupModel(name: String, ext: String) async -> Bool {
        guard let url = Bundle.main.url(forResource: name, withExtension: ext) else { return false }
        #if canImport(CoreML)
        do {
            let cfg = MLModelConfiguration()
            _ = try MLModel(contentsOf: url, configuration: cfg)
            return true
        } catch {
            return false
        }
        #else
        return FileManager.default.fileExists(atPath: url.path)
        #endif
    }
}
