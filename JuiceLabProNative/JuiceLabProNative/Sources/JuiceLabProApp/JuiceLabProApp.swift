import SwiftUI
import AppKit

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
                                                AppTheme.primary.opacity(0.9),
                                                Color.cyan.opacity(0.8),
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
                                    .stroke(AppTheme.primary.opacity(0.22), lineWidth: 1.5)
                                    .frame(width: 266, height: 266)
                                    .scaleEffect(pulse ? 1.04 : 0.96)
                                    .opacity(pulse ? 0.75 : 0.35)

                                Image("JuiceLabPro_splash")
                                    .resizable()
                                    .scaledToFit()
                                    .frame(width: 260, height: 260)
                                    .scaleEffect(pulse ? 1.015 : 0.985)
                            }
                            .animation(.linear(duration: 16).repeatForever(autoreverses: false), value: spin)
                            .animation(.easeInOut(duration: 2.0).repeatForever(autoreverses: true), value: pulse)
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
                    await runStartupSequence()
                }
            }
        }
    }

    private func runStartupSequence() async {
        try? await Task.sleep(nanoseconds: 850_000_000)
        bootPhase = .loadingModels

        let modelChecks: [(String, String)] = [
            ("NSFWDetector", "mlmodelc"),
            ("NSFWReasons", "mlmodelc")
        ]

        let step = 1.0 / Double(max(modelChecks.count + 1, 1))
        for (name, ext) in modelChecks {
            statusText = "Loading \(name)…"
            _ = Bundle.main.url(forResource: name, withExtension: ext)
            progress = min(progress + step, 0.95)
            try? await Task.sleep(nanoseconds: 380_000_000)
        }

        statusText = "Preparing studio interface…"
        progress = 1.0
        try? await Task.sleep(nanoseconds: 260_000_000)

        bootPhase = .ready
        vm.route = .results
    }
}
