import SwiftUI

@main
struct JuiceLabProApp: App {
    @StateObject private var viewModel = AppViewModel()

    init() {
        if let url = Bundle.main.url(forResource: "NSFWDetector", withExtension: "mlmodelc") {
            print("✅ NSFWDetector model found at:", url.path)
        } else {
            print("❌ NSFWDetector model NOT found in bundle")
        }
    }

    var body: some Scene {
        WindowGroup {
            MainSplitView()
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
