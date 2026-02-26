import SwiftUI

@main
struct JuiceLabProApp: App {
    @StateObject private var viewModel = AppViewModel()

    var body: some Scene {
        WindowGroup {
            MainSplitView()
                .environmentObject(viewModel)
                .frame(minWidth: 1200, minHeight: 760)
        }
        .windowStyle(.automatic)
    }
}
