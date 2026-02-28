import SwiftUI
import SecuPersoFeatures

@MainActor
final class AppBootstrapState: ObservableObject {
    @Published var viewModel: SecurityConsoleViewModel?
    @Published var exposureViewModel: ExposureViewModel?
    @Published var errorMessage: String?

    init() {
        do {
            let container = try AppContainer()
            self.viewModel = container.viewModel
            self.exposureViewModel = container.exposureViewModel
        } catch {
            self.errorMessage = error.localizedDescription
            self.viewModel = nil
            self.exposureViewModel = nil
        }
    }
}

@main
struct SecuPersoApp: App {
    @StateObject private var bootstrap = AppBootstrapState()

    var body: some Scene {
        WindowGroup {
            if let viewModel = bootstrap.viewModel, let exposureViewModel = bootstrap.exposureViewModel {
                SecurityConsoleView(viewModel: viewModel, exposureViewModel: exposureViewModel)
            } else {
                VStack(alignment: .leading, spacing: 12) {
                    Text("SecuPerso failed to bootstrap")
                        .font(.title2.weight(.semibold))
                    Text(bootstrap.errorMessage ?? "Unknown startup error")
                        .foregroundStyle(.secondary)
                    Text("Check fixture files and Keychain access, then relaunch.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(24)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
        }
    }
}
