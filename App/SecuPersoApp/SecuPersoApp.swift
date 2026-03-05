import SwiftUI
import SecuPersoFeatures

@MainActor
final class AppBootstrapState: ObservableObject {
    @Published var viewModel: SecurityConsoleViewModel?
    @Published var exposureViewModel: ExposureViewModel?
    @Published var errorMessage: String?
    @Published var isBootstrapping = false

    private var started = false

    func startIfNeeded() {
        guard !started else {
            return
        }

        started = true
        scheduleBootstrap()
    }

    func retry() {
        scheduleBootstrap()
    }

    private func scheduleBootstrap() {
        Task { @MainActor [weak self] in
            await Task.yield()
            self?.bootstrap()
        }
    }

    private func bootstrap() {
        isBootstrapping = true
        errorMessage = nil
        viewModel = nil
        exposureViewModel = nil

        Task { @MainActor [weak self] in
            guard let self else {
                return
            }

            do {
                let container = try AppContainer()
                self.viewModel = container.viewModel
                self.exposureViewModel = container.exposureViewModel
            } catch {
                self.errorMessage = error.localizedDescription
            }

            self.isBootstrapping = false
        }
    }
}

@main
struct SecuPersoApp: App {
    @StateObject private var bootstrap = AppBootstrapState()
    @State private var selectedSection: AppSection = .overview

    var body: some Scene {
        WindowGroup {
            Group {
                if let viewModel = bootstrap.viewModel, let exposureViewModel = bootstrap.exposureViewModel {
                    SecurityConsoleView(
                        viewModel: viewModel,
                        exposureViewModel: exposureViewModel,
                        selectedSection: $selectedSection
                    )
                } else {
                    BootstrapShellView(
                        isBootstrapping: bootstrap.isBootstrapping,
                        errorMessage: bootstrap.errorMessage,
                        retry: bootstrap.retry
                    )
                }
            }
            .onAppear {
                bootstrap.startIfNeeded()
            }
        }
        .commands {
            SecurityConsoleCommands(
                viewModel: bootstrap.viewModel,
                selectedSection: $selectedSection
            )
        }
        Settings {
            if let viewModel = bootstrap.viewModel, let exposureViewModel = bootstrap.exposureViewModel {
                SettingsScreen(viewModel: viewModel, exposureViewModel: exposureViewModel)
            } else {
                Text("Settings unavailable during bootstrap.")
                    .foregroundStyle(.secondary)
                    .padding(24)
            }
        }
    }
}

private struct BootstrapShellView: View {
    let isBootstrapping: Bool
    let errorMessage: String?
    let retry: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("SecuPerso")
                .font(.title2.weight(.semibold))

            if isBootstrapping {
                ProgressView("Preparing secure workspace...")
                    .controlSize(.small)
                Text("Loading fixtures, encryption, and data services.")
                    .foregroundStyle(.secondary)
            } else if let errorMessage {
                Text("Bootstrap failed")
                    .font(.headline)
                Text(errorMessage)
                    .foregroundStyle(.secondary)
                Button("Retry") {
                    retry()
                }
                .buttonStyle(.borderedProminent)
            } else {
                ProgressView("Preparing secure workspace...")
                    .controlSize(.small)
            }
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

private struct SecurityConsoleCommands: Commands {
    let viewModel: SecurityConsoleViewModel?
    @Binding var selectedSection: AppSection

    var body: some Commands {
        CommandMenu("Security") {
            Button("Refresh Security Data") {
                Task {
                    await viewModel?.refreshAll()
                }
            }
            .keyboardShortcut("r", modifiers: [.command])
            .disabled(viewModel == nil)

            Divider()

            Button("Show Overview") {
                selectedSection = .overview
            }
            .keyboardShortcut("1", modifiers: [.command])
            .disabled(viewModel == nil)

            Button("Show Activity") {
                selectedSection = .activity
            }
            .keyboardShortcut("2", modifiers: [.command])
            .disabled(viewModel == nil)

            Button("Show Exposure") {
                selectedSection = .exposure
            }
            .keyboardShortcut("3", modifiers: [.command])
            .disabled(viewModel == nil)

            Button("Show Integrations") {
                selectedSection = .integrations
            }
            .keyboardShortcut("4", modifiers: [.command])
            .disabled(viewModel == nil)
        }
    }
}
