import SwiftUI
import SecuPersoDomain

public struct SettingsScreen: View {
    let viewModel: SecurityConsoleViewModel
    @ObservedObject var exposureViewModel: ExposureViewModel
    @State private var scenarioDraft: FixtureScenario = .moderate
    @State private var exposureSourceAPIKeyDraft: String = ""
    @State private var exposureSourceUserAgentDraft: String = "SecuPersoApp/1.0"

    public init(viewModel: SecurityConsoleViewModel, exposureViewModel: ExposureViewModel) {
        self.viewModel = viewModel
        self.exposureViewModel = exposureViewModel
    }

    public var body: some View {
        Form {
            Section("General") {
                Text("SecuPerso stores your monitoring data locally and keeps setup intentionally simple.")
                    .foregroundStyle(.secondary)
            }

            Section("Exposure Data Source (HIBP v3)") {
                SecureField("API Key", text: $exposureSourceAPIKeyDraft)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled(true)
                    .accessibilityLabel("API Key")

                TextField("User-Agent", text: $exposureSourceUserAgentDraft)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled(true)
                    .accessibilityLabel("User-Agent")

                HStack {
                    Text(exposureSourceConfigured ? "Configured" : "Missing API key")
                        .foregroundStyle(exposureSourceConfigured ? .green : .secondary)
                    Spacer()
                    Button("Save") {
                        exposureViewModel.exposureSourceAPIKey = exposureSourceAPIKeyDraft
                        exposureViewModel.exposureSourceUserAgent = exposureSourceUserAgentDraft
                        exposureViewModel.saveExposureSourceConfiguration()
                    }
                }

                if let inlineStatusMessage = exposureViewModel.inlineStatusMessage {
                    Text(inlineStatusMessage)
                        .foregroundStyle(.orange)
                }

                Text("Uses Have I Been Pwned API v3 for breach checks.")
                    .foregroundStyle(.secondary)
            }

            Section("Mock Login Scenario") {
                Picker("Scenario", selection: $scenarioDraft) {
                    ForEach(FixtureScenario.allCases, id: \.self) { scenario in
                        Text(scenario.title).tag(scenario)
                    }
                }
                .accessibilityLabel("Scenario")

                Text("Switches deterministic fixture sets used for demo sign-in and incident data.")
                    .foregroundStyle(.secondary)
            }

            Section("Data Security") {
                Text("Local data is encrypted in SQLite. The encryption key is stored in Keychain entry com.secuperso.app.db-key.")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .padding(20)
        .frame(minWidth: 620, minHeight: 420, alignment: .topLeading)
        .onAppear {
            syncDraftsFromViewModel()
            scenarioDraft = viewModel.scenario
        }
        .onChange(of: scenarioDraft) { _, newScenario in
            guard newScenario != viewModel.scenario else { return }
            Task { @MainActor in
                viewModel.setScenario(newScenario)
            }
        }
    }

    private var exposureSourceConfigured: Bool {
        !exposureSourceAPIKeyDraft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private func syncDraftsFromViewModel() {
        exposureSourceAPIKeyDraft = exposureViewModel.exposureSourceAPIKey
        exposureSourceUserAgentDraft = exposureViewModel.exposureSourceUserAgent
    }
}
