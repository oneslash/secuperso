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
                Text("SecuPerso stores monitoring data locally and keeps setup intentionally focused on provider trust and exposure checks.")
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
                    Label(
                        exposureSourceConfigured ? "Configured" : "Missing API key",
                        systemImage: exposureSourceConfigured ? "checkmark.circle.fill" : "exclamationmark.circle"
                    )
                    .foregroundStyle(exposureSourceConfigured ? .green : .secondary)
                    Spacer()
                    Button {
                        exposureViewModel.exposureSourceAPIKey = exposureSourceAPIKeyDraft
                        exposureViewModel.exposureSourceUserAgent = exposureSourceUserAgentDraft
                        exposureViewModel.saveExposureSourceConfiguration()
                    } label: {
                        if exposureViewModel.isSavingConfiguration {
                            HStack(spacing: 6) {
                                ProgressView()
                                    .controlSize(.small)
                                Text("Saving")
                            }
                        } else {
                            Text("Save")
                        }
                    }
                    .disabled(!canSaveExposureSourceConfiguration)
                }

                if let feedback = exposureViewModel.configurationFeedback {
                    HStack(spacing: 8) {
                        Image(systemName: feedbackSymbol(feedback))
                            .foregroundStyle(feedbackColor(feedback))

                        Text(feedback.message)
                            .foregroundStyle(.primary)

                        Spacer()

                        Button("Dismiss") {
                            exposureViewModel.clearConfigurationFeedback()
                        }
                        .buttonStyle(.plain)
                    }
                    .padding(.vertical, 4)
                }

                Text("Uses Have I Been Pwned API v3 for breach checks. Keep the User-Agent present and identifiable when configuring production credentials.")
                    .foregroundStyle(.secondary)
            }

            Section("Mock Login Scenario") {
                Picker("Scenario", selection: $scenarioDraft) {
                    ForEach(FixtureScenario.allCases, id: \.self) { scenario in
                        Text(scenario.title).tag(scenario)
                    }
                }
                .accessibilityLabel("Scenario")

                Text("Switches deterministic fixture sets used for demo sign-in and incident data without changing the app structure.")
                    .foregroundStyle(.secondary)
            }

            Section("Data Security") {
                Text("Local data is encrypted in SQLite. The encryption key is stored in Keychain entry com.secuperso.app.db-key, and provider credentials should stay in the secure store.")
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

    private var canSaveExposureSourceConfiguration: Bool {
        !exposureSourceUserAgentDraft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
            !exposureViewModel.isSavingConfiguration
    }

    private func syncDraftsFromViewModel() {
        exposureSourceAPIKeyDraft = exposureViewModel.exposureSourceAPIKey
        exposureSourceUserAgentDraft = exposureViewModel.exposureSourceUserAgent
    }

    private func feedbackSymbol(_ feedback: OperationFeedback) -> String {
        switch feedback.tone {
        case .info:
            return "info.circle.fill"
        case .success:
            return "checkmark.circle.fill"
        case .warning:
            return "exclamationmark.circle.fill"
        case .error:
            return "xmark.octagon.fill"
        }
    }

    private func feedbackColor(_ feedback: OperationFeedback) -> Color {
        switch feedback.tone {
        case .info, .success:
            return .green
        case .warning:
            return .orange
        case .error:
            return .red
        }
    }
}
