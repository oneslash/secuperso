import SwiftUI
import SecuPersoDomain
import SecuPersoUI

struct SettingsScreen: View {
    @ObservedObject var viewModel: SecurityConsoleViewModel
    @ObservedObject var exposureViewModel: ExposureViewModel
    @State private var advancedExpanded = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: DesignTokens.spacingL) {
                SectionContainer(title: "General") {
                    Text("SecuPerso stores your monitoring data locally and keeps setup intentionally simple.")
                        .font(.subheadline)
                        .foregroundStyle(DesignTokens.mutedForeground)
                }

                SectionContainer {
                    DisclosureGroup("Advanced", isExpanded: $advancedExpanded) {
                        advancedContent
                            .padding(.top, DesignTokens.spacingS)
                    }
                    .font(.headline)
                }
            }
            .padding(DesignTokens.spacingL)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(DesignTokens.appBackground)
    }

    @ViewBuilder
    private var advancedContent: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingM) {
            VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                Text("Exposure Data Source (HIBP v3)")
                    .font(.headline)

                Text("API Key")
                    .font(.caption)
                    .foregroundStyle(DesignTokens.mutedForeground)
                SecureField("API Key", text: $exposureViewModel.exposureSourceAPIKey)
                    .textFieldStyle(.roundedBorder)

                Text("User-Agent")
                    .font(.caption)
                    .foregroundStyle(DesignTokens.mutedForeground)
                TextField("User-Agent", text: $exposureViewModel.exposureSourceUserAgent)
                    .textFieldStyle(.roundedBorder)

                HStack {
                    Text(exposureViewModel.exposureSourceConfigured ? "Configured" : "Missing API key")
                        .font(.caption)
                        .foregroundStyle(exposureViewModel.exposureSourceConfigured ? .green : DesignTokens.mutedForeground)
                    Spacer()
                    Button("Save") {
                        exposureViewModel.saveExposureSourceConfiguration()
                    }
                }

                if let inlineStatusMessage = exposureViewModel.inlineStatusMessage {
                    Text(inlineStatusMessage)
                        .font(.caption)
                        .foregroundStyle(.orange)
                }

                Text("Uses Have I Been Pwned API v3 for breach checks.")
                    .font(.caption)
                    .foregroundStyle(DesignTokens.mutedForeground)
            }

            Divider()

            VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                Text("Mock Login Scenario")
                    .font(.headline)

                Picker(
                    "Scenario",
                    selection: Binding(
                        get: { viewModel.scenario },
                        set: { newScenario in
                            guard viewModel.scenario != newScenario else { return }
                            viewModel.setScenario(newScenario)
                        }
                    )
                ) {
                    ForEach(FixtureScenario.allCases, id: \.self) { scenario in
                        Text(scenario.title).tag(scenario)
                    }
                }
                .labelsHidden()
                .frame(maxWidth: 220, alignment: .leading)

                Text("Switches deterministic fixture sets used for demo sign-in and incident data.")
                    .font(.caption)
                    .foregroundStyle(DesignTokens.mutedForeground)
            }

            Divider()

            VStack(alignment: .leading, spacing: DesignTokens.spacingXS) {
                Text("Data Security")
                    .font(.headline)
                Text("Local data is encrypted in SQLite. The encryption key is stored in Keychain entry com.secuperso.app.db-key.")
                    .font(.caption)
                    .foregroundStyle(DesignTokens.mutedForeground)
            }
        }
    }
}
