import SwiftUI
import SecuPersoDomain
import SecuPersoUI

struct SettingsScreen: View {
    @ObservedObject var viewModel: SecurityConsoleViewModel

    var body: some View {
        Form {
            Section("Exposure Data Source (HIBP v3)") {
                SecureField("API Key", text: $viewModel.exposureSourceAPIKey)
                TextField("Email", text: $viewModel.exposureSourceEmail)
                TextField("User-Agent", text: $viewModel.exposureSourceUserAgent)

                HStack {
                    Text(viewModel.exposureSourceConfigured ? "Configured" : "Missing API key or email")
                        .font(.caption)
                        .foregroundStyle(viewModel.exposureSourceConfigured ? .green : .secondary)
                    Spacer()
                    Button("Save") {
                        viewModel.saveExposureSourceConfiguration()
                    }
                }

                Text("Uses Have I Been Pwned API v3 to fetch breaches for the configured email.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Mock Login Scenario") {
                Picker("Scenario", selection: Binding(
                    get: { viewModel.scenario },
                    set: { newScenario in
                        guard viewModel.scenario != newScenario else {
                            return
                        }
                        viewModel.setScenario(newScenario)
                    }
                )) {
                    ForEach(FixtureScenario.allCases, id: \.self) { scenario in
                        Text(scenario.title).tag(scenario)
                    }
                }
                Text("Switches deterministic fixture set used for login activity and incidents.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Connected Providers") {
                ForEach(viewModel.providers) { provider in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(provider.displayName)
                            Text(provider.details)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text((viewModel.providerStates[provider.id] ?? .disconnected).rawValue.capitalized)
                            .font(.caption)
                            .foregroundStyle(.secondary)

                        if (viewModel.providerStates[provider.id] ?? .disconnected) == .connected {
                            Button("Disconnect") {
                                viewModel.disconnect(provider: provider.id)
                            }
                        } else {
                            Button("Connect") {
                                viewModel.beginConnectFlow(for: provider.id)
                            }
                        }
                    }
                }
            }

            Section("Data Security") {
                Text("Local data is encrypted and stored in SQLite. Encryption key is persisted in Keychain entry com.secuperso.app.db-key.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(DesignTokens.spacingL)
    }
}
