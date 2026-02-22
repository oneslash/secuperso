import SwiftUI
import SecuPersoUI

struct LoginActivityScreen: View {
    @ObservedObject var viewModel: SecurityConsoleViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingL) {
            VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                Text("Sign-in Activity")
                    .font(.headline)
                List(viewModel.loginEvents) { event in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("\(event.provider.displayName) • \(event.occurredAt, style: .time)")
                                .font(.subheadline.weight(.semibold))
                            Spacer()
                            if event.suspicious || !event.expected {
                                Text("Suspicious")
                                    .font(.caption.weight(.bold))
                                    .foregroundStyle(.red)
                            } else {
                                Text("Expected")
                                    .font(.caption.weight(.bold))
                                    .foregroundStyle(.green)
                            }
                        }

                        Text("\(event.location) • \(event.device) • \(event.ipAddress)")
                            .font(.caption)
                            .foregroundStyle(.secondary)

                        Text(event.reason)
                            .font(.caption)

                        HStack {
                            Button("Mark as me") {
                                viewModel.markAsMe(event)
                            }
                            Button("Create incident") {
                                viewModel.createIncident(for: event)
                            }
                        }
                    }
                    .padding(.vertical, 4)
                }
                .frame(minHeight: 270)
            }

            VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                Text("Incidents")
                    .font(.headline)
                if viewModel.incidents.isEmpty {
                    Text("No incidents yet.")
                        .foregroundStyle(.secondary)
                } else {
                    Table(viewModel.incidents) {
                        TableColumn("Title", value: \.title)
                        TableColumn("Severity") { incident in
                            Text(incident.severity.rawValue.capitalized)
                        }
                        TableColumn("Status") { incident in
                            Text(incident.status.rawValue.capitalized)
                                .foregroundStyle(incident.status == .resolved ? .green : .primary)
                        }
                        TableColumn("Created") { incident in
                            Text(incident.createdAt, style: .date)
                        }
                        TableColumn("") { incident in
                            if incident.status == .open {
                                Button("Resolve") {
                                    viewModel.resolveIncident(incident)
                                }
                            }
                        }
                    }
                }
            }
        }
        .padding(DesignTokens.spacingL)
    }
}
