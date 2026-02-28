import SwiftUI
import SecuPersoDomain
import SecuPersoUI

struct ExposureScreen: View {
    @ObservedObject var viewModel: SecurityConsoleViewModel
    @ObservedObject var exposureViewModel: ExposureViewModel

    @State private var emailInput: String = ""
    @State private var providerHint: ProviderID = .other

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: DesignTokens.spacingL) {
                monitoredEmailsSection
                exposureSummarySection
                openFindingsSection
            }
            .padding(DesignTokens.spacingL)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(DesignTokens.appBackground)
    }

    private var monitoredEmailsSection: some View {
        SectionContainer(title: "Monitored emails", subtitle: "Add the email addresses you want to monitor for breach exposure.") {
            VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                HStack(spacing: DesignTokens.spacingS) {
                    TextField("Email address", text: $emailInput)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled(true)

                    Picker("Provider", selection: $providerHint) {
                        Text("Google").tag(ProviderID.google)
                        Text("Outlook").tag(ProviderID.outlook)
                        Text("Other").tag(ProviderID.other)
                    }
                    .labelsHidden()
                    .frame(maxWidth: 140)

                    Button("Add") {
                        exposureViewModel.addMonitoredEmail(email: emailInput, providerHint: providerHint)
                        emailInput = ""
                    }
                    .buttonStyle(.borderedProminent)
                }

                if let message = exposureViewModel.inlineStatusMessage {
                    HStack {
                        Text(message)
                            .font(.caption)
                            .foregroundStyle(.orange)
                        Spacer(minLength: 0)
                        Button("Dismiss") {
                            exposureViewModel.clearInlineStatusMessage()
                        }
                        .buttonStyle(.plain)
                        .font(.caption)
                    }
                }

                if exposureViewModel.monitoredEmails.isEmpty {
                    Text("No monitored emails configured yet.")
                        .foregroundStyle(DesignTokens.mutedForeground)
                        .font(.subheadline)
                } else {
                    VStack(alignment: .leading, spacing: DesignTokens.spacingXS) {
                        ForEach(exposureViewModel.monitoredEmails) { monitoredEmail in
                            monitoredEmailRow(monitoredEmail)
                        }
                    }
                }
            }
        }
    }

    private func monitoredEmailRow(_ monitoredEmail: MonitoredEmailAddress) -> some View {
        HStack(spacing: DesignTokens.spacingS) {
            VStack(alignment: .leading, spacing: 2) {
                Text(monitoredEmail.email)
                    .font(.subheadline.weight(.semibold))
                Text("\(monitoredEmail.providerHint.displayName) · \(checkedLabel(for: monitoredEmail.lastCheckedAt))")
                    .font(.caption)
                    .foregroundStyle(DesignTokens.mutedForeground)
            }

            Spacer(minLength: 0)

            Toggle("Enabled", isOn: Binding(
                get: { monitoredEmail.isEnabled },
                set: { isEnabled in
                    exposureViewModel.setMonitoredEmailEnabled(id: monitoredEmail.id, isEnabled: isEnabled)
                }
            ))
            .toggleStyle(.switch)
            .labelsHidden()
            .frame(maxWidth: 58)

            Button("Remove", role: .destructive) {
                exposureViewModel.removeMonitoredEmail(id: monitoredEmail.id)
            }
            .buttonStyle(.bordered)
        }
        .padding(DesignTokens.spacingS)
        .background(
            RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius)
                .fill(DesignTokens.secondaryCardBackground)
        )
    }

    private var exposureSummarySection: some View {
        SectionContainer(title: "Exposure summary") {
            VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                Text(viewModel.exposureSummary.headline)
                    .font(.headline)
                Text(viewModel.exposureSummary.detail)
                    .font(.subheadline)
                    .foregroundStyle(DesignTokens.mutedForeground)

                HStack(spacing: DesignTokens.spacingM) {
                    exposureMetric(value: viewModel.exposureSummary.openCount, label: "Open alerts")
                    exposureMetric(value: viewModel.exposureSummary.highRiskOpenCount, label: "High priority")
                    exposureMetric(value: viewModel.exposureSummary.affectedEmailCount, label: "Affected emails")
                }

                if let mostRecentAt = viewModel.exposureSummary.mostRecentAt {
                    Text("Most recent alert \(mostRecentAt, style: .relative)")
                        .font(.caption)
                        .foregroundStyle(DesignTokens.mutedForeground)
                }
            }
        }
    }

    private var openFindingsSection: some View {
        SectionContainer(title: "Open findings", subtitle: "Grouped by monitored email.") {
            let grouped = Dictionary(grouping: viewModel.exposures.filter { $0.status == .open }, by: \.email)
            let sortedEmails = grouped.keys.sorted()

            if sortedEmails.isEmpty {
                Text("No open findings.")
                    .foregroundStyle(DesignTokens.mutedForeground)
            } else {
                VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                    ForEach(sortedEmails, id: \.self) { email in
                        VStack(alignment: .leading, spacing: DesignTokens.spacingXS) {
                            Text(email)
                                .font(.subheadline.weight(.semibold))

                            ForEach((grouped[email] ?? []).sorted(by: { $0.foundAt > $1.foundAt }), id: \.id) { finding in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("\(finding.source) · \(finding.severity.rawValue.capitalized)")
                                        .font(.caption.weight(.semibold))
                                    Text(finding.remediation)
                                        .font(.caption)
                                        .foregroundStyle(DesignTokens.mutedForeground)
                                    Text("Found \(finding.foundAt, style: .relative)")
                                        .font(.caption2)
                                        .foregroundStyle(DesignTokens.mutedForeground)
                                }
                                .padding(DesignTokens.spacingXS)
                                .background(
                                    RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius)
                                        .fill(DesignTokens.secondaryCardBackground)
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    private func checkedLabel(for date: Date?) -> String {
        guard let date else {
            return "Not checked yet"
        }
        return "Checked \(date.formatted(date: .abbreviated, time: .shortened))"
    }

    private func exposureMetric(value: Int, label: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(value)")
                .font(.title3.weight(.semibold))
            Text(label)
                .font(.caption)
                .foregroundStyle(DesignTokens.mutedForeground)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(DesignTokens.spacingS)
        .background(
            RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius)
                .fill(DesignTokens.secondaryCardBackground)
        )
    }
}
