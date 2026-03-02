import SwiftUI
import SecuPersoDomain
import SecuPersoUI

struct ExposureScreen: View {
    @ObservedObject var viewModel: SecurityConsoleViewModel
    let exposureViewModel: ExposureViewModel

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: DesignTokens.spacingL) {
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
        MonitoredEmailsSection(exposureViewModel: exposureViewModel)
    }

    private var exposureSummarySection: some View {
        SectionContainer(title: "Exposure summary", style: .flat) {
            VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                StatusPill(exposureStateLabel, tone: exposureStateTone)
                Text(viewModel.exposureSummary.headline)
                    .font(DesignTokens.headlineMedium)
                Text(viewModel.exposureSummary.detail)
                    .font(DesignTokens.body)
                    .foregroundStyle(DesignTokens.mutedForeground)

                HStack(spacing: DesignTokens.spacingM) {
                    exposureMetric(value: viewModel.exposureSummary.openCount, label: "Open alerts")
                    exposureMetric(value: viewModel.exposureSummary.highRiskOpenCount, label: "High priority")
                    exposureMetric(value: viewModel.exposureSummary.affectedEmailCount, label: "Affected emails")
                }

                if let mostRecentAt = viewModel.exposureSummary.mostRecentAt {
                    Text("Most recent alert \(mostRecentAt, style: .relative)")
                        .font(DesignTokens.caption)
                        .foregroundStyle(DesignTokens.mutedForeground)
                }
            }
        }
    }

    private var openFindingsSection: some View {
        SectionContainer(
            title: "Open findings",
            subtitle: "Review grouped findings and prioritize items at risk.",
            style: .elevated
        ) {
            if viewModel.openExposureFindings.isEmpty {
                Text("No open findings.")
                    .foregroundStyle(DesignTokens.mutedForeground)
            } else {
                VStack(alignment: .leading, spacing: DesignTokens.spacingM) {
                    if viewModel.isRefreshing {
                        ProgressView("Refreshing findings...")
                            .controlSize(.small)
                    }

                    Table(viewModel.exposureFindingRows) {
                        TableColumn("Email") { finding in
                            Text(finding.email)
                                .font(.subheadline.weight(.semibold))
                        }

                        TableColumn("Source") { finding in
                            Text(finding.source)
                                .font(.caption)
                        }

                        TableColumn("Severity") { finding in
                            StatusPill(finding.severity.rawValue.capitalized, tone: tone(for: finding.severity))
                        }

                        TableColumn("Found") { finding in
                            Text(DisplayDateFormatter.shortDateTime.string(from: finding.foundAt))
                                .font(.caption)
                                .foregroundStyle(DesignTokens.mutedForeground)
                        }

                        TableColumn("Remediation") { finding in
                            Text(finding.remediation)
                                .font(.caption)
                                .foregroundStyle(DesignTokens.mutedForeground)
                                .lineLimit(2)
                        }
                    }
                    .frame(minHeight: 260)
                    .padding(DesignTokens.spacingXS)
                    .background(
                        RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius, style: .continuous)
                            .fill(DesignTokens.surfaceTertiary)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius, style: .continuous)
                            .stroke(DesignTokens.borderSubtle, lineWidth: DesignTokens.borderWidth)
                    )
                }
            }
        }
    }

    private func tone(for severity: ExposureSeverity) -> StatusPillTone {
        switch severity {
        case .low:
            return .positive
        case .medium:
            return .caution
        case .high, .critical:
            return .critical
        }
    }

    private func exposureMetric(value: Int, label: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(value)")
                .font(.title3.weight(.semibold))
            Text(label)
                .font(DesignTokens.caption)
                .foregroundStyle(DesignTokens.mutedForeground)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, DesignTokens.spacingXS)
        .padding(.horizontal, DesignTokens.spacingS)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(DesignTokens.surfaceSecondary)
        )
    }

    private var exposureStateLabel: String {
        if viewModel.exposureSummary.highRiskOpenCount > 0 {
            return "At risk"
        }
        if viewModel.exposureSummary.openCount > 0 {
            return "Needs attention"
        }
        return "Stable"
    }

    private var exposureStateTone: StatusPillTone {
        if viewModel.exposureSummary.highRiskOpenCount > 0 {
            return .critical
        }
        if viewModel.exposureSummary.openCount > 0 {
            return .caution
        }
        return .positive
    }
}

private struct MonitoredEmailsSection: View {
    @ObservedObject var exposureViewModel: ExposureViewModel
    @State private var emailInput: String = ""
    @State private var providerHint: ProviderID = .other

    var body: some View {
        SectionContainer(
            title: "Monitored emails",
            subtitle: "Add addresses you want continuously checked for exposure findings.",
            style: .inset
        ) {
            VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                HStack(spacing: DesignTokens.spacingS) {
                    TextField("Email address", text: $emailInput)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled(true)
                        .accessibilityLabel("Email address")

                    Picker("Provider", selection: $providerHint) {
                        Text("Google").tag(ProviderID.google)
                        Text("Outlook").tag(ProviderID.outlook)
                        Text("Other").tag(ProviderID.other)
                    }
                    .frame(maxWidth: 140)
                    .accessibilityLabel("Provider")

                    Button("Add") {
                        exposureViewModel.addMonitoredEmail(email: emailInput, providerHint: providerHint)
                        emailInput = ""
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(emailInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                .padding(DesignTokens.spacingS)
                .background(
                    RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius, style: .continuous)
                        .fill(DesignTokens.surfaceTertiary)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius, style: .continuous)
                        .stroke(DesignTokens.borderSubtle, lineWidth: DesignTokens.borderWidth)
                )

                if let message = exposureViewModel.inlineStatusMessage {
                    HStack(spacing: DesignTokens.spacingS) {
                        Text(message)
                            .font(DesignTokens.caption)
                            .foregroundStyle(DesignTokens.textPrimary)
                            .frame(maxWidth: .infinity, alignment: .leading)

                        Button("Dismiss") {
                            exposureViewModel.clearInlineStatusMessage()
                        }
                        .buttonStyle(.plain)
                        .font(DesignTokens.caption.weight(.semibold))
                    }
                    .padding(.horizontal, DesignTokens.spacingS)
                    .padding(.vertical, DesignTokens.spacingXS)
                    .background(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .fill(DesignTokens.riskAmber.opacity(0.14))
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .stroke(DesignTokens.riskAmber.opacity(0.26), lineWidth: DesignTokens.borderWidth)
                    )
                }

                if exposureViewModel.monitoredEmails.isEmpty {
                    Text("No monitored emails configured yet.")
                        .foregroundStyle(DesignTokens.mutedForeground)
                        .font(.subheadline)
                } else {
                    Table(exposureViewModel.monitoredEmails) {
                        TableColumn("Email") { monitoredEmail in
                            Text(monitoredEmail.email)
                                .font(.subheadline.weight(.semibold))
                        }

                        TableColumn("Provider") { monitoredEmail in
                            Text(monitoredEmail.providerHint.displayName)
                                .font(.caption)
                        }

                        TableColumn("Last checked") { monitoredEmail in
                            Text(checkedLabel(for: monitoredEmail.lastCheckedAt))
                                .font(.caption)
                                .foregroundStyle(DesignTokens.mutedForeground)
                        }

                        TableColumn("Enabled") { monitoredEmail in
                            Toggle("Enabled", isOn: Binding(
                                get: { monitoredEmail.isEnabled },
                                set: { isEnabled in
                                    exposureViewModel.setMonitoredEmailEnabled(id: monitoredEmail.id, isEnabled: isEnabled)
                                }
                            ))
                            .toggleStyle(.switch)
                            .controlSize(.small)
                            .accessibilityLabel("Enable monitoring for \(monitoredEmail.email)")
                        }

                        TableColumn("Actions") { monitoredEmail in
                            Button("Remove", role: .destructive) {
                                exposureViewModel.removeMonitoredEmail(id: monitoredEmail.id)
                            }
                            .buttonStyle(.bordered)
                        }
                    }
                    .frame(minHeight: 180)
                    .padding(DesignTokens.spacingXS)
                    .background(
                        RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius, style: .continuous)
                            .fill(DesignTokens.surfaceTertiary)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius, style: .continuous)
                            .stroke(DesignTokens.borderSubtle, lineWidth: DesignTokens.borderWidth)
                    )
                }
            }
        }
    }

    private func checkedLabel(for date: Date?) -> String {
        guard let date else {
            return "Not checked yet"
        }
        return "Checked \(DisplayDateFormatter.shortDateTime.string(from: date))"
    }
}
