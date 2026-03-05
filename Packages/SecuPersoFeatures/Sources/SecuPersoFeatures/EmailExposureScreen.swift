import SwiftUI
import SecuPersoDomain
import SecuPersoUI

struct ExposureScreen: View {
    @ObservedObject var viewModel: SecurityConsoleViewModel
    @ObservedObject var exposureViewModel: ExposureViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingL) {
            MonitoredEmailsSection(exposureViewModel: exposureViewModel)
            exposureSummarySection

            HSplitView {
                findingsWorkspacePane
                    .frame(minWidth: 360, idealWidth: 400)

                inspectorWorkspacePane
                    .frame(minWidth: 380, idealWidth: 460, maxWidth: .infinity)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .padding(DesignTokens.spacingL)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(DesignTokens.appBackground)
    }

    private var exposureSummarySection: some View {
        SectionContainer(title: "Exposure summary", style: .flat) {
            VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                StatusPill(exposureStateLabel, tone: exposureStateTone)

                Text(viewModel.exposureSummary.headline)
                    .font(DesignTokens.headlineMedium)
                    .foregroundStyle(DesignTokens.textPrimary)

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

    private var findingsWorkspacePane: some View {
        SectionContainer(
            title: "Open findings",
            subtitle: "Search findings, focus at-risk items first, and keep a selected breach in view while triaging.",
            style: .elevated
        ) {
            VStack(alignment: .leading, spacing: DesignTokens.spacingM) {
                HStack(spacing: DesignTokens.spacingS) {
                    Picker("Severity", selection: Binding(
                        get: { viewModel.exposureFilter },
                        set: { viewModel.exposureFilter = $0 }
                    )) {
                        ForEach(ExposureFindingFilter.allCases) { filter in
                            Text(filter.title).tag(filter)
                        }
                    }
                    .pickerStyle(.segmented)

                    TextField("Search findings", text: Binding(
                        get: { viewModel.exposureSearchText },
                        set: { viewModel.exposureSearchText = $0 }
                    ))
                    .textFieldStyle(.roundedBorder)
                    .frame(minWidth: 180)
                }

                if viewModel.isRefreshing {
                    ProgressView("Refreshing findings...")
                        .controlSize(.small)
                }

                if viewModel.filteredExposureFindingRows.isEmpty {
                    ExposureEmptyState(
                        title: exposureViewModel.monitoredEmails.isEmpty ? "Add a monitored email to start exposure checks" : "No findings match this view",
                        detail: exposureViewModel.monitoredEmails.isEmpty
                            ? "Use the monitored email section above to add the addresses you want checked."
                            : "Clear the search or widen the severity filter to review more open findings."
                    )
                } else {
                    List(selection: exposureSelection) {
                        ForEach(viewModel.filteredExposureFindingRows) { finding in
                            ExposureFindingRowView(finding: finding)
                                .tag(finding.id)
                        }
                    }
                    .listStyle(.inset)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
    }

    private var inspectorWorkspacePane: some View {
        SectionContainer(
            title: "Finding details",
            subtitle: "Keep the selected finding in focus while reviewing remediation guidance and monitoring context.",
            style: .flat
        ) {
            if let inspector = viewModel.exposureInspector(monitoredEmails: exposureViewModel.monitoredEmails) {
                ExposureInspectorView(inspector: inspector)
            } else {
                ExposureEmptyState(
                    title: "Select a finding",
                    detail: "Choose an open finding to review the breach source, remediation, and monitoring state."
                )
            }
        }
    }

    private var exposureSelection: Binding<UUID?> {
        Binding(
            get: { viewModel.selectedExposureFindingID },
            set: { viewModel.selectExposureFinding(id: $0) }
        )
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
    @FocusState private var emailComposerFocused: Bool

    var body: some View {
        SectionContainer(
            title: "Monitored emails",
            subtitle: "Manage the addresses that drive continuous exposure checks.",
            style: .inset
        ) {
            VStack(alignment: .leading, spacing: DesignTokens.spacingM) {
                HStack(spacing: DesignTokens.spacingS) {
                    TextField("Email address", text: $emailInput)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled(true)
                        .accessibilityLabel("Email address")
                        .focused($emailComposerFocused)

                    Button {
                        exposureViewModel.addMonitoredEmail(email: emailInput)
                        emailInput = ""
                    } label: {
                        if exposureViewModel.isUpdatingMonitoredEmails {
                            ProgressView()
                                .controlSize(.small)
                                .frame(width: 50)
                        } else {
                            Text("Add")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(
                        exposureViewModel.isUpdatingMonitoredEmails ||
                        emailInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    )
                }

                if let feedback = exposureViewModel.monitoredEmailsFeedback {
                    FeedbackBanner(feedback: feedback) {
                        exposureViewModel.clearMonitoredEmailsFeedback()
                    }
                }

                if exposureViewModel.monitoredEmails.isEmpty {
                    Text("No monitored emails configured yet.")
                        .foregroundStyle(DesignTokens.mutedForeground)
                        .font(.subheadline)
                } else {
                    VStack(spacing: DesignTokens.spacingXS) {
                        ForEach(exposureViewModel.monitoredEmails) { monitoredEmail in
                            HStack(spacing: DesignTokens.spacingS) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(monitoredEmail.email)
                                        .font(.subheadline.weight(.semibold))
                                        .foregroundStyle(DesignTokens.textPrimary)

                                    Text(checkedLabel(for: monitoredEmail.lastCheckedAt))
                                        .font(DesignTokens.caption)
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
                                .controlSize(.small)
                                .disabled(exposureViewModel.isUpdatingMonitoredEmails)
                                .labelsHidden()

                                Button("Remove", role: .destructive) {
                                    exposureViewModel.removeMonitoredEmail(id: monitoredEmail.id)
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                                .disabled(exposureViewModel.isUpdatingMonitoredEmails)
                            }
                            .padding(DesignTokens.spacingS)
                            .background(
                                RoundedRectangle(cornerRadius: 12, style: .continuous)
                                    .fill(DesignTokens.surfaceTertiary)
                            )
                        }
                    }
                }
            }
        }
        .onChange(of: exposureViewModel.monitoredEmailComposerFocusToken) { _, _ in
            emailComposerFocused = true
        }
    }

    private func checkedLabel(for date: Date?) -> String {
        guard let date else {
            return "Not checked yet"
        }
        return "Checked \(DisplayDateFormatter.shortDateTime.string(from: date))"
    }
}

private struct ExposureFindingRowView: View {
    let finding: ExposureFindingsProjectionRow

    var body: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingXS) {
            HStack(spacing: DesignTokens.spacingS) {
                Text(finding.email)
                    .font(DesignTokens.bodyStrong)
                    .foregroundStyle(DesignTokens.textPrimary)

                Spacer(minLength: 0)

                StatusPill(finding.severity.rawValue.capitalized, tone: tone)
            }

            Text(finding.source)
                .font(.subheadline)
                .foregroundStyle(DesignTokens.textPrimary)

            Text(finding.remediation)
                .font(DesignTokens.caption)
                .foregroundStyle(DesignTokens.textSecondary)
                .lineLimit(2)

            Text(DisplayDateFormatter.shortDateTime.string(from: finding.foundAt))
                .font(DesignTokens.caption)
                .foregroundStyle(DesignTokens.textSecondary)
        }
        .padding(.vertical, DesignTokens.spacingXS)
    }

    private var tone: StatusPillTone {
        switch finding.severity {
        case .low:
            return .positive
        case .medium:
            return .caution
        case .high, .critical:
            return .critical
        }
    }
}

private struct ExposureInspectorView: View {
    let inspector: ExposureInspectorProjection

    var body: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingM) {
            HStack(alignment: .top, spacing: DesignTokens.spacingS) {
                StatusPill(inspector.severity.rawValue.capitalized, tone: tone)

                Spacer(minLength: 0)

                VStack(alignment: .trailing, spacing: 2) {
                    Text(inspector.foundAt, style: .relative)
                        .font(DesignTokens.caption.weight(.semibold))
                        .foregroundStyle(DesignTokens.textPrimary)

                    Text(inspector.foundAt.formatted(date: .abbreviated, time: .shortened))
                        .font(DesignTokens.caption)
                        .foregroundStyle(DesignTokens.textSecondary)
                }
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(inspector.email)
                    .font(DesignTokens.headlineLarge)
                    .foregroundStyle(DesignTokens.textPrimary)

                Text(inspector.source)
                    .font(DesignTokens.bodyStrong)
                    .foregroundStyle(DesignTokens.textSecondary)
            }

            ExposureDetailBlock(title: "Recommended remediation", value: inspector.remediation)
            ExposureDetailBlock(title: "Monitoring", value: inspector.monitoringSummary)
            ExposureDetailBlock(
                title: "Related open findings",
                value: "\(inspector.relatedOpenFindingCount) open finding(s) currently affect this address."
            )
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private var tone: StatusPillTone {
        switch inspector.severity {
        case .low:
            return .positive
        case .medium:
            return .caution
        case .high, .critical:
            return .critical
        }
    }
}

private struct ExposureEmptyState: View {
    let title: String
    let detail: String

    var body: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
            Text(title)
                .font(DesignTokens.bodyStrong)
                .foregroundStyle(DesignTokens.textPrimary)

            Text(detail)
                .font(DesignTokens.caption)
                .foregroundStyle(DesignTokens.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .padding(.top, DesignTokens.spacingS)
    }
}

private struct ExposureDetailBlock: View {
    let title: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(DesignTokens.caption.weight(.semibold))
                .foregroundStyle(DesignTokens.textSecondary)

            Text(value)
                .font(DesignTokens.body)
                .foregroundStyle(DesignTokens.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct FeedbackBanner: View {
    let feedback: OperationFeedback
    let dismiss: () -> Void

    var body: some View {
        HStack(spacing: DesignTokens.spacingS) {
            Image(systemName: symbol)
                .foregroundStyle(color)

            Text(feedback.message)
                .font(DesignTokens.caption)
                .foregroundStyle(DesignTokens.textPrimary)
                .frame(maxWidth: .infinity, alignment: .leading)

            Button("Dismiss") {
                dismiss()
            }
            .buttonStyle(.plain)
            .font(DesignTokens.caption.weight(.semibold))
        }
        .padding(.horizontal, DesignTokens.spacingS)
        .padding(.vertical, DesignTokens.spacingXS)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(color.opacity(0.12))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(color.opacity(0.24), lineWidth: DesignTokens.borderWidth)
        )
    }

    private var symbol: String {
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

    private var color: Color {
        switch feedback.tone {
        case .info:
            return DesignTokens.brandTeal
        case .success:
            return DesignTokens.brandTeal
        case .warning:
            return DesignTokens.riskAmber
        case .error:
            return DesignTokens.riskRed
        }
    }
}
