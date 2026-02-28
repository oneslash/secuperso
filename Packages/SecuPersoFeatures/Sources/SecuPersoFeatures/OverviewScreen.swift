import SwiftUI
import SecuPersoDomain
import SecuPersoUI

struct OverviewScreen: View {
    @ObservedObject var viewModel: SecurityConsoleViewModel
    let onNavigate: (AppSection) -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: DesignTokens.spacingL) {
                riskSummarySection
                nextStepSection
                recentActivitySection
            }
            .padding(DesignTokens.spacingL)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(DesignTokens.appBackground)
    }

    private var riskSummarySection: some View {
        SectionContainer(title: "Security status") {
            HStack(alignment: .center, spacing: DesignTokens.spacingM) {
                VStack(alignment: .leading, spacing: DesignTokens.spacingXS) {
                    Text(viewModel.overviewSummary.headline)
                        .font(.title3.weight(.semibold))
                    Text(viewModel.overviewSummary.detail)
                        .font(.subheadline)
                        .foregroundStyle(DesignTokens.mutedForeground)
                    Text("Updated \(viewModel.overviewSummary.lastUpdatedAt, style: .relative)")
                        .font(.caption)
                        .foregroundStyle(DesignTokens.mutedForeground)
                }

                Spacer(minLength: 0)

                VStack(alignment: .trailing, spacing: DesignTokens.spacingXS) {
                    Text("\(viewModel.overviewSummary.riskScore)")
                        .font(.system(size: 42, weight: .bold, design: .rounded))
                    StatusPill(
                        viewModel.overviewSummary.riskLevel.rawValue.capitalized,
                        tone: tone(for: viewModel.overviewSummary.riskLevel)
                    )
                }
            }
        }
    }

    private var nextStepSection: some View {
        SectionContainer(title: "Next step") {
            VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                Text(viewModel.nextAction.title)
                    .font(.headline)

                Text(viewModel.nextAction.detail)
                    .font(.subheadline)
                    .foregroundStyle(DesignTokens.mutedForeground)

                Button(viewModel.nextAction.buttonTitle) {
                    let destination = viewModel.handleNextActionTap()
                    onNavigate(destination)
                }
                .buttonStyle(.borderedProminent)
            }
        }
    }

    private var recentActivitySection: some View {
        SectionContainer(title: "Recent activity") {
            if viewModel.activityFeed.isEmpty {
                Text("No recent activity yet.")
                    .foregroundStyle(DesignTokens.mutedForeground)
            } else {
                VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                    ForEach(Array(viewModel.activityFeed.prefix(5))) { item in
                        HStack(alignment: .top, spacing: DesignTokens.spacingS) {
                            Image(systemName: symbol(for: item.kind))
                                .foregroundStyle(color(for: item.severity))
                                .frame(width: 18)
                                .padding(.top, 1)

                            VStack(alignment: .leading, spacing: 2) {
                                Text(item.title)
                                    .font(.subheadline.weight(.semibold))
                                Text(item.detail)
                                    .font(.caption)
                                    .foregroundStyle(DesignTokens.mutedForeground)
                            }

                            Spacer(minLength: 0)

                            VStack(alignment: .trailing, spacing: 4) {
                                Text(item.date, style: .time)
                                    .font(.caption)
                                    .foregroundStyle(DesignTokens.mutedForeground)
                                if item.needsAttention {
                                    StatusPill("Needs attention", tone: .caution)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private func tone(for level: RiskLevel) -> StatusPillTone {
        switch level {
        case .low:
            return .positive
        case .medium:
            return .caution
        case .high:
            return .critical
        }
    }

    private func symbol(for kind: ActivityFeedItem.Kind) -> String {
        switch kind {
        case .exposure:
            return "envelope.badge"
        case .login:
            return "person.badge.shield.checkmark"
        case .incident:
            return "exclamationmark.triangle"
        }
    }

    private func color(for severity: ActivityFeedItem.Severity) -> Color {
        switch severity {
        case .neutral:
            return .secondary
        case .caution:
            return .orange
        case .warning:
            return .red
        }
    }
}
