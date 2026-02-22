import SwiftUI
import SecuPersoUI

struct OverviewScreen: View {
    @ObservedObject var viewModel: SecurityConsoleViewModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: DesignTokens.spacingL) {
                HStack(alignment: .top, spacing: DesignTokens.spacingM) {
                    VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                        Text("Current Risk")
                            .font(.headline)
                        HStack(spacing: DesignTokens.spacingS) {
                            Text("\(viewModel.riskSnapshot.score)")
                                .font(.system(size: 44, weight: .bold, design: .rounded))
                            RiskBadgeView(level: viewModel.riskSnapshot.level)
                        }
                        Text("Last recalculated \(viewModel.riskSnapshot.lastUpdatedAt, style: .relative)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(DesignTokens.spacingM)
                    .background(RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius).fill(DesignTokens.elevatedCardBackground))

                    MetricCardView(
                        title: "New Exposures",
                        value: "\(viewModel.newExposureCount)",
                        subtitle: "Open and unresolved"
                    )
                    MetricCardView(
                        title: "Suspicious Logins",
                        value: "\(viewModel.suspiciousLoginsCount)",
                        subtitle: "Needs review"
                    )
                    MetricCardView(
                        title: "Open Incidents",
                        value: "\(viewModel.unresolvedIncidentCount)",
                        subtitle: "Pending resolution"
                    )
                }

                VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                    Text("Recent Security Events")
                        .font(.headline)
                    if viewModel.timelineEvents.isEmpty {
                        Text("No events available for this scenario.")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(viewModel.timelineEvents) { item in
                            HStack(alignment: .top, spacing: DesignTokens.spacingS) {
                                Circle()
                                    .fill(color(for: item.kind))
                                    .frame(width: 10, height: 10)
                                    .padding(.top, 6)

                                VStack(alignment: .leading, spacing: 2) {
                                    Text(item.title)
                                        .font(.subheadline.weight(.semibold))
                                    Text(item.details)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }

                                Spacer()
                                Text(item.date, style: .time)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            .padding(.vertical, 5)
                        }
                    }
                }
                .padding(DesignTokens.spacingM)
                .background(RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius).fill(DesignTokens.elevatedCardBackground))
            }
            .padding(DesignTokens.spacingL)
        }
    }

    private func color(for kind: TimelineEvent.Kind) -> Color {
        switch kind {
        case .exposure:
            return .orange
        case .login:
            return .blue
        case .incident:
            return .red
        }
    }
}
