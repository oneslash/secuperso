import SwiftUI
import SecuPersoDomain
import SecuPersoUI

struct OverviewScreen: View {
    @ObservedObject var viewModel: SecurityConsoleViewModel
    let onNavigate: (AppSection) -> Void

    @State private var hasAppeared = false
    @State private var highRiskPulse = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private let metricColumns = Array(
        repeating: GridItem(.flexible(minimum: 130), spacing: DesignTokens.spacingS),
        count: 4
    )

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: DesignTokens.spacingL) {
                statusHeroSection
                    .opacity(reduceMotion || hasAppeared ? 1 : 0)
                    .offset(y: reduceMotion ? 0 : (hasAppeared ? 0 : 8))
                    .animation(
                        reduceMotion ? nil : .easeOut(duration: 0.18).delay(0.01),
                        value: hasAppeared
                    )

                recentActivitySection
                    .opacity(reduceMotion || hasAppeared ? 1 : 0)
                    .offset(y: reduceMotion ? 0 : (hasAppeared ? 0 : 8))
                    .animation(
                        reduceMotion ? nil : .easeOut(duration: 0.18).delay(0.09),
                        value: hasAppeared
                    )

                signalStripSection
                    .opacity(reduceMotion || hasAppeared ? 1 : 0)
                    .offset(y: reduceMotion ? 0 : (hasAppeared ? 0 : 8))
                    .animation(
                        reduceMotion ? nil : .easeOut(duration: 0.18).delay(0.14),
                        value: hasAppeared
                    )
            }
            .padding(DesignTokens.spacingL)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(DesignTokens.appBackground)
        .onAppear {
            if !hasAppeared {
                hasAppeared = true
            }
            refreshPulse(for: viewModel.overviewSummary.riskLevel)
        }
        .onChange(of: viewModel.overviewSummary.riskLevel) { _, level in
            refreshPulse(for: level)
        }
    }

    private var statusHeroSection: some View {
        SectionContainer(style: .elevated) {
            VStack(alignment: .leading, spacing: DesignTokens.spacingM) {
                HStack(alignment: .top, spacing: DesignTokens.spacingL) {
                    VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                        StatusPill(viewModel.overviewSummary.stateLabel, tone: tone(for: viewModel.overviewSummary.riskLevel))

                        Text(viewModel.overviewSummary.headline)
                            .font(DesignTokens.heroDisplay)
                            .foregroundStyle(DesignTokens.textPrimary)

                        Text(viewModel.overviewSummary.detail)
                            .font(DesignTokens.body)
                            .foregroundStyle(DesignTokens.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)

                        Text("Updated \(viewModel.overviewSummary.lastUpdatedAt, style: .relative)")
                            .font(DesignTokens.caption)
                            .foregroundStyle(DesignTokens.textSecondary)
                    }

                    Spacer(minLength: 0)

                    scoreOrb
                }

                Rectangle()
                    .fill(DesignTokens.borderSubtle)
                    .frame(height: 1)

                HStack(alignment: .center, spacing: DesignTokens.spacingM) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(viewModel.nextAction.title)
                            .font(DesignTokens.bodyStrong)
                            .foregroundStyle(DesignTokens.textPrimary)
                        Text(viewModel.nextAction.detail)
                            .font(DesignTokens.caption)
                            .foregroundStyle(DesignTokens.textSecondary)
                            .lineLimit(1)
                    }

                    Spacer(minLength: 0)

                    Button(viewModel.nextAction.buttonTitle) {
                        let destination = viewModel.handleNextActionTap()
                        onNavigate(destination)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(DesignTokens.brandTeal)
                    .controlSize(.regular)
                }
            }
        }
        .overlay(
            RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius)
                .stroke(
                    riskEmphasisColor.opacity(viewModel.overviewSummary.riskLevel == .high ? (highRiskPulse ? 0.55 : 0.2) : 0),
                    lineWidth: viewModel.overviewSummary.riskLevel == .high ? 1.2 : 0
                )
        )
    }

    private var recentActivitySection: some View {
        SectionContainer(
            title: "Activity preview",
            subtitle: "Items marked Needs attention or At risk appear first.",
            style: .flat
        ) {
            if viewModel.overviewActivityPreviewItems.isEmpty {
                Text("No recent activity yet.")
                    .foregroundStyle(DesignTokens.textSecondary)
            } else {
                LazyVStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                    if viewModel.isRefreshing {
                        ProgressView("Refreshing activity...")
                            .controlSize(.small)
                    }

                    ForEach(viewModel.activityPreview) { preview in
                        ActivityFeedRowView(item: preview.item)
                        if preview.id != viewModel.activityPreview.last?.id {
                            Rectangle()
                                .fill(DesignTokens.borderSubtle)
                                .frame(height: 1)
                        }
                    }

                    Button("Open full activity") {
                        onNavigate(.activity)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(DesignTokens.brandTeal)
                }
            }
        }
    }

    private var signalStripSection: some View {
        SectionContainer(
            title: "Security signals",
            subtitle: "What is driving your current state.",
            style: .inset
        ) {
            LazyVGrid(columns: metricColumns, spacing: DesignTokens.spacingS) {
                MetricCardView(
                    title: "Open exposures",
                    value: "\(viewModel.exposureSummary.openCount)",
                    subtitle: exposureSubtitle
                )
                MetricCardView(
                    title: "Suspicious sign-ins",
                    value: "\(viewModel.overviewSignals.suspiciousSignInCount)",
                    subtitle: viewModel.overviewSignals.suspiciousSignInCount == 0 ? "No anomalies" : "Review account access"
                )
                MetricCardView(
                    title: "Open incidents",
                    value: "\(viewModel.overviewSignals.openIncidentCount)",
                    subtitle: viewModel.overviewSignals.openIncidentCount == 0 ? "No unresolved incidents" : "Resolve pending incidents"
                )
                MetricCardView(
                    title: "Provider coverage",
                    value: "\(viewModel.overviewSignals.connectedProviderCount)/\(viewModel.overviewSignals.totalProviderCount)",
                    subtitle: viewModel.overviewSignals.connectedProviderCount == viewModel.overviewSignals.totalProviderCount ? "All providers connected" : "Connect remaining providers"
                )
            }
        }
    }

    private var exposureSubtitle: String {
        if viewModel.exposureSummary.highRiskOpenCount > 0 {
            return "\(viewModel.exposureSummary.highRiskOpenCount) at risk"
        }

        return viewModel.exposureSummary.openCount == 0
            ? "No open exposure alerts"
            : "Needs attention"
    }

    private var riskEmphasisColor: Color {
        switch viewModel.overviewSummary.riskLevel {
        case .low:
            return DesignTokens.brandTeal
        case .medium:
            return DesignTokens.riskAmber
        case .high:
            return DesignTokens.riskRed
        }
    }

    private var scoreOrb: some View {
        let level = viewModel.overviewSummary.riskLevel

        return ZStack {
            Circle()
                .fill(DesignTokens.surfaceSecondary)
                .frame(width: 112, height: 112)
                .shadow(
                    color: DesignTokens.cardShadowColor.opacity(0.5),
                    radius: 6,
                    x: 0,
                    y: 2
                )

            Circle()
                .stroke(riskEmphasisColor.opacity(0.5), lineWidth: 1.6)
                .frame(width: 112, height: 112)

            VStack(spacing: 2) {
                Text("\(viewModel.overviewSummary.riskScore)")
                    .font(DesignTokens.heroScore)
                    .foregroundStyle(DesignTokens.textPrimary)
                Text(level == .high ? "AT RISK" : (level == .medium ? "ATTN" : "STABLE"))
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(DesignTokens.textSecondary)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Current risk score")
        .accessibilityValue("\(viewModel.overviewSummary.riskScore), \(viewModel.overviewSummary.stateLabel)")
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

    private func refreshPulse(for level: RiskLevel) {
        guard !reduceMotion, level == .high else {
            highRiskPulse = false
            return
        }

        highRiskPulse = false
        withAnimation(.easeInOut(duration: 1.6).repeatForever(autoreverses: true)) {
            highRiskPulse = true
        }
    }
}
