import SwiftUI
import SecuPersoDomain
import SecuPersoUI

struct OverviewScreen: View {
    @ObservedObject var viewModel: SecurityConsoleViewModel
    @ObservedObject var exposureViewModel: ExposureViewModel
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

                riskDriversSection
                    .opacity(reduceMotion || hasAppeared ? 1 : 0)
                    .offset(y: reduceMotion ? 0 : (hasAppeared ? 0 : 8))
                    .animation(
                        reduceMotion ? nil : .easeOut(duration: 0.18).delay(0.06),
                        value: hasAppeared
                    )

                recentActivitySection
                    .opacity(reduceMotion || hasAppeared ? 1 : 0)
                    .offset(y: reduceMotion ? 0 : (hasAppeared ? 0 : 8))
                    .animation(
                        reduceMotion ? nil : .easeOut(duration: 0.18).delay(0.1),
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
                        StatusPill(heroStatusLabel, tone: heroTone)

                        Text(heroHeadline)
                            .font(DesignTokens.heroDisplay)
                            .foregroundStyle(DesignTokens.textPrimary)

                        Text(heroDetail)
                            .font(DesignTokens.body)
                            .foregroundStyle(DesignTokens.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)

                        Text(heroTimestampLine)
                            .font(DesignTokens.caption)
                            .foregroundStyle(DesignTokens.textSecondary)
                    }

                    Spacer(minLength: 0)

                    heroOrb
                }

                Rectangle()
                    .fill(DesignTokens.borderSubtle)
                    .frame(height: 1)

                HStack(alignment: .center, spacing: DesignTokens.spacingM) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(heroActionTitle)
                            .font(DesignTokens.bodyStrong)
                            .foregroundStyle(DesignTokens.textPrimary)
                        Text(heroActionDetail)
                            .font(DesignTokens.caption)
                            .foregroundStyle(DesignTokens.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    Spacer(minLength: 0)

                    Button(heroButtonTitle) {
                        performHeroAction()
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

    private var riskDriversSection: some View {
        SectionContainer(
            title: "What is driving your score",
            subtitle: riskDriverSubtitle,
            style: .flat
        ) {
            LazyVStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                ForEach(viewModel.overviewRiskDrivers) { driver in
                    OverviewRiskDriverRow(driver: driver)
                }
            }
        }
    }

    private var recentActivitySection: some View {
        SectionContainer(
            title: "Activity preview",
            subtitle: "Items marked Needs attention or At risk appear first.",
            style: .flat
        ) {
            if viewModel.overviewActivityPreviewItems.isEmpty {
                VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                    Text("Activity appears here after providers connect or a refresh completes.")
                        .foregroundStyle(DesignTokens.textSecondary)

                    if !viewModel.hasConnectedProviders {
                        Button("Connect provider") {
                            onNavigate(viewModel.openIntegrationsWorkspace())
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(DesignTokens.brandTeal)
                    } else {
                        Button("Refresh now") {
                            viewModel.runQuickSecurityCheck()
                        }
                        .buttonStyle(.bordered)
                    }
                }
            } else {
                LazyVStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                    if viewModel.isRefreshing {
                        ProgressView("Refreshing activity...")
                            .controlSize(.small)
                    }

                    ForEach(viewModel.overviewActivityPreviewItems) { item in
                        ActivityFeedRowView(item: item)
                        if item.id != viewModel.overviewActivityPreviewItems.last?.id {
                            Rectangle()
                                .fill(DesignTokens.borderSubtle)
                                .frame(height: 1)
                        }
                    }

                    Button("Open full activity") {
                        onNavigate(viewModel.openActivityWorkspace())
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
            subtitle: "Jump directly into the item that is currently affecting your security posture.",
            style: .inset
        ) {
            LazyVGrid(columns: metricColumns, spacing: DesignTokens.spacingS) {
                MetricActionCard(
                    title: "Open exposures",
                    value: "\(viewModel.exposureSummary.openCount)",
                    subtitle: exposureSubtitle
                ) {
                    onNavigate(viewModel.openHighestPriorityExposure())
                }
                MetricActionCard(
                    title: "Suspicious sign-ins",
                    value: "\(viewModel.overviewSignals.suspiciousSignInCount)",
                    subtitle: viewModel.overviewSignals.suspiciousSignInCount == 0 ? "No anomalies" : "Review account access"
                ) {
                    onNavigate(viewModel.openSuspiciousSignIns())
                }
                MetricActionCard(
                    title: "Open incidents",
                    value: "\(viewModel.overviewSignals.openIncidentCount)",
                    subtitle: viewModel.overviewSignals.openIncidentCount == 0 ? "No unresolved incidents" : "Resolve pending incidents"
                ) {
                    onNavigate(viewModel.openOpenIncidents())
                }
                MetricActionCard(
                    title: "Provider coverage",
                    value: "\(viewModel.overviewSignals.connectedProviderCount)/\(viewModel.overviewSignals.totalProviderCount)",
                    subtitle: viewModel.overviewSignals.connectedProviderCount == viewModel.overviewSignals.totalProviderCount ? "All providers connected" : "Connect remaining providers"
                ) {
                    onNavigate(viewModel.openProviderCoverage())
                }
            }
        }
    }

    private var heroStatusLabel: String {
        onboardingState?.badgeLabel ?? viewModel.overviewSummary.stateLabel
    }

    private var heroTone: StatusPillTone {
        if let onboardingState {
            switch onboardingState {
            case .connectProvider, .addMonitoredEmail:
                return .neutral
            case .runFirstCheck:
                return .positive
            }
        }

        return tone(for: viewModel.overviewSummary.riskLevel)
    }

    private var heroHeadline: String {
        onboardingState?.headline ?? viewModel.overviewSummary.headline
    }

    private var heroDetail: String {
        onboardingState?.detail ?? viewModel.overviewSummary.detail
    }

    private var heroActionTitle: String {
        onboardingState?.actionTitle ?? viewModel.nextAction.title
    }

    private var heroActionDetail: String {
        onboardingState?.actionDetail ?? viewModel.nextAction.detail
    }

    private var heroButtonTitle: String {
        onboardingState?.buttonTitle ?? viewModel.nextAction.buttonTitle
    }

    private var heroTimestampLine: String {
        if let onboardingState {
            return onboardingState.timestampLine
        }

        if let lastRefreshAt = viewModel.lastRefreshAt {
            return "Last check \(lastRefreshAt.formatted(date: .abbreviated, time: .shortened)) · Score updated \(relativeDateText(for: viewModel.overviewSummary.lastUpdatedAt))"
        }

        return "Updated \(relativeDateText(for: viewModel.overviewSummary.lastUpdatedAt))"
    }

    private var riskDriverSubtitle: String {
        if let lastRefreshAt = viewModel.lastRefreshAt {
            return "Last security check: \(lastRefreshAt.formatted(date: .abbreviated, time: .shortened))."
        }
        return "Current contributors to the score."
    }

    private var onboardingState: OverviewOnboardingState? {
        if !viewModel.hasConnectedProviders {
            return .connectProvider
        }

        if exposureViewModel.monitoredEmails.isEmpty {
            return .addMonitoredEmail
        }

        if !viewModel.hasLoadedSecurityData && viewModel.lastRefreshAt == nil {
            return .runFirstCheck
        }

        return nil
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

    @ViewBuilder
    private var heroOrb: some View {
        if let onboardingState {
            setupOrb(symbol: onboardingState.symbol)
        } else {
            scoreOrb
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

    private func setupOrb(symbol: String) -> some View {
        ZStack {
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
                .stroke(DesignTokens.brandTeal.opacity(0.32), lineWidth: 1.4)
                .frame(width: 112, height: 112)

            Image(systemName: symbol)
                .font(.system(size: 34, weight: .semibold))
                .foregroundStyle(DesignTokens.brandTeal)
        }
        .accessibilityHidden(true)
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

    private func performHeroAction() {
        guard let onboardingState else {
            onNavigate(viewModel.handleNextActionTap())
            return
        }

        switch onboardingState {
        case .connectProvider:
            onNavigate(viewModel.openIntegrationsWorkspace())
        case .addMonitoredEmail:
            exposureViewModel.requestMonitoredEmailComposerFocus()
            onNavigate(viewModel.openExposureWorkspace())
        case .runFirstCheck:
            viewModel.runQuickSecurityCheck()
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

    private func relativeDateText(for date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter.localizedString(for: date, relativeTo: .now)
    }
}

private struct MetricActionCard: View {
    let title: String
    let value: String
    let subtitle: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            MetricCardView(title: title, value: value, subtitle: subtitle)
                .overlay(alignment: .topTrailing) {
                    Image(systemName: "arrow.up.right")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(DesignTokens.textSecondary)
                        .padding(DesignTokens.spacingS)
                }
        }
        .buttonStyle(.plain)
    }
}

private struct OverviewRiskDriverRow: View {
    let driver: OverviewRiskDriver

    var body: some View {
        HStack(alignment: .top, spacing: DesignTokens.spacingS) {
            Image(systemName: symbol)
                .foregroundStyle(color)
                .frame(width: 20, height: 20)

            VStack(alignment: .leading, spacing: 2) {
                Text(driver.title)
                    .font(DesignTokens.bodyStrong)
                    .foregroundStyle(DesignTokens.textPrimary)

                Text(driver.detail)
                    .font(DesignTokens.caption)
                    .foregroundStyle(DesignTokens.textSecondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(DesignTokens.spacingS)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(DesignTokens.surfaceSecondary)
        )
    }

    private var symbol: String {
        switch driver.emphasis {
        case .calm:
            return "checkmark.circle.fill"
        case .caution:
            return "exclamationmark.circle.fill"
        case .critical:
            return "exclamationmark.triangle.fill"
        }
    }

    private var color: Color {
        switch driver.emphasis {
        case .calm:
            return DesignTokens.brandTeal
        case .caution:
            return DesignTokens.riskAmber
        case .critical:
            return DesignTokens.riskRed
        }
    }
}

private enum OverviewOnboardingState {
    case connectProvider
    case addMonitoredEmail
    case runFirstCheck

    var badgeLabel: String {
        switch self {
        case .connectProvider, .addMonitoredEmail:
            return "Getting started"
        case .runFirstCheck:
            return "Ready to scan"
        }
    }

    var headline: String {
        switch self {
        case .connectProvider:
            return "Connect your first provider"
        case .addMonitoredEmail:
            return "Add a monitored email"
        case .runFirstCheck:
            return "Run your first security check"
        }
    }

    var detail: String {
        switch self {
        case .connectProvider:
            return "Link a provider so SecuPerso can pull account activity into this secure workspace."
        case .addMonitoredEmail:
            return "Add the addresses you want checked for exposure findings so alerts can start appearing here."
        case .runFirstCheck:
            return "Your providers and monitored emails are ready. Run a check to populate your first security signals."
        }
    }

    var actionTitle: String {
        switch self {
        case .connectProvider:
            return "Start with provider coverage"
        case .addMonitoredEmail:
            return "Add exposure monitoring"
        case .runFirstCheck:
            return "Pull your first results"
        }
    }

    var actionDetail: String {
        switch self {
        case .connectProvider:
            return "Provider coverage unlocks sign-in monitoring and richer security context."
        case .addMonitoredEmail:
            return "Monitored addresses drive exposure findings and breach alerts."
        case .runFirstCheck:
            return "A refresh will populate the latest account activity and exposure checks."
        }
    }

    var buttonTitle: String {
        switch self {
        case .connectProvider:
            return "Connect provider"
        case .addMonitoredEmail:
            return "Add monitored email"
        case .runFirstCheck:
            return "Run check"
        }
    }

    var timestampLine: String {
        switch self {
        case .connectProvider:
            return "No provider activity has been collected yet."
        case .addMonitoredEmail:
            return "Providers are connected, but exposure monitoring is not configured yet."
        case .runFirstCheck:
            return "The workspace is configured and ready for its first scan."
        }
    }

    var symbol: String {
        switch self {
        case .connectProvider:
            return "link.badge.plus"
        case .addMonitoredEmail:
            return "envelope.badge"
        case .runFirstCheck:
            return "arrow.clockwise.circle.fill"
        }
    }
}
