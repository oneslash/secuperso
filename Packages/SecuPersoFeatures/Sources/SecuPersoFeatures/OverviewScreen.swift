import SwiftUI
import SecuPersoDomain
import SecuPersoUI

// MARK: - Overview Screen (Redesigned)
//
// Layout: two distinct branches — onboarding vs active monitoring.
//
// Onboarding:  centered, focused, single CTA with step progress.
// Monitoring:  compact posture header (one card) → attention rows → recent activity.
//              Signal stats are inline text in the header, not a card grid.

struct OverviewScreen: View {
    @ObservedObject var viewModel: SecurityConsoleViewModel
    @ObservedObject var exposureViewModel: ExposureViewModel
    let onNavigate: (AppSection) -> Void

    @State private var hasAppeared = false
    @State private var highRiskPulse = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Group {
            if let step = onboardingStep {
                onboardingLayout(step)
            } else {
                monitoringLayout
            }
        }
        .background(DesignTokens.appBackground)
        .onAppear {
            if !hasAppeared { hasAppeared = true }
            refreshPulse(for: viewModel.overviewSummary.riskLevel)
        }
        .onChange(of: viewModel.overviewSummary.riskLevel) { _, level in
            refreshPulse(for: level)
        }
    }

    // MARK: - State Detection

    private var onboardingStep: OnboardingStep? {
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
}

// MARK: - Onboarding Layout

private extension OverviewScreen {
    func onboardingLayout(_ step: OnboardingStep) -> some View {
        VStack(spacing: 0) {
            Spacer(minLength: DesignTokens.spacingXL)

            VStack(spacing: DesignTokens.spacingL) {
                Image(systemName: step.symbol)
                    .font(.system(size: 36, weight: .light))
                    .foregroundStyle(DesignTokens.brandTeal)
                    .frame(width: 72, height: 72)
                    .background(
                        Circle().fill(DesignTokens.brandTeal.opacity(0.08))
                    )

                VStack(spacing: DesignTokens.spacingXS) {
                    Text(step.headline)
                        .font(.title2.weight(.semibold))
                        .foregroundStyle(DesignTokens.textPrimary)

                    Text(step.detail)
                        .font(DesignTokens.body)
                        .foregroundStyle(DesignTokens.textSecondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 380)
                }

                Button(step.buttonTitle) {
                    performOnboardingAction(step)
                }
                .buttonStyle(.borderedProminent)
                .tint(DesignTokens.brandTeal)
                .controlSize(.large)

                VStack(spacing: DesignTokens.spacingXS) {
                    HStack(spacing: 8) {
                        ForEach(0..<3, id: \.self) { index in
                            Circle()
                                .fill(
                                    index <= step.progressIndex
                                        ? DesignTokens.brandTeal
                                        : DesignTokens.borderSubtle
                                )
                                .frame(width: 6, height: 6)
                        }
                    }

                    Text(step.contextLine)
                        .font(.caption)
                        .foregroundStyle(DesignTokens.textSecondary)
                }
            }
            .padding(DesignTokens.spacingXL)

            Spacer(minLength: DesignTokens.spacingXL)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    func performOnboardingAction(_ step: OnboardingStep) {
        switch step {
        case .connectProvider:
            onNavigate(viewModel.openIntegrationsWorkspace())
        case .addMonitoredEmail:
            exposureViewModel.requestMonitoredEmailComposerFocus()
            onNavigate(viewModel.openExposureWorkspace())
        case .runFirstCheck:
            viewModel.runQuickSecurityCheck()
        }
    }
}

// MARK: - Active Monitoring Layout

private extension OverviewScreen {
    var monitoringLayout: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: DesignTokens.spacingXL) {
                postureHeader
                    .staggerIn(hasAppeared: hasAppeared, reduceMotion: reduceMotion, delay: 0.01)

                attentionSection
                    .staggerIn(hasAppeared: hasAppeared, reduceMotion: reduceMotion, delay: 0.06)

                recentSection
                    .staggerIn(hasAppeared: hasAppeared, reduceMotion: reduceMotion, delay: 0.1)
            }
            .padding(DesignTokens.spacingL)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: Posture Header — one card with score + headline + inline stats

    var postureHeader: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingM) {
            HStack(alignment: .center, spacing: DesignTokens.spacingM) {
                scoreIndicator

                VStack(alignment: .leading, spacing: DesignTokens.spacingXXS) {
                    Text(viewModel.overviewSummary.headline)
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(DesignTokens.textPrimary)

                    HStack(spacing: DesignTokens.spacingS) {
                        StatusPill(viewModel.overviewSummary.stateLabel, tone: statusTone)

                        if let lastRefreshAt = viewModel.lastRefreshAt {
                            Text("Checked \(relativeDateText(for: lastRefreshAt))")
                                .font(DesignTokens.caption)
                                .foregroundStyle(DesignTokens.textSecondary)
                        }
                    }
                }

                Spacer(minLength: 0)
            }

            Divider()

            HStack(spacing: 0) {
                signalStat(
                    value: viewModel.overviewSignals.suspiciousSignInCount,
                    label: "sign-ins flagged"
                ) {
                    onNavigate(viewModel.openSuspiciousSignIns())
                }

                Spacer(minLength: 0)

                signalStat(
                    value: viewModel.overviewSignals.openIncidentCount,
                    label: "open incidents"
                ) {
                    onNavigate(viewModel.openOpenIncidents())
                }

                Spacer(minLength: 0)

                signalStat(
                    value: viewModel.exposureSummary.openCount,
                    label: "exposures"
                ) {
                    onNavigate(viewModel.openHighestPriorityExposure())
                }

                Spacer(minLength: 0)

                signalStat(
                    formattedValue: "\(viewModel.overviewSignals.connectedProviderCount)/\(viewModel.overviewSignals.totalProviderCount)",
                    label: "providers"
                ) {
                    onNavigate(viewModel.openProviderCoverage())
                }
            }
        }
        .padding(DesignTokens.spacingM)
        .background(
            RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius, style: .continuous)
                .fill(DesignTokens.surfacePrimary)
        )
        .overlay(
            RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius, style: .continuous)
                .stroke(headerBorderColor, lineWidth: DesignTokens.borderWidth)
        )
        .shadow(
            color: DesignTokens.cardShadowColor,
            radius: DesignTokens.cardShadowRadius,
            x: 0,
            y: DesignTokens.cardShadowYOffset
        )
    }

    var scoreIndicator: some View {
        let level = viewModel.overviewSummary.riskLevel

        return ZStack {
            Circle()
                .fill(DesignTokens.surfaceSecondary)
                .frame(width: 64, height: 64)

            Circle()
                .stroke(riskColor(for: level).opacity(0.45), lineWidth: 1.4)
                .frame(width: 64, height: 64)

            VStack(spacing: 1) {
                Text("\(viewModel.overviewSummary.riskScore)")
                    .font(.system(.title2, design: .rounded).weight(.bold))
                    .foregroundStyle(DesignTokens.textPrimary)
                Text(level == .high ? "RISK" : (level == .medium ? "ATTN" : "OK"))
                    .font(.system(size: 9, weight: .semibold))
                    .foregroundStyle(DesignTokens.textSecondary)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Risk score")
        .accessibilityValue("\(viewModel.overviewSummary.riskScore), \(viewModel.overviewSummary.stateLabel)")
    }

    func signalStat(value: Int? = nil, formattedValue: String? = nil, label: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 2) {
                Text(formattedValue ?? "\(value ?? 0)")
                    .font(.title3.weight(.semibold).monospacedDigit())
                    .foregroundStyle(DesignTokens.textPrimary)
                Text(label)
                    .font(.caption)
                    .foregroundStyle(DesignTokens.textSecondary)
            }
        }
        .buttonStyle(.plain)
    }

    var headerBorderColor: Color {
        if viewModel.overviewSummary.riskLevel == .high {
            return DesignTokens.riskRed.opacity(highRiskPulse ? 0.4 : 0.15)
        }
        return DesignTokens.borderSubtle
    }

    // MARK: Attention Section — flat rows, no card wrapper

    var attentionSection: some View {
        let drivers = viewModel.overviewRiskDrivers
        let flagged = drivers.filter { $0.emphasis != .calm }
        let hasAttention = !flagged.isEmpty

        return VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
            HStack(alignment: .firstTextBaseline) {
                Text(hasAttention ? "Needs attention" : "All clear")
                    .font(DesignTokens.sectionTitle)
                    .foregroundStyle(DesignTokens.textPrimary)

                Spacer(minLength: 0)

                if hasAttention {
                    Button(viewModel.nextAction.buttonTitle) {
                        onNavigate(viewModel.handleNextActionTap())
                    }
                    .font(DesignTokens.caption.weight(.semibold))
                    .foregroundStyle(DesignTokens.brandTeal)
                    .buttonStyle(.plain)
                }
            }

            if hasAttention {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(flagged.enumerated()), id: \.element.id) { index, driver in
                        attentionRow(driver)
                        if index < flagged.count - 1 {
                            Divider().padding(.leading, 32)
                        }
                    }
                }
            } else {
                HStack(spacing: DesignTokens.spacingS) {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(DesignTokens.brandTeal)
                    Text(viewModel.overviewSummary.detail)
                        .font(DesignTokens.body)
                        .foregroundStyle(DesignTokens.textSecondary)
                }
                .padding(.vertical, DesignTokens.spacingXS)
            }
        }
    }

    func attentionRow(_ driver: OverviewRiskDriver) -> some View {
        HStack(alignment: .top, spacing: DesignTokens.spacingS) {
            Image(systemName: driverSymbol(for: driver.emphasis))
                .foregroundStyle(driverColor(for: driver.emphasis))
                .frame(width: 20, height: 20)

            VStack(alignment: .leading, spacing: 2) {
                Text(driver.title)
                    .font(DesignTokens.bodyStrong)
                    .foregroundStyle(DesignTokens.textPrimary)
                Text(driver.detail)
                    .font(DesignTokens.caption)
                    .foregroundStyle(DesignTokens.textSecondary)
            }

            Spacer(minLength: 0)
        }
        .padding(.vertical, DesignTokens.spacingS)
    }

    // MARK: Recent Activity — flat rows, no card wrapper

    var recentSection: some View {
        let items = viewModel.overviewActivityPreviewItems

        return VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
            HStack(alignment: .firstTextBaseline) {
                Text("Recent")
                    .font(DesignTokens.sectionTitle)
                    .foregroundStyle(DesignTokens.textPrimary)

                Spacer(minLength: 0)

                if !items.isEmpty {
                    Button("View all") {
                        onNavigate(viewModel.openActivityWorkspace())
                    }
                    .font(DesignTokens.caption.weight(.semibold))
                    .foregroundStyle(DesignTokens.brandTeal)
                    .buttonStyle(.plain)
                }
            }

            if items.isEmpty {
                if viewModel.isRefreshing {
                    ProgressView("Loading activity…")
                        .controlSize(.small)
                        .padding(.vertical, DesignTokens.spacingS)
                } else {
                    Text("Activity will appear here after your next security check.")
                        .font(DesignTokens.body)
                        .foregroundStyle(DesignTokens.textSecondary)
                        .padding(.vertical, DesignTokens.spacingS)
                }
            } else {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(items.enumerated()), id: \.element.id) { index, item in
                        ActivityFeedRowView(item: item)
                        if index < items.count - 1 {
                            Divider().padding(.leading, 42)
                        }
                    }
                }
            }
        }
    }
}

// MARK: - Helpers

private extension OverviewScreen {
    var statusTone: StatusPillTone {
        switch viewModel.overviewSummary.riskLevel {
        case .low: return .positive
        case .medium: return .caution
        case .high: return .critical
        }
    }

    func riskColor(for level: RiskLevel) -> Color {
        switch level {
        case .low: return DesignTokens.brandTeal
        case .medium: return DesignTokens.riskAmber
        case .high: return DesignTokens.riskRed
        }
    }

    func driverSymbol(for emphasis: OverviewRiskDriver.Emphasis) -> String {
        switch emphasis {
        case .calm: return "checkmark.circle.fill"
        case .caution: return "exclamationmark.circle.fill"
        case .critical: return "exclamationmark.triangle.fill"
        }
    }

    func driverColor(for emphasis: OverviewRiskDriver.Emphasis) -> Color {
        switch emphasis {
        case .calm: return DesignTokens.brandTeal
        case .caution: return DesignTokens.riskAmber
        case .critical: return DesignTokens.riskRed
        }
    }

    func relativeDateText(for date: Date) -> String {
        DisplayDateFormatter.relativeAbbreviated.localizedString(for: date, relativeTo: .now)
    }

    func refreshPulse(for level: RiskLevel) {
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

// MARK: - Stagger Animation

private extension View {
    @ViewBuilder
    func staggerIn(hasAppeared: Bool, reduceMotion: Bool, delay: Double) -> some View {
        self
            .opacity(reduceMotion || hasAppeared ? 1 : 0)
            .offset(y: reduceMotion ? 0 : (hasAppeared ? 0 : 8))
            .animation(
                reduceMotion ? nil : .easeOut(duration: 0.18).delay(delay),
                value: hasAppeared
            )
    }
}

// MARK: - Onboarding Step

private enum OnboardingStep {
    case connectProvider
    case addMonitoredEmail
    case runFirstCheck

    var progressIndex: Int {
        switch self {
        case .connectProvider: return 0
        case .addMonitoredEmail: return 1
        case .runFirstCheck: return 2
        }
    }

    var headline: String {
        switch self {
        case .connectProvider: return "Connect your first provider"
        case .addMonitoredEmail: return "Add a monitored email"
        case .runFirstCheck: return "Run your first security check"
        }
    }

    var detail: String {
        switch self {
        case .connectProvider:
            return "Link a provider so SecuPerso can monitor your account activity and sign-ins."
        case .addMonitoredEmail:
            return "Add email addresses to check for data breaches and exposure alerts."
        case .runFirstCheck:
            return "Everything is set up. Run a check to see your security posture."
        }
    }

    var buttonTitle: String {
        switch self {
        case .connectProvider: return "Connect provider"
        case .addMonitoredEmail: return "Add email"
        case .runFirstCheck: return "Run check"
        }
    }

    var contextLine: String {
        switch self {
        case .connectProvider: return "Step 1 of 3 · No providers connected yet"
        case .addMonitoredEmail: return "Step 2 of 3 · Providers connected"
        case .runFirstCheck: return "Step 3 of 3 · Ready to scan"
        }
    }

    var symbol: String {
        switch self {
        case .connectProvider: return "link.badge.plus"
        case .addMonitoredEmail: return "envelope.badge"
        case .runFirstCheck: return "arrow.clockwise.circle.fill"
        }
    }
}
