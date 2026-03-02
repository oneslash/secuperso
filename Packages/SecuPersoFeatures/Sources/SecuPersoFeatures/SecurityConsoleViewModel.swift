import Foundation
import SwiftUI
import SecuPersoDomain

@MainActor
public final class SecurityConsoleViewModel: ObservableObject {
    public private(set) var exposures: [ExposureRecord] = []
    public private(set) var loginEvents: [LoginEvent] = []
    public private(set) var incidents: [IncidentCase] = []
    public private(set) var providers: [ProviderDescriptor] = []
    public private(set) var providerStates: [ProviderID: ConnectionState] = [:]

    public private(set) var riskSnapshot = RiskSnapshot(score: 0, level: .low, lastUpdatedAt: Date())
    public private(set) var timelineEvents: [TimelineEvent] = []
    @Published public private(set) var overviewSummary = SecurityConsoleViewModel.defaultOverviewSummary()
    @Published public private(set) var nextAction = SecurityConsoleViewModel.defaultNextAction()
    @Published public private(set) var accountCards: [AccountCardSummary] = []
    @Published public private(set) var exposureSummary = SecurityConsoleViewModel.defaultExposureSummary()
    @Published public private(set) var openExposureFindings: [ExposureFindingsGroup] = []
    @Published public private(set) var exposureFindingRows: [ExposureFindingsProjectionRow] = []
    @Published public private(set) var overviewSignals = SecurityConsoleViewModel.defaultOverviewSignalsProjection()
    @Published public private(set) var activityFeed: [ActivityFeedItem] = []
    @Published public private(set) var activityPreview: [ActivityPreviewProjection] = []
    @Published public private(set) var pendingConfirmationAction: PendingConfirmationAction?

    @Published public var activityFilter: ActivityFeedFilter = .needsAttention
    @Published public var scenario: FixtureScenario = .moderate
    @Published public private(set) var isRefreshing = false
    @Published public private(set) var lastRefreshAt: Date?
    @Published public private(set) var presentedError: SecurityConsoleError?

    @Published public var oauthSheetProvider: ProviderID?
    @Published public private(set) var oauthState: ConnectionState = .disconnected
    @Published public private(set) var oauthStatusMessage: String = "Provider disconnected."

    private let exposureService: any ExposureMonitoringService
    private let loginActivityService: any LoginActivityService
    private let incidentService: any IncidentService
    private let incidentReadableService: (any IncidentReadableService)?
    private let providerConnectionService: any ProviderConnectionService
    private let providerConnectionReadableService: (any ProviderConnectionReadableService)?
    private let providerCatalogService: (any ProviderCatalogService)?
    private let scenarioControlService: (any ScenarioControlService)?
    private let loginEventActionService: (any LoginEventActionService)?
    private let riskEngine: RiskScoringEngine
    private let highRiskNotifier: (@Sendable (RiskSnapshot) async -> Void)?
    private let onRiskRecomputed: ((RiskSnapshot) -> Void)?
    private let onViewProjectionsRebuilt: (() -> Void)?
    private let onTimelineRebuilt: (() -> Void)?

    private var streamTasks: [Task<Void, Never>] = []
    private var refreshLoopTask: Task<Void, Never>?
    private var oauthTask: Task<Void, Never>?
    private var riskFlushTask: Task<Void, Never>?
    private var started = false

    private var riskRecomputeSuppressionDepth = 0
    private var pendingRiskRecompute = false
    private var riskFlushScheduled = false

    private var projectionRecomputeSuppressionDepth = 0
    private var pendingProjectionRebuild = false
    private var pendingTimelineRebuild = false

    private let overviewPreviewLimit = 3

    public var errorMessage: String? {
        get { presentedError?.message }
        set {
            if let newValue {
                presentedError = SecurityConsoleError(context: .unknown, message: newValue)
            } else {
                presentedError = nil
            }
        }
    }

    public var filteredActivityFeed: [ActivityFeedItem] {
        switch activityFilter {
        case .needsAttention:
            return activityFeed.filter(\.needsAttention)
        case .all:
            return activityFeed
        }
    }

    public var overviewActivityPreviewItems: [ActivityFeedItem] {
        activityPreview.map(\.item)
    }

    public init(
        exposureService: any ExposureMonitoringService,
        loginActivityService: any LoginActivityService,
        incidentService: any IncidentService,
        incidentReadableService: (any IncidentReadableService)? = nil,
        providerConnectionService: any ProviderConnectionService,
        providerConnectionReadableService: (any ProviderConnectionReadableService)? = nil,
        providerCatalogService: (any ProviderCatalogService)? = nil,
        scenarioControlService: (any ScenarioControlService)? = nil,
        loginEventActionService: (any LoginEventActionService)? = nil,
        exposureConfigurationService: (any ExposureSourceConfigurationService)? = nil,
        initialScenario: FixtureScenario = .moderate,
        riskEngine: RiskScoringEngine = RiskScoringEngine(),
        highRiskNotifier: (@Sendable (RiskSnapshot) async -> Void)? = nil,
        onRiskRecomputed: ((RiskSnapshot) -> Void)? = nil,
        onViewProjectionsRebuilt: (() -> Void)? = nil,
        onTimelineRebuilt: (() -> Void)? = nil
    ) {
        self.exposureService = exposureService
        self.loginActivityService = loginActivityService
        self.incidentService = incidentService
        self.incidentReadableService = incidentReadableService
        self.providerConnectionService = providerConnectionService
        self.providerConnectionReadableService = providerConnectionReadableService
        self.providerCatalogService = providerCatalogService
        self.scenarioControlService = scenarioControlService
        self.loginEventActionService = loginEventActionService
        _ = exposureConfigurationService
        self.scenario = initialScenario
        self.riskEngine = riskEngine
        self.highRiskNotifier = highRiskNotifier
        self.onRiskRecomputed = onRiskRecomputed
        self.onViewProjectionsRebuilt = onViewProjectionsRebuilt
        self.onTimelineRebuilt = onTimelineRebuilt
    }

    deinit {
        streamTasks.forEach { $0.cancel() }
        refreshLoopTask?.cancel()
        oauthTask?.cancel()
        riskFlushTask?.cancel()
    }

    public func start() {
        guard !started else { return }
        started = true

        subscribeStreams()

        Task {
            await loadStaticData()
            await refreshAll()
        }

        refreshLoopTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(300))
                guard let self else { continue }
                await self.refreshAll()
            }
        }
    }

    public func refreshAll() async {
        isRefreshing = true
        beginProjectionRecomputeSuppression()
        beginRiskRecomputeSuppression()
        defer {
            endRiskRecomputeSuppression()
            endProjectionRecomputeSuppression()
            isRefreshing = false
        }

        do {
            async let refreshedExposures = exposureService.refresh()
            async let refreshedLogins = loginActivityService.refresh()
            let exposureResults = try await refreshedExposures
            let loginResults = try await refreshedLogins

            applyExposures(exposureResults)
            applyLoginEvents(loginResults)

            if let incidentReadableService {
                applyIncidents(try await incidentReadableService.list())
            }
            if let providerConnectionReadableService {
                let connections = try await providerConnectionReadableService.connections()
                applyProviderStates(connections)
            }

            lastRefreshAt = Date()
        } catch {
            present(error: error, context: .refreshAll)
        }
    }

    public func setScenario(_ scenario: FixtureScenario) {
        guard self.scenario != scenario else {
            return
        }

        self.scenario = scenario
        Task {
            do {
                try await scenarioControlService?.setScenario(scenario)
                await refreshAll()
            } catch {
                present(error: error, context: .setScenario)
            }
        }
    }

    public func beginConnectFlow(for provider: ProviderID) {
        oauthTask?.cancel()
        oauthSheetProvider = provider
        oauthState = .connecting
        oauthStatusMessage = "Opening consent screen..."

        oauthTask = Task { [weak self] in
            guard let self else { return }

            let stream = await providerConnectionService.beginConnection(for: provider)
            for await update in stream {
                await MainActor.run {
                    self.oauthState = update.state
                    self.oauthStatusMessage = update.message
                    self.providerStates[provider] = update.state
                    self.requestViewProjectionRebuild()
                }
            }

            await self.reloadConnections()
        }
    }

    public func dismissOAuthSheet() {
        guard oauthSheetProvider != nil || oauthState != .disconnected || oauthStatusMessage != "Provider disconnected." else {
            return
        }
        oauthSheetProvider = nil
        oauthState = .disconnected
        oauthStatusMessage = "Provider disconnected."
    }

    public func dismissError() {
        guard presentedError != nil else {
            return
        }
        presentedError = nil
    }

    public func disconnect(provider: ProviderID) {
        Task {
            do {
                try await providerConnectionService.disconnect(provider)
                providerStates[provider] = .disconnected
                requestViewProjectionRebuild()
                await reloadConnections()
            } catch {
                present(error: error, context: .disconnectProvider)
            }
        }
    }

    public func markAsMe(_ login: LoginEvent) {
        Task {
            do {
                if let updated = try await loginEventActionService?.markAsExpected(login.id) {
                    replaceLoginEvent(updated)
                } else {
                    var edited = login
                    edited.suspicious = false
                    edited.expected = true
                    edited.reason = "Confirmed by you"
                    replaceLoginEvent(edited)
                }
            } catch {
                present(error: error, context: .markLoginAsExpected)
            }
        }
    }

    public func requestMarkAsMe(_ login: LoginEvent) {
        pendingConfirmationAction = PendingConfirmationAction(
            title: "Confirm sign-in",
            message: "Mark this sign-in as expected?",
            confirmTitle: "Mark as me",
            isDestructive: false,
            kind: .markLoginAsExpected(loginID: login.id)
        )
    }

    public func requestCreateIncident(_ login: LoginEvent) {
        pendingConfirmationAction = PendingConfirmationAction(
            title: "Create incident",
            message: "Create an incident for this suspicious sign-in?",
            confirmTitle: "Create incident",
            isDestructive: false,
            kind: .createIncident(loginID: login.id)
        )
    }

    public func requestResolveIncident(_ incident: IncidentCase) {
        pendingConfirmationAction = PendingConfirmationAction(
            title: "Resolve incident",
            message: "Mark this incident as resolved?",
            confirmTitle: "Resolve",
            isDestructive: true,
            kind: .resolveIncident(incidentID: incident.id)
        )
    }

    public func confirmPendingAction() {
        guard let action = pendingConfirmationAction else {
            return
        }

        pendingConfirmationAction = nil

        switch action.kind {
        case let .markLoginAsExpected(loginID):
            guard let login = loginEvents.first(where: { $0.id == loginID }) else {
                return
            }
            markAsMe(login)
        case let .createIncident(loginID):
            guard let login = loginEvents.first(where: { $0.id == loginID }) else {
                return
            }
            createIncident(for: login)
        case let .resolveIncident(incidentID):
            guard let incident = incidents.first(where: { $0.id == incidentID && $0.status == .open }) else {
                return
            }
            resolveIncident(incident)
        }
    }

    public func cancelPendingAction() {
        guard pendingConfirmationAction != nil else {
            return
        }
        pendingConfirmationAction = nil
    }

    public func handleNextActionTap() -> AppSection {
        switch nextAction.kind {
        case .reviewHighRiskExposure:
            return .exposure
        case .reviewSuspiciousLogin, .reviewIncident:
            activityFilter = .needsAttention
            return .activity
        case .connectProvider:
            return .integrations
        case .runSecurityCheck:
            Task {
                await refreshAll()
            }
            return .overview
        }
    }

    public func createIncident(for login: LoginEvent) {
        Task {
            do {
                let incident = try await incidentService.create(from: login.id)
                var updatedIncidents = incidents
                updatedIncidents.insert(incident, at: 0)
                applyIncidents(updatedIncidents)
            } catch {
                present(error: error, context: .createIncident)
            }
        }
    }

    public func resolveIncident(_ incident: IncidentCase) {
        Task {
            do {
                try await incidentService.resolve(incident.id)
                var updatedIncidents = incidents
                if let index = updatedIncidents.firstIndex(where: { $0.id == incident.id }) {
                    updatedIncidents[index].status = .resolved
                    updatedIncidents[index].resolvedAt = Date()
                    applyIncidents(updatedIncidents)
                }
            } catch {
                present(error: error, context: .resolveIncident)
            }
        }
    }

    public var unresolvedIncidentCount: Int {
        incidents.filter { $0.status == .open }.count
    }

    public var suspiciousLoginsCount: Int {
        loginEvents.filter { $0.suspicious || !$0.expected }.count
    }

    public var newExposureCount: Int {
        exposures.filter { $0.status == .open }.count
    }

    public var oauthStatusText: String {
        oauthStatusMessage
    }

    private func subscribeStreams() {
        let exposureTask = Task { [weak self] in
            guard let self else { return }
            for await values in exposureService.stream() {
                await MainActor.run {
                    self.applyExposures(values)
                }
            }
        }

        let loginTask = Task { [weak self] in
            guard let self else { return }
            for await values in loginActivityService.stream() {
                await MainActor.run {
                    self.applyLoginEvents(values)
                }
            }
        }

        streamTasks = [exposureTask, loginTask]
    }

    private func loadStaticData() async {
        beginProjectionRecomputeSuppression()
        beginRiskRecomputeSuppression()
        defer {
            endRiskRecomputeSuppression()
            endProjectionRecomputeSuppression()
        }

        do {
            if let providerCatalogService {
                providers = try await providerCatalogService.providers()
            } else {
                providers = ProviderID.allCases.map {
                    ProviderDescriptor(id: $0, displayName: $0.displayName, details: "Mock provider")
                }
            }

            if let scenarioControlService {
                scenario = await scenarioControlService.currentScenario()
            }

            await reloadConnections()

            if let incidentReadableService {
                applyIncidents(try await incidentReadableService.list())
            }

            requestViewProjectionRebuild()
        } catch {
            present(error: error, context: .loadStaticData)
        }
    }

    private func reloadConnections() async {
        do {
            if let providerConnectionReadableService {
                applyProviderStates(try await providerConnectionReadableService.connections())
            }
        } catch {
            present(error: error, context: .reloadConnections)
        }
    }

    private func applyProviderStates(_ connections: [ProviderConnection]) {
        providerStates = Dictionary(uniqueKeysWithValues: connections.map { ($0.id, $0.state) })
        requestViewProjectionRebuild()
    }

    private func replaceLoginEvent(_ loginEvent: LoginEvent) {
        var updatedLogins = loginEvents
        if let index = updatedLogins.firstIndex(where: { $0.id == loginEvent.id }) {
            updatedLogins[index] = loginEvent
            applyLoginEvents(updatedLogins)
        }
    }

    private func applyExposures(_ values: [ExposureRecord]) {
        exposures = values
        requestTimelineRebuild()
        requestViewProjectionRebuild()
        requestRiskRecompute()
    }

    private func applyLoginEvents(_ values: [LoginEvent]) {
        loginEvents = values
        requestTimelineRebuild()
        requestViewProjectionRebuild()
        requestRiskRecompute()
    }

    private func applyIncidents(_ values: [IncidentCase]) {
        incidents = values
        requestTimelineRebuild()
        requestViewProjectionRebuild()
        requestRiskRecompute()
    }

    private func beginProjectionRecomputeSuppression() {
        projectionRecomputeSuppressionDepth += 1
    }

    private func endProjectionRecomputeSuppression() {
        projectionRecomputeSuppressionDepth = max(0, projectionRecomputeSuppressionDepth - 1)
        if projectionRecomputeSuppressionDepth == 0 {
            flushPendingProjectionRebuildsIfNeeded()
        }
    }

    private func requestViewProjectionRebuild() {
        pendingProjectionRebuild = true
        guard projectionRecomputeSuppressionDepth == 0 else {
            return
        }

        flushPendingProjectionRebuildsIfNeeded()
    }

    private func requestTimelineRebuild() {
        pendingTimelineRebuild = true
        guard projectionRecomputeSuppressionDepth == 0 else {
            return
        }

        flushPendingProjectionRebuildsIfNeeded()
    }

    private func flushPendingProjectionRebuildsIfNeeded() {
        guard projectionRecomputeSuppressionDepth == 0 else {
            return
        }

        if pendingTimelineRebuild {
            pendingTimelineRebuild = false
            rebuildTimelineEvents()
        }

        if pendingProjectionRebuild {
            pendingProjectionRebuild = false
            rebuildViewProjections()
        }
    }

    private func rebuildTimelineEvents() {
        let exposureEvents = exposures.map {
            TimelineEvent(
                id: "exposure-\($0.id.uuidString)",
                kind: .exposure,
                title: "\($0.severity.rawValue.capitalized) exposure",
                details: "\($0.email) from \($0.source)",
                date: $0.foundAt
            )
        }

        let loginTimeline = loginEvents.map {
            TimelineEvent(
                id: "login-\($0.id.uuidString)",
                kind: .login,
                title: "\($0.provider.displayName) sign-in",
                details: "\($0.location) · \($0.device)",
                date: $0.occurredAt
            )
        }

        let incidentTimeline = incidents.map {
            TimelineEvent(
                id: "incident-\($0.id.uuidString)",
                kind: .incident,
                title: $0.title,
                details: "Status: \($0.status.rawValue)",
                date: $0.createdAt
            )
        }

        timelineEvents = (exposureEvents + loginTimeline + incidentTimeline)
            .sorted(by: { $0.date > $1.date })
            .prefix(12)
            .map { $0 }
        onTimelineRebuilt?()
    }

    private func beginRiskRecomputeSuppression() {
        riskRecomputeSuppressionDepth += 1
    }

    private func endRiskRecomputeSuppression() {
        riskRecomputeSuppressionDepth = max(0, riskRecomputeSuppressionDepth - 1)
        if riskRecomputeSuppressionDepth == 0 {
            flushPendingRiskRecomputeIfNeeded()
        }
    }

    private func requestRiskRecompute() {
        pendingRiskRecompute = true

        guard riskRecomputeSuppressionDepth == 0 else {
            return
        }

        scheduleRiskRecomputeFlush()
    }

    private func scheduleRiskRecomputeFlush() {
        guard !riskFlushScheduled else { return }
        riskFlushScheduled = true

        riskFlushTask?.cancel()
        riskFlushTask = Task { @MainActor [weak self] in
            guard let self else { return }
            self.riskFlushScheduled = false
            self.flushPendingRiskRecomputeIfNeeded()
        }
    }

    private func flushPendingRiskRecomputeIfNeeded() {
        guard riskRecomputeSuppressionDepth == 0, pendingRiskRecompute else {
            return
        }

        pendingRiskRecompute = false
        recomputeRisk()
    }

    private func recomputeRisk() {
        let oldLevel = riskSnapshot.level
        riskSnapshot = riskEngine.score(exposures: exposures, logins: loginEvents, incidents: incidents, now: Date())
        requestViewProjectionRebuild()
        onRiskRecomputed?(riskSnapshot)

        if oldLevel != .high, riskSnapshot.level == .high {
            Task {
                await highRiskNotifier?(riskSnapshot)
            }
        }
    }

    private func rebuildViewProjections() {
        let projectedAccountCards = buildAccountCards()
        let projectedExposureSummary = buildExposureSummary()
        let projectedOpenExposureFindings = buildOpenExposureFindings()
        let projectedExposureFindingRows = buildExposureFindingRows(from: projectedOpenExposureFindings)
        let projectedActivityFeed = buildActivityFeed()
        let projectedOverviewSignals = buildOverviewSignalsProjection(accountCards: projectedAccountCards)
        let projectedOverviewSummary = buildOverviewSummary(signals: projectedOverviewSignals)
        let projectedActivityPreview = buildActivityPreview(from: projectedActivityFeed)
        let projectedNextAction = buildNextAction()

        accountCards = projectedAccountCards
        exposureSummary = projectedExposureSummary
        openExposureFindings = projectedOpenExposureFindings
        exposureFindingRows = projectedExposureFindingRows
        activityFeed = projectedActivityFeed
        overviewSignals = projectedOverviewSignals
        overviewSummary = projectedOverviewSummary
        activityPreview = projectedActivityPreview
        nextAction = projectedNextAction
        onViewProjectionsRebuilt?()
    }

    private func buildOverviewSummary(signals: OverviewSignalsProjection) -> OverviewSummary {
        let stateLabel: String
        let headline: String
        switch riskSnapshot.level {
        case .low:
            stateLabel = "Stable"
            headline = "No critical risks detected"
        case .medium:
            stateLabel = "Needs attention"
            headline = "Review pending security signals"
        case .high:
            stateLabel = "At risk"
            headline = "Immediate review required"
        }

        let detail = "\(newExposureCount) open exposure alerts · \(signals.suspiciousSignInCount) suspicious sign-ins · \(signals.openIncidentCount) open incidents"

        return OverviewSummary(
            riskScore: riskSnapshot.score,
            riskLevel: riskSnapshot.level,
            stateLabel: stateLabel,
            headline: headline,
            detail: detail,
            lastUpdatedAt: riskSnapshot.lastUpdatedAt
        )
    }

    private func buildOverviewSignalsProjection(accountCards: [AccountCardSummary]) -> OverviewSignalsProjection {
        let suspiciousSignInCount = loginEvents.filter { $0.suspicious || !$0.expected }.count
        let openIncidentCount = incidents.filter { $0.status == .open }.count
        let connectedProviderCount = accountCards.filter { $0.connectionState == .connected }.count
        let totalProviderCount = max(accountCards.count, 1)

        return OverviewSignalsProjection(
            suspiciousSignInCount: suspiciousSignInCount,
            openIncidentCount: openIncidentCount,
            connectedProviderCount: connectedProviderCount,
            totalProviderCount: totalProviderCount
        )
    }

    private func buildExposureSummary() -> ExposureSummary {
        let openExposures = exposures.filter { $0.status == .open }
        let highRiskOpenCount = openExposures.filter { $0.severity == .critical || $0.severity == .high }.count
        let affectedEmailCount = Set(openExposures.map(\.email)).count
        let mostRecentAt = openExposures.max(by: { $0.foundAt < $1.foundAt })?.foundAt

        let headline: String
        if openExposures.isEmpty {
            headline = "No open exposure alerts"
        } else if highRiskOpenCount > 0 {
            headline = "High-priority exposure alerts found"
        } else {
            headline = "Exposure alerts need review"
        }

        let detail = openExposures.isEmpty
            ? "Your monitored emails currently have no open exposure findings."
            : "\(openExposures.count) open alert(s) across \(affectedEmailCount) email address(es)."

        return ExposureSummary(
            openCount: openExposures.count,
            highRiskOpenCount: highRiskOpenCount,
            affectedEmailCount: affectedEmailCount,
            mostRecentAt: mostRecentAt,
            headline: headline,
            detail: detail
        )
    }

    private func buildOpenExposureFindings() -> [ExposureFindingsGroup] {
        let grouped = Dictionary(grouping: exposures.filter { $0.status == .open }, by: \.email)
        return grouped.keys.sorted().map { email in
            let findings = (grouped[email] ?? []).sorted(by: { $0.foundAt > $1.foundAt })
            return ExposureFindingsGroup(email: email, findings: findings)
        }
    }

    private func buildExposureFindingRows(from groups: [ExposureFindingsGroup]) -> [ExposureFindingsProjectionRow] {
        groups.flatMap { group in
            group.findings.map { finding in
                ExposureFindingsProjectionRow(
                    id: finding.id,
                    email: group.email,
                    source: finding.source,
                    foundAt: finding.foundAt,
                    severity: finding.severity,
                    remediation: finding.remediation
                )
            }
        }
    }

    private func buildAccountCards() -> [AccountCardSummary] {
        let providerSource: [ProviderDescriptor] = providers.isEmpty
            ? ProviderID.allCases.map {
                ProviderDescriptor(id: $0, displayName: $0.displayName, details: "Mock provider")
            }
            : providers

        return providerSource.map { provider in
            let state = providerStates[provider.id] ?? .disconnected
            let providerLogins = loginEvents
                .filter { $0.provider == provider.id }
                .sorted(by: { $0.occurredAt > $1.occurredAt })

            let suspiciousCount = providerLogins.filter { $0.suspicious || !$0.expected }.count
            let latestLogin = providerLogins.first

            return AccountCardSummary(
                providerID: provider.id,
                providerName: provider.displayName,
                details: provider.details,
                connectionState: state,
                suspiciousLoginCount: suspiciousCount,
                latestLoginAt: latestLogin?.occurredAt,
                latestLoginSummary: latestLogin.map { "\($0.location) · \($0.device)" },
                needsAttention: state != .connected || suspiciousCount > 0
            )
        }
    }

    private func buildActivityFeed() -> [ActivityFeedItem] {
        let openIncidentLoginIDs = Set(incidents.filter { $0.status == .open }.map(\.linkedLoginEventID))

        let exposureItems = exposures.map { exposure in
            let needsAttention = exposure.status == .open
            let severity: ActivityFeedItem.Severity
            if exposure.severity == .critical || exposure.severity == .high {
                severity = .warning
            } else if exposure.severity == .medium {
                severity = .caution
            } else {
                severity = .neutral
            }

            return ActivityFeedItem(
                id: "exposure-\(exposure.id.uuidString)",
                kind: .exposure,
                date: exposure.foundAt,
                title: "Exposure alert for \(exposure.email)",
                detail: "\(exposure.source) · \(exposure.severity.rawValue.capitalized) · \(exposure.status.rawValue.capitalized)",
                severity: severity,
                needsAttention: needsAttention,
                actions: []
            )
        }

        let loginItems = loginEvents.map { event in
            let needsAttention = event.suspicious || !event.expected
            let severity: ActivityFeedItem.Severity = event.suspicious ? .warning : (needsAttention ? .caution : .neutral)

            var actions: [ActivityFeedAction] = []
            if needsAttention {
                actions.append(
                    ActivityFeedAction(
                        id: "mark-login-\(event.id.uuidString)",
                        title: "Mark as me",
                        kind: .markLoginAsExpected(loginID: event.id)
                    )
                )

                if !openIncidentLoginIDs.contains(event.id) {
                    actions.append(
                        ActivityFeedAction(
                            id: "create-incident-\(event.id.uuidString)",
                            title: "Create incident",
                            kind: .createIncident(loginID: event.id)
                        )
                    )
                }
            }

            return ActivityFeedItem(
                id: "login-\(event.id.uuidString)",
                kind: .login,
                date: event.occurredAt,
                title: "\(event.provider.displayName) sign-in",
                detail: loginDetail(for: event),
                severity: severity,
                needsAttention: needsAttention,
                actions: actions
            )
        }

        let incidentItems = incidents.map { incident in
            let isOpen = incident.status == .open
            let actions: [ActivityFeedAction] = isOpen
                ? [
                    ActivityFeedAction(
                        id: "resolve-incident-\(incident.id.uuidString)",
                        title: "Resolve incident",
                        kind: .resolveIncident(incidentID: incident.id)
                    )
                ]
                : []

            return ActivityFeedItem(
                id: "incident-\(incident.id.uuidString)",
                kind: .incident,
                date: incident.createdAt,
                title: incident.title,
                detail: "\(incident.severity.rawValue.capitalized) severity · \(incident.status.rawValue.capitalized)",
                severity: isOpen ? .warning : .neutral,
                needsAttention: isOpen,
                actions: actions
            )
        }

        return (exposureItems + loginItems + incidentItems)
            .sorted(by: { $0.date > $1.date })
    }

    private func buildActivityPreview(from items: [ActivityFeedItem]) -> [ActivityPreviewProjection] {
        items
            .sorted { lhs, rhs in
                if lhs.needsAttention != rhs.needsAttention {
                    return lhs.needsAttention && !rhs.needsAttention
                }
                return lhs.date > rhs.date
            }
            .prefix(overviewPreviewLimit)
            .map { ActivityPreviewProjection(item: $0) }
    }

    private func buildNextAction() -> NextAction {
        if let exposure = exposures
            .filter({ $0.status == .open && ($0.severity == .critical || $0.severity == .high) })
            .sorted(by: { $0.foundAt > $1.foundAt })
            .first {
            return NextAction(
                kind: .reviewHighRiskExposure(exposureID: exposure.id),
                title: "Review high-priority exposure",
                detail: "\(exposure.email) appears in \(exposure.source).",
                buttonTitle: "Review exposure",
                destinationSection: .exposure
            )
        }

        if let login = loginEvents
            .filter({ $0.suspicious || !$0.expected })
            .sorted(by: { $0.occurredAt > $1.occurredAt })
            .first {
            return NextAction(
                kind: .reviewSuspiciousLogin(loginID: login.id),
                title: "Review suspicious sign-in",
                detail: "\(login.provider.displayName) sign-in from \(login.location).",
                buttonTitle: "Review sign-in",
                destinationSection: .activity
            )
        }

        if let incident = incidents
            .filter({ $0.status == .open })
            .sorted(by: { $0.createdAt > $1.createdAt })
            .first {
            return NextAction(
                kind: .reviewIncident(incidentID: incident.id),
                title: "Resolve open incident",
                detail: incident.title,
                buttonTitle: "Resolve incident",
                destinationSection: .activity
            )
        }

        let providerSource: [ProviderDescriptor] = providers.isEmpty
            ? ProviderID.allCases.map {
                ProviderDescriptor(id: $0, displayName: $0.displayName, details: "Mock provider")
            }
            : providers

        if let disconnectedProvider = providerSource.first(where: { (providerStates[$0.id] ?? .disconnected) != .connected }) {
            return NextAction(
                kind: .connectProvider(providerID: disconnectedProvider.id),
                title: "Connect another account",
                detail: "Add \(disconnectedProvider.displayName) to improve monitoring coverage.",
                buttonTitle: "Connect provider",
                destinationSection: .integrations
            )
        }

        return SecurityConsoleViewModel.defaultNextAction()
    }

    private func present(error: any Error, context: SecurityConsoleError.Context) {
        presentedError = SecurityConsoleError(context: context, error: error)
    }

    private func loginDetail(for event: LoginEvent) -> String {
        let accountContext = event.providerAccountEmail.map { "\($0) · " } ?? ""
        return "\(accountContext)\(event.location) · \(event.device) · \(event.reason)"
    }

    private static func defaultOverviewSummary() -> OverviewSummary {
        OverviewSummary(
            riskScore: 0,
            riskLevel: .low,
            stateLabel: "Stable",
            headline: "No critical risks detected",
            detail: "No activity has been loaded yet.",
            lastUpdatedAt: Date()
        )
    }

    private static func defaultNextAction() -> NextAction {
        NextAction(
            kind: .runSecurityCheck,
            title: "Run a quick security check",
            detail: "Refresh to pull the latest account activity.",
            buttonTitle: "Run check",
            destinationSection: .overview
        )
    }

    private static func defaultExposureSummary() -> ExposureSummary {
        ExposureSummary(
            openCount: 0,
            highRiskOpenCount: 0,
            affectedEmailCount: 0,
            mostRecentAt: nil,
            headline: "No open exposure alerts",
            detail: "Your monitored emails currently have no open exposure findings."
        )
    }

    private static func defaultOverviewSignalsProjection() -> OverviewSignalsProjection {
        OverviewSignalsProjection(
            suspiciousSignInCount: 0,
            openIncidentCount: 0,
            connectedProviderCount: 0,
            totalProviderCount: 1
        )
    }
}
