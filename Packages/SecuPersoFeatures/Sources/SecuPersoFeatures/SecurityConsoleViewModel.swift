import Foundation
import SwiftUI
import SecuPersoDomain

@MainActor
public final class SecurityConsoleViewModel: ObservableObject {
    @Published public private(set) var exposures: [ExposureRecord] = []
    @Published public private(set) var loginEvents: [LoginEvent] = []
    @Published public private(set) var incidents: [IncidentCase] = []
    @Published public private(set) var providers: [ProviderDescriptor] = []
    @Published public private(set) var providerStates: [ProviderID: ConnectionState] = [:]

    @Published public private(set) var riskSnapshot = RiskSnapshot(score: 0, level: .low, lastUpdatedAt: Date())
    @Published public private(set) var timelineEvents: [TimelineEvent] = []
    @Published public var scenario: FixtureScenario = .moderate
    @Published public private(set) var isRefreshing = false
    @Published public private(set) var lastRefreshAt: Date?
    @Published public private(set) var presentedError: SecurityConsoleError?

    @Published public var oauthSheetProvider: ProviderID?
    @Published public private(set) var oauthState: ConnectionState = .disconnected
    @Published public private(set) var oauthStep: Int = 0
    @Published public var exposureSourceAPIKey: String = ""
    @Published public var exposureSourceEmail: String = ""
    @Published public var exposureSourceUserAgent: String = "SecuPersoApp/1.0"

    private let exposureService: any ExposureMonitoringService
    private let loginActivityService: any LoginActivityService
    private let incidentService: any IncidentService
    private let incidentReadableService: (any IncidentReadableService)?
    private let providerConnectionService: any ProviderConnectionService
    private let providerConnectionReadableService: (any ProviderConnectionReadableService)?
    private let providerCatalogService: (any ProviderCatalogService)?
    private let scenarioControlService: (any ScenarioControlService)?
    private let loginEventActionService: (any LoginEventActionService)?
    private let exposureConfigurationService: (any ExposureSourceConfigurationService)?
    private let riskEngine: RiskScoringEngine
    private let highRiskNotifier: (@Sendable (RiskSnapshot) async -> Void)?
    private let onRiskRecomputed: ((RiskSnapshot) -> Void)?

    private var streamTasks: [Task<Void, Never>] = []
    private var refreshLoopTask: Task<Void, Never>?
    private var oauthTask: Task<Void, Never>?
    private var riskFlushTask: Task<Void, Never>?
    private var started = false

    private var riskRecomputeSuppressionDepth = 0
    private var pendingRiskRecompute = false
    private var riskFlushScheduled = false

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
        onRiskRecomputed: ((RiskSnapshot) -> Void)? = nil
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
        self.exposureConfigurationService = exposureConfigurationService
        self.scenario = initialScenario
        self.riskEngine = riskEngine
        self.highRiskNotifier = highRiskNotifier
        self.onRiskRecomputed = onRiskRecomputed
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
        beginRiskRecomputeSuppression()
        defer {
            isRefreshing = false
            endRiskRecomputeSuppression()
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
            flushPendingRiskRecomputeIfNeeded()
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
        oauthStep = 0
        oauthState = .connecting

        oauthTask = Task { [weak self] in
            guard let self else { return }

            let stream = await providerConnectionService.beginMockOAuth(for: provider)
            for await state in stream {
                await MainActor.run {
                    self.oauthStep += 1
                    self.oauthState = state
                    self.providerStates[provider] = state
                }
            }

            await self.reloadConnections()
        }
    }

    public func dismissOAuthSheet() {
        oauthSheetProvider = nil
        oauthStep = 0
        oauthState = .disconnected
    }

    public func dismissError() {
        presentedError = nil
    }

    public func disconnect(provider: ProviderID) {
        Task {
            do {
                try await providerConnectionService.disconnect(provider)
                providerStates[provider] = .disconnected
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
                    edited.reason = "Confirmed by user"
                    replaceLoginEvent(edited)
                }
            } catch {
                present(error: error, context: .markLoginAsExpected)
            }
        }
    }

    public var exposureSourceConfigured: Bool {
        !exposureSourceAPIKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !exposureSourceEmail.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    public func saveExposureSourceConfiguration() {
        Task {
            do {
                let configuration = ExposureSourceConfiguration(
                    apiKey: exposureSourceAPIKey,
                    email: exposureSourceEmail,
                    userAgent: exposureSourceUserAgent
                )
                try await exposureConfigurationService?.saveConfiguration(configuration)
                await refreshAll()
            } catch {
                present(error: error, context: .saveExposureSourceConfiguration)
            }
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
        switch oauthState {
        case .connecting:
            return oauthStep <= 1 ? "Opening consent screen..." : "Granting permissions..."
        case .connected:
            return "Provider connected successfully."
        case .error:
            return "Provider connection failed in mock flow."
        case .disconnected:
            return "Provider disconnected."
        }
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
        beginRiskRecomputeSuppression()
        defer {
            endRiskRecomputeSuppression()
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

            if let exposureConfigurationService {
                let configuration = try await exposureConfigurationService.loadConfiguration()
                exposureSourceAPIKey = configuration.apiKey
                exposureSourceEmail = configuration.email
                exposureSourceUserAgent = configuration.userAgent
            }

            await reloadConnections()

            if let incidentReadableService {
                applyIncidents(try await incidentReadableService.list())
            }
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
        rebuildTimelineEvents()
        requestRiskRecompute()
    }

    private func applyLoginEvents(_ values: [LoginEvent]) {
        loginEvents = values
        rebuildTimelineEvents()
        requestRiskRecompute()
    }

    private func applyIncidents(_ values: [IncidentCase]) {
        incidents = values
        rebuildTimelineEvents()
        requestRiskRecompute()
    }

    private func rebuildTimelineEvents() {
        let exposureEvents = exposures.map {
            TimelineEvent(
                kind: .exposure,
                title: "\($0.severity.rawValue.capitalized) exposure",
                details: "\($0.email) from \($0.source)",
                date: $0.foundAt
            )
        }

        let loginTimeline = loginEvents.map {
            TimelineEvent(
                kind: .login,
                title: "\($0.provider.displayName) sign-in",
                details: "\($0.location) · \($0.device)",
                date: $0.occurredAt
            )
        }

        let incidentTimeline = incidents.map {
            TimelineEvent(
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
        onRiskRecomputed?(riskSnapshot)

        if oldLevel != .high, riskSnapshot.level == .high {
            Task {
                await highRiskNotifier?(riskSnapshot)
            }
        }
    }

    private func present(error: any Error, context: SecurityConsoleError.Context) {
        presentedError = SecurityConsoleError(context: context, error: error)
    }
}
