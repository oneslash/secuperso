import XCTest
import SecuPersoDomain
import SecuPersoFeatures

@MainActor
final class SecurityConsoleViewModelTests: XCTestCase {
    func testTimelineCacheRebuildsDuringRefresh() async {
        let exposure = ExposureRecord(
            id: UUID(),
            email: "owner@example.com",
            source: "Breach",
            foundAt: Date(timeIntervalSince1970: 100),
            severity: .high,
            status: .open,
            remediation: "Rotate"
        )
        let login = LoginEvent(
            id: UUID(),
            provider: .google,
            occurredAt: Date(timeIntervalSince1970: 300),
            device: "Mac",
            ipAddress: "203.0.113.8",
            location: "US",
            reason: "Expected",
            suspicious: false,
            expected: true
        )
        let incident = IncidentCase(
            id: UUID(),
            title: "Incident",
            severity: .medium,
            createdAt: Date(timeIntervalSince1970: 200),
            status: .open,
            linkedLoginEventID: login.id,
            notes: "note",
            resolvedAt: nil
        )

        let exposureService = StubExposureService(refreshResult: .success([exposure]))
        let loginService = StubLoginActivityService(refreshResult: .success([login]))
        let incidentService = StubIncidentService(incidents: [incident])
        let providerService = StubProviderConnectionService()

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService
        )

        await viewModel.refreshAll()

        XCTAssertEqual(viewModel.timelineEvents.count, 3)
        XCTAssertEqual(viewModel.timelineEvents.map(\.kind), [.login, .incident, .exposure])
        XCTAssertEqual(viewModel.timelineEvents.first?.title, "Google sign-in")
    }

    func testRefreshAllCoalescesRiskRecomputeIntoSinglePass() async {
        let recomputeCounter = RiskRecomputeCounter()

        let exposure = ExposureRecord(
            id: UUID(),
            email: "owner@example.com",
            source: "Breach",
            foundAt: Date(timeIntervalSince1970: 100),
            severity: .high,
            status: .open,
            remediation: "Rotate"
        )
        let login = LoginEvent(
            id: UUID(),
            provider: .outlook,
            occurredAt: Date(timeIntervalSince1970: 200),
            device: "Windows",
            ipAddress: "198.51.100.44",
            location: "Unknown",
            reason: "Risky",
            suspicious: true,
            expected: false
        )
        let incident = IncidentCase(
            id: UUID(),
            title: "Open incident",
            severity: .high,
            createdAt: Date(timeIntervalSince1970: 150),
            status: .open,
            linkedLoginEventID: login.id,
            notes: "note",
            resolvedAt: nil
        )

        let exposureService = StubExposureService(refreshResult: .success([exposure]))
        let loginService = StubLoginActivityService(refreshResult: .success([login]))
        let incidentService = StubIncidentService(incidents: [incident])
        let providerService = StubProviderConnectionService()

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService,
            onRiskRecomputed: { _ in
                recomputeCounter.increment()
            }
        )

        await viewModel.refreshAll()

        XCTAssertEqual(recomputeCounter.count, 1)
    }

    func testRefreshAllMapsTypedErrorContext() async {
        let expected = StubError(message: "refresh failed")

        let exposureService = StubExposureService(refreshResult: .failure(expected))
        let loginService = StubLoginActivityService(refreshResult: .success([]))
        let incidentService = StubIncidentService(incidents: [])
        let providerService = StubProviderConnectionService()

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService
        )

        await viewModel.refreshAll()

        XCTAssertEqual(viewModel.presentedError?.context, .refreshAll)
        XCTAssertEqual(viewModel.errorMessage, expected.message)
    }

    func testSaveConfigurationMapsTypedErrorContext() async {
        let expected = StubError(message: "save failed")

        let exposureService = StubExposureService(refreshResult: .success([]))
        let loginService = StubLoginActivityService(refreshResult: .success([]))
        let incidentService = StubIncidentService(incidents: [])
        let providerService = StubProviderConnectionService()
        let configurationService = StubExposureSourceConfigurationService(saveError: expected)

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService,
            exposureConfigurationService: configurationService
        )

        viewModel.exposureSourceAPIKey = "api-key"
        viewModel.exposureSourceEmail = "owner@example.com"
        viewModel.exposureSourceUserAgent = "SecuPersoTests/1.0"

        viewModel.saveExposureSourceConfiguration()

        let error = await waitForPresentedError(on: viewModel)
        XCTAssertEqual(error?.context, .saveExposureSourceConfiguration)
        XCTAssertEqual(error?.message, expected.message)
    }

    func testResolveIncidentMapsTypedErrorContext() async {
        let expected = StubError(message: "resolve failed")

        let exposureService = StubExposureService(refreshResult: .success([]))
        let loginService = StubLoginActivityService(refreshResult: .success([]))
        let incidentService = StubIncidentService(incidents: [], resolveError: expected)
        let providerService = StubProviderConnectionService()

        let viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerService,
            providerConnectionReadableService: providerService
        )

        let incident = IncidentCase(
            id: UUID(),
            title: "Needs resolution",
            severity: .medium,
            createdAt: Date(),
            status: .open,
            linkedLoginEventID: UUID(),
            notes: "note",
            resolvedAt: nil
        )

        viewModel.resolveIncident(incident)

        let error = await waitForPresentedError(on: viewModel)
        XCTAssertEqual(error?.context, .resolveIncident)
        XCTAssertEqual(error?.message, expected.message)
    }

    private func waitForPresentedError(
        on viewModel: SecurityConsoleViewModel,
        timeoutNanoseconds: UInt64 = 1_000_000_000
    ) async -> SecurityConsoleError? {
        let step: UInt64 = 20_000_000
        var remaining = timeoutNanoseconds

        while remaining > 0 {
            if let error = viewModel.presentedError {
                return error
            }

            try? await Task.sleep(nanoseconds: step)
            if remaining > step {
                remaining -= step
            } else {
                remaining = 0
            }
        }

        return viewModel.presentedError
    }
}

private struct StubError: Error, LocalizedError {
    let message: String

    var errorDescription: String? {
        message
    }
}

private final class RiskRecomputeCounter {
    private(set) var count = 0

    func increment() {
        count += 1
    }
}

private final class StubExposureService: ExposureMonitoringService, @unchecked Sendable {
    let refreshResult: Result<[ExposureRecord], Error>

    init(refreshResult: Result<[ExposureRecord], Error>) {
        self.refreshResult = refreshResult
    }

    func refresh() async throws -> [ExposureRecord] {
        try refreshResult.get()
    }

    func stream() -> AsyncStream<[ExposureRecord]> {
        AsyncStream { continuation in
            continuation.finish()
        }
    }
}

private final class StubLoginActivityService: LoginActivityService, @unchecked Sendable {
    let refreshResult: Result<[LoginEvent], Error>

    init(refreshResult: Result<[LoginEvent], Error>) {
        self.refreshResult = refreshResult
    }

    func refresh() async throws -> [LoginEvent] {
        try refreshResult.get()
    }

    func stream() -> AsyncStream<[LoginEvent]> {
        AsyncStream { continuation in
            continuation.finish()
        }
    }
}

private final class StubIncidentService: IncidentService, IncidentReadableService, @unchecked Sendable {
    let incidents: [IncidentCase]
    let resolveError: (any Error)?

    init(incidents: [IncidentCase], resolveError: (any Error)? = nil) {
        self.incidents = incidents
        self.resolveError = resolveError
    }

    func create(from loginEventID: UUID) async throws -> IncidentCase {
        IncidentCase(
            id: UUID(),
            title: "Created",
            severity: .medium,
            createdAt: Date(),
            status: .open,
            linkedLoginEventID: loginEventID,
            notes: "mock",
            resolvedAt: nil
        )
    }

    func resolve(_ incidentID: UUID) async throws {
        if let resolveError {
            throw resolveError
        }
    }

    func list() async throws -> [IncidentCase] {
        incidents
    }
}

private final class StubProviderConnectionService: ProviderConnectionService, ProviderConnectionReadableService, @unchecked Sendable {
    func beginMockOAuth(for provider: ProviderID) async -> AsyncStream<ConnectionState> {
        AsyncStream { continuation in
            continuation.finish()
        }
    }

    func disconnect(_ provider: ProviderID) async throws {}

    func connections() async throws -> [ProviderConnection] {
        []
    }
}

private final class StubExposureSourceConfigurationService: ExposureSourceConfigurationService, @unchecked Sendable {
    let saveError: (any Error)?

    init(saveError: (any Error)? = nil) {
        self.saveError = saveError
    }

    func loadConfiguration() async throws -> ExposureSourceConfiguration {
        ExposureSourceConfiguration()
    }

    func saveConfiguration(_ configuration: ExposureSourceConfiguration) async throws {
        if let saveError {
            throw saveError
        }
    }
}
