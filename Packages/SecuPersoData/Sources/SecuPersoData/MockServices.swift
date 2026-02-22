import Foundation
import SecuPersoDomain

public final class MockExposureMonitoringService: ExposureMonitoringService, @unchecked Sendable {
    private let coordinator: MockDataCoordinator
    private let streamStore = StreamStore<[ExposureRecord]>(initialValue: [])

    public init(coordinator: MockDataCoordinator) {
        self.coordinator = coordinator
    }

    public func refresh() async throws -> [ExposureRecord] {
        let exposures = try await coordinator.refreshExposures()
        streamStore.publish(exposures)
        return exposures
    }

    public func stream() -> AsyncStream<[ExposureRecord]> {
        streamStore.makeStream()
    }
}

public final class MockLoginActivityService: LoginActivityService, @unchecked Sendable {
    private let coordinator: MockDataCoordinator
    private let streamStore = StreamStore<[LoginEvent]>(initialValue: [])

    public init(coordinator: MockDataCoordinator) {
        self.coordinator = coordinator
    }

    public func refresh() async throws -> [LoginEvent] {
        let events = try await coordinator.refreshLoginEvents()
        streamStore.publish(events)
        return events
    }

    public func stream() -> AsyncStream<[LoginEvent]> {
        streamStore.makeStream()
    }
}

public final class MockIncidentService: IncidentService, IncidentReadableService, @unchecked Sendable {
    private let coordinator: MockDataCoordinator

    public init(coordinator: MockDataCoordinator) {
        self.coordinator = coordinator
    }

    public func create(from loginEventID: UUID) async throws -> IncidentCase {
        try await coordinator.createIncident(from: loginEventID)
    }

    public func resolve(_ incidentID: UUID) async throws {
        try await coordinator.resolveIncident(incidentID)
    }

    public func list() async throws -> [IncidentCase] {
        try await coordinator.listIncidents()
    }
}

public final class MockProviderConnectionService: ProviderConnectionService, ProviderConnectionReadableService, @unchecked Sendable {
    private let coordinator: MockDataCoordinator

    public init(coordinator: MockDataCoordinator) {
        self.coordinator = coordinator
    }

    public func beginMockOAuth(for provider: ProviderID) async -> AsyncStream<ConnectionState> {
        AsyncStream { continuation in
            Task {
                continuation.yield(.connecting)
                try? await Task.sleep(for: .seconds(1))

                continuation.yield(.connecting)
                try? await Task.sleep(for: .seconds(1))

                let finalState: ConnectionState = provider == .other ? .error : .connected
                try? await coordinator.updateProviderState(provider, state: finalState)
                continuation.yield(finalState)
                continuation.finish()
            }
        }
    }

    public func disconnect(_ provider: ProviderID) async throws {
        try await coordinator.updateProviderState(provider, state: .disconnected)
    }

    public func connections() async throws -> [ProviderConnection] {
        try await coordinator.listProviderConnections()
    }
}

public final class MockProviderCatalogService: ProviderCatalogService, @unchecked Sendable {
    private let coordinator: MockDataCoordinator

    public init(coordinator: MockDataCoordinator) {
        self.coordinator = coordinator
    }

    public func providers() async throws -> [ProviderDescriptor] {
        try await coordinator.loadProviderCatalog()
    }
}

public final class MockScenarioControlService: ScenarioControlService, @unchecked Sendable {
    private let coordinator: MockDataCoordinator

    public init(coordinator: MockDataCoordinator) {
        self.coordinator = coordinator
    }

    public func setScenario(_ scenario: FixtureScenario) async throws {
        await coordinator.setScenario(scenario)
    }

    public func currentScenario() async -> FixtureScenario {
        await coordinator.currentScenario()
    }
}

public final class MockLoginEventActionService: LoginEventActionService, @unchecked Sendable {
    private let coordinator: MockDataCoordinator

    public init(coordinator: MockDataCoordinator) {
        self.coordinator = coordinator
    }

    public func markAsExpected(_ loginEventID: UUID) async throws -> LoginEvent? {
        try await coordinator.markLoginAsExpected(loginEventID)
    }
}
