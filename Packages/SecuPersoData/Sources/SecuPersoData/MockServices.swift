import Foundation
import SecuPersoDomain

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

    public func beginConnection(for provider: ProviderID) async -> AsyncStream<ProviderConnectionUpdate> {
        AsyncStream { continuation in
            let task = Task {
                defer { continuation.finish() }

                do {
                    continuation.yield(ProviderConnectionUpdate(state: .connecting, message: "Opening consent screen..."))
                    try await Task.sleep(for: .seconds(1))
                    try Task.checkCancellation()

                    continuation.yield(ProviderConnectionUpdate(state: .connecting, message: "Granting permissions..."))
                    try await Task.sleep(for: .seconds(1))
                    try Task.checkCancellation()

                    let finalState: ConnectionState = provider == .other ? .error : .connected
                    try await coordinator.updateProviderState(provider, state: finalState)
                    let finalMessage = finalState == .connected
                        ? "Provider connected successfully."
                        : "Provider connection failed in mock flow."
                    continuation.yield(ProviderConnectionUpdate(state: finalState, message: finalMessage))
                } catch is CancellationError {
                    return
                } catch {
                    try? await coordinator.updateProviderState(provider, state: .error)
                    continuation.yield(
                        ProviderConnectionUpdate(
                            state: .error,
                            message: "Provider connection failed in mock flow."
                        )
                    )
                }
            }

            continuation.onTermination = { @Sendable _ in
                task.cancel()
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
