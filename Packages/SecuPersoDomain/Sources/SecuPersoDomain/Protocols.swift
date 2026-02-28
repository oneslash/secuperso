import Foundation

public protocol ExposureMonitoringService: Sendable {
    func refresh() async throws -> [ExposureRecord]
    func stream() -> AsyncStream<[ExposureRecord]>
}

public protocol LoginActivityService: Sendable {
    func refresh() async throws -> [LoginEvent]
    func stream() -> AsyncStream<[LoginEvent]>
}

public protocol ProviderConnectionService: Sendable {
    func beginConnection(for provider: ProviderID) async -> AsyncStream<ProviderConnectionUpdate>
    func disconnect(_ provider: ProviderID) async throws
}

public protocol IncidentService: Sendable {
    func create(from loginEventID: UUID) async throws -> IncidentCase
    func resolve(_ incidentID: UUID) async throws
}

public protocol SecureStore: Sendable {
    func read(_ key: String) throws -> Data?
    func write(_ value: Data, for key: String) throws
    func delete(_ key: String) throws
}

public protocol IncidentReadableService: Sendable {
    func list() async throws -> [IncidentCase]
}

public protocol ProviderCatalogService: Sendable {
    func providers() async throws -> [ProviderDescriptor]
}

public protocol ProviderConnectionReadableService: Sendable {
    func connections() async throws -> [ProviderConnection]
}

public protocol ScenarioControlService: Sendable {
    func setScenario(_ scenario: FixtureScenario) async throws
    func currentScenario() async -> FixtureScenario
}

public protocol LoginEventActionService: Sendable {
    func markAsExpected(_ loginEventID: UUID) async throws -> LoginEvent?
}

public protocol ExposureSourceConfigurationService: Sendable {
    func loadConfiguration() async throws -> ExposureSourceConfiguration
    func saveConfiguration(_ configuration: ExposureSourceConfiguration) async throws
}

public protocol MonitoredEmailService: Sendable {
    func listMonitoredEmails() async throws -> [MonitoredEmailAddress]
    func addMonitoredEmail(_ email: String, providerHint: ProviderID) async throws -> MonitoredEmailAddress
    func setMonitoredEmailEnabled(id: UUID, isEnabled: Bool) async throws
    func removeMonitoredEmail(id: UUID) async throws
}
