import Foundation
import SecuPersoDomain

public actor MockDataCoordinator {
    private let fixtureLoader: FixtureDataLoader
    private let database: EncryptedSQLiteDatabase
    private var scenario: FixtureScenario

    public init(
        fixtureLoader: FixtureDataLoader,
        database: EncryptedSQLiteDatabase,
        initialScenario: FixtureScenario = .moderate
    ) {
        self.fixtureLoader = fixtureLoader
        self.database = database
        self.scenario = initialScenario
    }

    public func setScenario(_ scenario: FixtureScenario) {
        self.scenario = scenario
    }

    public func currentScenario() -> FixtureScenario {
        scenario
    }

    public func refreshLoginEvents() throws -> [LoginEvent] {
        let events = try fixtureLoader.loadLoginEvents(for: scenario)
        try database.replaceLoginEvents(events)
        try database.appendAuditEvent("Refreshed login fixtures for scenario: \(scenario.rawValue)")
        return try database.fetchLoginEvents()
    }

    public func markLoginAsExpected(_ loginEventID: UUID) throws -> LoginEvent? {
        guard var loginEvent = try database.fetchLoginEvent(id: loginEventID) else {
            return nil
        }
        loginEvent.expected = true
        loginEvent.suspicious = false
        loginEvent.reason = "Confirmed by user"
        try database.upsertLoginEvent(loginEvent)
        try database.appendAuditEvent("User marked login event \(loginEventID.uuidString) as expected")
        return loginEvent
    }

    public func createIncident(from loginEventID: UUID) throws -> IncidentCase {
        guard let login = try database.fetchLoginEvent(id: loginEventID) else {
            throw SecuPersoDataError.loginEventNotFound(loginEventID)
        }

        let incident = IncidentCase(
            id: UUID(),
            title: "Suspicious \(login.provider.displayName) sign-in",
            severity: login.suspicious ? .high : .medium,
            createdAt: Date(),
            status: .open,
            linkedLoginEventID: login.id,
            notes: "Auto-generated from login activity.",
            resolvedAt: nil
        )

        try database.upsertIncident(incident)
        try database.appendAuditEvent("Created incident \(incident.id.uuidString)")
        return incident
    }

    public func resolveIncident(_ incidentID: UUID) throws {
        guard var incident = try database.fetchIncident(id: incidentID) else {
            throw SecuPersoDataError.incidentNotFound(incidentID)
        }

        incident.status = .resolved
        incident.resolvedAt = Date()
        try database.upsertIncident(incident)
        try database.appendAuditEvent("Resolved incident \(incidentID.uuidString)")
    }

    public func listIncidents() throws -> [IncidentCase] {
        try database.fetchIncidents()
    }

    public func loadProviderCatalog() throws -> [ProviderDescriptor] {
        let providers = try fixtureLoader.loadProviders()
        let existing = try database.fetchProviderConnections()
        let existingIDs = Set(existing.map(\.id))

        for provider in providers where !existingIDs.contains(provider.id) {
            let connection = ProviderConnection(
                id: provider.id,
                state: .disconnected,
                lastUpdatedAt: Date()
            )
            try database.upsertProviderConnection(connection)
        }

        return providers
    }

    public func updateProviderState(_ provider: ProviderID, state: ConnectionState) throws {
        let connection = ProviderConnection(
            id: provider,
            state: state,
            lastUpdatedAt: Date()
        )
        try database.upsertProviderConnection(connection)
        try database.appendAuditEvent("Provider \(provider.rawValue) moved to state \(state.rawValue)")
    }

    public func listProviderConnections() throws -> [ProviderConnection] {
        try database.fetchProviderConnections()
    }
}
