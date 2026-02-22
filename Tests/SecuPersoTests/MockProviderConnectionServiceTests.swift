import CryptoKit
import XCTest
import SecuPersoData
import SecuPersoDomain

final class MockProviderConnectionServiceTests: XCTestCase {
    func testGoogleMockOAuthEndsConnected() async throws {
        let service = try await makeService()
        let stream = await service.beginMockOAuth(for: .google)

        var states: [ConnectionState] = []
        for await state in stream {
            states.append(state)
        }

        XCTAssertEqual(states.last, .connected)
    }

    func testOtherProviderMockOAuthEndsError() async throws {
        let service = try await makeService()
        let stream = await service.beginMockOAuth(for: .other)

        var states: [ConnectionState] = []
        for await state in stream {
            states.append(state)
        }

        XCTAssertEqual(states.last, .error)
    }

    private func makeService() async throws -> MockProviderConnectionService {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let exposuresURL = directory.appendingPathComponent("exposures.json")
        let loginsURL = directory.appendingPathComponent("login_events.json")
        let providersURL = directory.appendingPathComponent("providers.json")

        try "{\"clean\":[],\"moderate\":[],\"critical\":[]}".write(to: exposuresURL, atomically: true, encoding: .utf8)
        try "{\"clean\":[],\"moderate\":[],\"critical\":[]}".write(to: loginsURL, atomically: true, encoding: .utf8)
        try "[{\"id\":\"google\",\"displayName\":\"Google\",\"details\":\"Mock\"},{\"id\":\"outlook\",\"displayName\":\"Outlook\",\"details\":\"Mock\"},{\"id\":\"other\",\"displayName\":\"Other\",\"details\":\"Mock\"}]".write(to: providersURL, atomically: true, encoding: .utf8)

        let loader = FixtureDataLoader(exposuresURL: exposuresURL, loginEventsURL: loginsURL, providersURL: providersURL)
        let database = try EncryptedSQLiteDatabase(
            databaseURL: directory.appendingPathComponent("secuperso.sqlite"),
            key: SymmetricKey(size: .bits256)
        )

        let coordinator = MockDataCoordinator(fixtureLoader: loader, database: database)
        _ = try await coordinator.loadProviderCatalog()
        return MockProviderConnectionService(coordinator: coordinator)
    }
}
