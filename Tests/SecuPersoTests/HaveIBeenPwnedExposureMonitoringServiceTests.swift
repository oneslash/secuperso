import CryptoKit
import XCTest
import SecuPersoData
import SecuPersoDomain

final class HaveIBeenPwnedExposureMonitoringServiceTests: XCTestCase {
    func testSaveConfigurationAndRefreshMapsBreachPayload() async throws {
        let recorder = RequestRecorder()
        let (preferences, suiteName) = makePreferences()
        defer { preferences.removePersistentDomain(forName: suiteName) }

        let database = try makeDatabase()
        let service = HaveIBeenPwnedExposureMonitoringService(
            secureStore: TestSecureStore(),
            preferences: preferences,
            database: database,
            dataLoader: { request in
                await recorder.record(request)
                let payload = """
                [
                  {
                    "Name": "Adobe",
                    "Title": "Adobe",
                    "BreachDate": "2013-10-04",
                    "AddedDate": "2025-11-03T12:30:00Z",
                    "PwnCount": 152445165,
                    "DataClasses": ["Email addresses", "Passwords"],
                    "IsSensitive": false,
                    "IsSpamList": false
                  }
                ]
                """
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: nil
                )!
                return (Data(payload.utf8), response)
            }
        )

        try await service.saveConfiguration(
            ExposureSourceConfiguration(
                apiKey: "test-api-key",
                userAgent: "SecuPersoTests/1.0"
            )
        )
        _ = try await service.addMonitoredEmail("owner@example.com", providerHint: .other)

        let exposures = try await service.refresh()
        let request = await recorder.firstRequest()

        XCTAssertEqual(exposures.count, 1)
        XCTAssertEqual(exposures.first?.email, "owner@example.com")
        XCTAssertEqual(exposures.first?.source, "Adobe")
        XCTAssertEqual(exposures.first?.severity, .critical)
        XCTAssertEqual(exposures.first?.status, .open)
        XCTAssertEqual(request?.value(forHTTPHeaderField: "hibp-api-key"), "test-api-key")
        XCTAssertEqual(request?.value(forHTTPHeaderField: "user-agent"), "SecuPersoTests/1.0")
        XCTAssertTrue(request?.url?.absoluteString.contains("truncateResponse=false") == true)
    }

    func testRefreshReturnsEmptyWhenConfigurationIsIncomplete() async throws {
        let recorder = RequestRecorder()
        let (preferences, suiteName) = makePreferences()
        defer { preferences.removePersistentDomain(forName: suiteName) }

        let database = try makeDatabase()
        let service = HaveIBeenPwnedExposureMonitoringService(
            secureStore: TestSecureStore(),
            preferences: preferences,
            database: database,
            dataLoader: { request in
                await recorder.record(request)
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: nil
                )!
                return (Data("[]".utf8), response)
            }
        )

        try await service.saveConfiguration(
            ExposureSourceConfiguration(apiKey: "", userAgent: "SecuPersoTests/1.0")
        )
        _ = try await service.addMonitoredEmail("owner@example.com", providerHint: .other)

        let exposures = try await service.refresh()
        let requestCount = await recorder.requestCount()

        XCTAssertTrue(exposures.isEmpty)
        XCTAssertEqual(requestCount, 0)
    }

    func testRefreshThrowsBatchAbortForInvalidKey() async throws {
        let (preferences, suiteName) = makePreferences()
        defer { preferences.removePersistentDomain(forName: suiteName) }

        let database = try makeDatabase()
        let service = HaveIBeenPwnedExposureMonitoringService(
            secureStore: TestSecureStore(),
            preferences: preferences,
            database: database,
            dataLoader: { request in
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 401,
                    httpVersion: nil,
                    headerFields: nil
                )!
                return (Data(), response)
            }
        )

        try await service.saveConfiguration(
            ExposureSourceConfiguration(apiKey: "bad-key", userAgent: "SecuPersoTests/1.0")
        )
        _ = try await service.addMonitoredEmail("owner@example.com", providerHint: .other)

        do {
            _ = try await service.refresh()
            XCTFail("Expected batch abort error")
        } catch let error as SecuPersoDataError {
            guard case .exposureBatchAborted = error else {
                XCTFail("Expected exposureBatchAborted, got \(error)")
                return
            }
        }
    }

    func testRemoveMonitoredEmailCascadesFindingsImmediately() async throws {
        let (preferences, suiteName) = makePreferences()
        defer { preferences.removePersistentDomain(forName: suiteName) }

        let database = try makeDatabase()
        let service = HaveIBeenPwnedExposureMonitoringService(
            secureStore: TestSecureStore(),
            preferences: preferences,
            database: database,
            dataLoader: { request in
                let payload = """
                [
                  {
                    "Name": "Adobe",
                    "Title": "Adobe",
                    "BreachDate": "2013-10-04",
                    "AddedDate": "2025-11-03T12:30:00Z",
                    "PwnCount": 152445165,
                    "DataClasses": ["Email addresses", "Passwords"],
                    "IsSensitive": false,
                    "IsSpamList": false
                  }
                ]
                """
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: nil
                )!
                return (Data(payload.utf8), response)
            }
        )

        try await service.saveConfiguration(
            ExposureSourceConfiguration(apiKey: "test-api-key", userAgent: "SecuPersoTests/1.0")
        )
        let monitored = try await service.addMonitoredEmail("owner@example.com", providerHint: .other)

        _ = try await service.refresh()
        XCTAssertEqual(try database.fetchExposures().count, 1)

        try await service.removeMonitoredEmail(id: monitored.id)
        XCTAssertEqual(try database.fetchExposures().count, 0)
    }

    func testDisablingMonitoredEmailClearsExistingFindings() async throws {
        let (preferences, suiteName) = makePreferences()
        defer { preferences.removePersistentDomain(forName: suiteName) }

        let database = try makeDatabase()
        let service = HaveIBeenPwnedExposureMonitoringService(
            secureStore: TestSecureStore(),
            preferences: preferences,
            database: database,
            dataLoader: { request in
                let payload = """
                [
                  {
                    "Name": "Adobe",
                    "Title": "Adobe",
                    "BreachDate": "2013-10-04",
                    "AddedDate": "2025-11-03T12:30:00Z",
                    "PwnCount": 152445165,
                    "DataClasses": ["Email addresses", "Passwords"],
                    "IsSensitive": false,
                    "IsSpamList": false
                  }
                ]
                """
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: nil
                )!
                return (Data(payload.utf8), response)
            }
        )

        try await service.saveConfiguration(
            ExposureSourceConfiguration(apiKey: "test-api-key", userAgent: "SecuPersoTests/1.0")
        )
        let monitored = try await service.addMonitoredEmail("owner@example.com", providerHint: .other)

        _ = try await service.refresh()
        XCTAssertEqual(try database.fetchExposures().count, 1)

        try await service.setMonitoredEmailEnabled(id: monitored.id, isEnabled: false)

        XCTAssertEqual(try database.fetchExposures().count, 0)
        XCTAssertEqual(try database.fetchMonitoredEmail(id: monitored.id)?.isEnabled, false)
    }

    func testBatchStopsAfterRateLimit() async throws {
        let recorder = RequestRecorder()
        let (preferences, suiteName) = makePreferences()
        defer { preferences.removePersistentDomain(forName: suiteName) }

        let database = try makeDatabase()
        let service = HaveIBeenPwnedExposureMonitoringService(
            secureStore: TestSecureStore(),
            preferences: preferences,
            database: database,
            dataLoader: { request in
                await recorder.record(request)
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 429,
                    httpVersion: nil,
                    headerFields: ["Retry-After": "15"]
                )!
                return (Data(), response)
            },
            requestInterval: .zero
        )

        try await service.saveConfiguration(
            ExposureSourceConfiguration(apiKey: "test-api-key", userAgent: "SecuPersoTests/1.0")
        )
        _ = try await service.addMonitoredEmail("first@example.com", providerHint: .other)
        _ = try await service.addMonitoredEmail("second@example.com", providerHint: .other)

        do {
            _ = try await service.refresh()
            XCTFail("Expected batch abort on 429")
        } catch let error as SecuPersoDataError {
            guard case .exposureBatchAborted(let reason) = error else {
                XCTFail("Expected exposureBatchAborted, got \(error)")
                return
            }
            XCTAssertTrue(reason.contains("Retry after 15"))
        }

        let requestCount = await recorder.requestCount()
        XCTAssertEqual(requestCount, 1)
    }

    func testConcurrentConfigurationReadsAndWritesRemainConsistent() async throws {
        let (preferences, suiteName) = makePreferences()
        defer { preferences.removePersistentDomain(forName: suiteName) }

        let database = try makeDatabase()
        let service = HaveIBeenPwnedExposureMonitoringService(
            secureStore: TestSecureStore(),
            preferences: preferences,
            database: database,
            dataLoader: { request in
                let response = HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: nil
                )!
                return (Data("[]".utf8), response)
            }
        )

        let configurations = (0..<20).map { index in
            ExposureSourceConfiguration(
                apiKey: "api-\(index)",
                userAgent: "SecuPersoTests/\(index)"
            )
        }

        try await withThrowingTaskGroup(of: Void.self) { group in
            for configuration in configurations {
                group.addTask {
                    try await service.saveConfiguration(configuration)
                }
            }

            for _ in 0..<20 {
                group.addTask {
                    _ = try await service.loadConfiguration()
                }
            }

            try await group.waitForAll()
        }

        let finalConfiguration = try await service.loadConfiguration()
        XCTAssertFalse(finalConfiguration.apiKey.isEmpty)
        XCTAssertFalse(finalConfiguration.userAgent.isEmpty)
    }

    private func makePreferences() -> (UserDefaults, String) {
        let suiteName = "HaveIBeenPwnedExposureMonitoringServiceTests.\(UUID().uuidString)"
        guard let preferences = UserDefaults(suiteName: suiteName) else {
            fatalError("Failed to create user defaults suite")
        }
        return (preferences, suiteName)
    }

    private func makeDatabase() throws -> EncryptedSQLiteDatabase {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("hibp-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return try EncryptedSQLiteDatabase(
            databaseURL: directory.appendingPathComponent("database.sqlite", isDirectory: false),
            key: SymmetricKey(size: .bits256)
        )
    }
}

private actor RequestRecorder {
    private var requests: [URLRequest] = []

    func record(_ request: URLRequest) {
        requests.append(request)
    }

    func firstRequest() -> URLRequest? {
        requests.first
    }

    func requestCount() -> Int {
        requests.count
    }
}

private final class TestSecureStore: SecureStore, @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String: Data] = [:]

    func read(_ key: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return storage[key]
    }

    func write(_ value: Data, for key: String) throws {
        lock.lock()
        defer { lock.unlock() }
        storage[key] = value
    }

    func delete(_ key: String) throws {
        lock.lock()
        defer { lock.unlock() }
        storage.removeValue(forKey: key)
    }
}
