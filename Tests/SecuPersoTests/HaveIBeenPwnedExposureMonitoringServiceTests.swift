import XCTest
import SecuPersoData
import SecuPersoDomain

final class HaveIBeenPwnedExposureMonitoringServiceTests: XCTestCase {
    func testSaveConfigurationAndRefreshMapsBreachPayload() async throws {
        let recorder = RequestRecorder()
        let (preferences, suiteName) = makePreferences()
        defer { preferences.removePersistentDomain(forName: suiteName) }

        let service = HaveIBeenPwnedExposureMonitoringService(
            secureStore: TestSecureStore(),
            preferences: preferences,
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
                email: "owner@example.com",
                userAgent: "SecuPersoTests/1.0"
            )
        )

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

        let service = HaveIBeenPwnedExposureMonitoringService(
            secureStore: TestSecureStore(),
            preferences: preferences,
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
            ExposureSourceConfiguration(apiKey: "", email: "owner@example.com", userAgent: "SecuPersoTests/1.0")
        )

        let exposures = try await service.refresh()
        let requestCount = await recorder.requestCount()

        XCTAssertTrue(exposures.isEmpty)
        XCTAssertEqual(requestCount, 0)
    }

    func testRefreshThrowsUnauthorizedErrorForInvalidKey() async throws {
        let (preferences, suiteName) = makePreferences()
        defer { preferences.removePersistentDomain(forName: suiteName) }

        let service = HaveIBeenPwnedExposureMonitoringService(
            secureStore: TestSecureStore(),
            preferences: preferences,
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
            ExposureSourceConfiguration(apiKey: "bad-key", email: "owner@example.com", userAgent: "SecuPersoTests/1.0")
        )

        do {
            _ = try await service.refresh()
            XCTFail("Expected unauthorized error")
        } catch let error as SecuPersoDataError {
            guard case .remoteRequestRejected(let statusCode, _) = error else {
                XCTFail("Expected remoteRequestRejected, got \(error)")
                return
            }
            XCTAssertEqual(statusCode, 401)
        }
    }

    func testConcurrentConfigurationReadsAndWritesRemainConsistent() async throws {
        let (preferences, suiteName) = makePreferences()
        defer { preferences.removePersistentDomain(forName: suiteName) }

        let service = HaveIBeenPwnedExposureMonitoringService(
            secureStore: TestSecureStore(),
            preferences: preferences,
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
                email: "owner+\(index)@example.com",
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
        XCTAssertFalse(finalConfiguration.email.isEmpty)
        XCTAssertFalse(finalConfiguration.userAgent.isEmpty)
    }

    private func makePreferences() -> (UserDefaults, String) {
        let suiteName = "HaveIBeenPwnedExposureMonitoringServiceTests.\(UUID().uuidString)"
        guard let preferences = UserDefaults(suiteName: suiteName) else {
            fatalError("Failed to create user defaults suite")
        }
        return (preferences, suiteName)
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
}
