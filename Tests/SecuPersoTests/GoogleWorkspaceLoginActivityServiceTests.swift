import XCTest
import SecuPersoData
import SecuPersoDomain

final class GoogleWorkspaceLoginActivityServiceTests: XCTestCase {
    private let fixedNow = Date(timeIntervalSince1970: 1_772_432_000) // 2026-03-02T00:00:00Z
    private let reportsScope = "https://www.googleapis.com/auth/admin.reports.audit.readonly"

    func testRefreshFallsBackWhenTokenIsUnavailable() async throws {
        let fallbackGoogle = makeLoginEvent(
            id: "91A6C9DD-F4D1-4E6F-A501-8B26AF3F0B01",
            provider: .google,
            occurredAt: fixedNow.addingTimeInterval(-120),
            ip: "203.0.113.5",
            suspicious: false
        )
        let fallbackOutlook = makeLoginEvent(
            id: "B6A8E7A9-5965-4F26-8D0D-DA5482853501",
            provider: .outlook,
            occurredAt: fixedNow.addingTimeInterval(-60),
            ip: "198.51.100.8",
            suspicious: true
        )
        let fallbackService = StubLoginActivityService(events: [fallbackGoogle, fallbackOutlook])
        let historyClient = StubGoogleWorkspaceLoginHistoryClient(
            result: .success([
                makeLoginEvent(
                    id: "2D06A782-BE1D-4A93-BE74-A1E5E3B03A01",
                    provider: .google,
                    occurredAt: fixedNow.addingTimeInterval(-30),
                    ip: "198.51.100.99",
                    suspicious: true
                )
            ])
        )
        let tokenStore = GoogleOAuthTokenStore(
            secureStore: InMemorySecureStore(),
            storageKey: "test.google.workspace.token.unavailable"
        )
        let fixedNow = self.fixedNow
        let service = GoogleWorkspaceLoginActivityService(
            fallbackService: fallbackService,
            oauthConfiguration: nil,
            tokenStore: tokenStore,
            tokenRefresher: nil,
            historyClient: historyClient,
            nowProvider: { fixedNow }
        )

        let refreshed = try await service.refresh()
        let requestCount = await historyClient.requestCount()

        XCTAssertEqual(refreshed, [fallbackOutlook, fallbackGoogle])
        XCTAssertEqual(requestCount, 0)
    }

    func testRefreshReplacesFallbackGoogleEventsWhenWorkspaceFetchSucceeds() async throws {
        let fallbackGoogle = makeLoginEvent(
            id: "91A6C9DD-F4D1-4E6F-A501-8B26AF3F0B11",
            provider: .google,
            occurredAt: fixedNow.addingTimeInterval(-600),
            ip: "203.0.113.6",
            suspicious: false
        )
        let fallbackOutlook = makeLoginEvent(
            id: "B6A8E7A9-5965-4F26-8D0D-DA5482853511",
            provider: .outlook,
            occurredAt: fixedNow.addingTimeInterval(-300),
            ip: "198.51.100.18",
            suspicious: false
        )
        let remoteGoogle = makeLoginEvent(
            id: "2D06A782-BE1D-4A93-BE74-A1E5E3B03A11",
            provider: .google,
            occurredAt: fixedNow.addingTimeInterval(-30),
            ip: "198.51.100.199",
            suspicious: true
        )
        let fallbackService = StubLoginActivityService(events: [fallbackGoogle, fallbackOutlook])
        let historyClient = StubGoogleWorkspaceLoginHistoryClient(result: .success([remoteGoogle]))
        let secureStore = InMemorySecureStore()
        let tokenStore = GoogleOAuthTokenStore(
            secureStore: secureStore,
            storageKey: "test.google.workspace.token.merge"
        )
        try tokenStore.save(
            GoogleOAuthToken(
                accessToken: "access-token",
                refreshToken: "refresh-token",
                expiresIn: 3600,
                scope: "openid profile email \(reportsScope)",
                tokenType: "Bearer"
            ),
            obtainedAt: fixedNow.addingTimeInterval(-120)
        )

        let fixedNow = self.fixedNow
        let service = GoogleWorkspaceLoginActivityService(
            fallbackService: fallbackService,
            oauthConfiguration: nil,
            tokenStore: tokenStore,
            tokenRefresher: nil,
            historyClient: historyClient,
            nowProvider: { fixedNow }
        )

        let refreshed = try await service.refresh()
        let requestCount = await historyClient.requestCount()
        let accessTokens = await historyClient.accessTokens()

        XCTAssertEqual(refreshed, [remoteGoogle, fallbackOutlook])
        XCTAssertEqual(requestCount, 1)
        XCTAssertEqual(accessTokens, ["access-token"])
    }

    func testRefreshUsesTokenRefresherWhenTokenIsExpired() async throws {
        let fallbackService = StubLoginActivityService(events: [])
        let remoteGoogle = makeLoginEvent(
            id: "2D06A782-BE1D-4A93-BE74-A1E5E3B03A21",
            provider: .google,
            occurredAt: fixedNow.addingTimeInterval(-45),
            ip: "198.51.100.45",
            suspicious: false
        )
        let historyClient = StubGoogleWorkspaceLoginHistoryClient(result: .success([remoteGoogle]))
        let tokenRefresher = StubGoogleOAuthTokenRefresher(
            result: .success(
                GoogleOAuthToken(
                    accessToken: "fresh-access-token",
                    refreshToken: "fresh-refresh-token",
                    expiresIn: 3600,
                    scope: "openid profile email \(reportsScope)",
                    tokenType: "Bearer"
                )
            )
        )
        let secureStore = InMemorySecureStore()
        let tokenStore = GoogleOAuthTokenStore(
            secureStore: secureStore,
            storageKey: "test.google.workspace.token.refresh"
        )
        try tokenStore.save(
            GoogleOAuthToken(
                accessToken: "stale-access-token",
                refreshToken: "stale-refresh-token",
                expiresIn: 60,
                scope: "openid profile email \(reportsScope)",
                tokenType: "Bearer"
            ),
            obtainedAt: fixedNow.addingTimeInterval(-600)
        )
        let oauthConfiguration = GoogleOAuthConfiguration(
            clientID: "client-id",
            redirectURI: URL(string: "secuperso://oauth")!,
            scopes: ["openid", "profile", "email", reportsScope]
        )
        let fixedNow = self.fixedNow
        let service = GoogleWorkspaceLoginActivityService(
            fallbackService: fallbackService,
            oauthConfiguration: oauthConfiguration,
            tokenStore: tokenStore,
            tokenRefresher: tokenRefresher,
            historyClient: historyClient,
            nowProvider: { fixedNow }
        )

        let refreshed = try await service.refresh()
        let accessTokens = await historyClient.accessTokens()
        let receivedRefreshTokens = await tokenRefresher.receivedRefreshTokens()

        XCTAssertEqual(refreshed, [remoteGoogle])
        XCTAssertEqual(accessTokens, ["fresh-access-token"])
        XCTAssertEqual(receivedRefreshTokens, ["stale-refresh-token"])

        let persisted = try tokenStore.load()
        XCTAssertEqual(persisted?.token.accessToken, "fresh-access-token")
        XCTAssertEqual(persisted?.token.refreshToken, "fresh-refresh-token")
    }

    func testRefreshReturnsFallbackWhenWorkspaceRequestFails() async throws {
        let fallbackGoogle = makeLoginEvent(
            id: "91A6C9DD-F4D1-4E6F-A501-8B26AF3F0B31",
            provider: .google,
            occurredAt: fixedNow.addingTimeInterval(-200),
            ip: "203.0.113.31",
            suspicious: false
        )
        let fallbackOutlook = makeLoginEvent(
            id: "B6A8E7A9-5965-4F26-8D0D-DA5482853531",
            provider: .outlook,
            occurredAt: fixedNow.addingTimeInterval(-100),
            ip: "198.51.100.31",
            suspicious: true
        )
        let fallbackService = StubLoginActivityService(events: [fallbackGoogle, fallbackOutlook])
        let historyClient = StubGoogleWorkspaceLoginHistoryClient(result: .failure(TestFailure()))
        let tokenStore = GoogleOAuthTokenStore(
            secureStore: InMemorySecureStore(),
            storageKey: "test.google.workspace.token.failure"
        )
        try tokenStore.save(
            GoogleOAuthToken(
                accessToken: "access-token",
                refreshToken: "refresh-token",
                expiresIn: 3600,
                scope: "openid profile email \(reportsScope)",
                tokenType: "Bearer"
            ),
            obtainedAt: fixedNow.addingTimeInterval(-60)
        )
        let fixedNow = self.fixedNow
        let service = GoogleWorkspaceLoginActivityService(
            fallbackService: fallbackService,
            oauthConfiguration: nil,
            tokenStore: tokenStore,
            tokenRefresher: nil,
            historyClient: historyClient,
            nowProvider: { fixedNow }
        )

        let refreshed = try await service.refresh()
        let requestCount = await historyClient.requestCount()

        XCTAssertEqual(refreshed, [fallbackOutlook, fallbackGoogle])
        XCTAssertEqual(requestCount, 1)
    }

    private func makeLoginEvent(
        id: String,
        provider: ProviderID,
        occurredAt: Date,
        ip: String,
        suspicious: Bool
    ) -> LoginEvent {
        LoginEvent(
            id: UUID(uuidString: id)!,
            provider: provider,
            providerAccountID: "account-id",
            providerAccountEmail: "owner@example.com",
            occurredAt: occurredAt,
            device: "MacBook Pro",
            ipAddress: ip,
            location: "Paris, FR",
            reason: suspicious ? "Suspicious sign-in" : "Expected sign-in",
            suspicious: suspicious,
            expected: !suspicious
        )
    }
}

private struct TestFailure: Error {}

private final class StubLoginActivityService: LoginActivityService, @unchecked Sendable {
    private let events: [LoginEvent]

    init(events: [LoginEvent]) {
        self.events = events
    }

    func refresh() async throws -> [LoginEvent] {
        events
    }

    func stream() -> AsyncStream<[LoginEvent]> {
        AsyncStream { continuation in
            continuation.yield(events)
            continuation.finish()
        }
    }
}

private actor StubGoogleWorkspaceLoginHistoryClient: GoogleWorkspaceLoginHistoryClient {
    private let result: Result<[LoginEvent], Error>
    private var requestedAccessTokens: [String] = []

    init(result: Result<[LoginEvent], Error>) {
        self.result = result
    }

    func fetchLoginEvents(
        accessToken: String,
        configuration: GoogleWorkspaceLoginHistoryConfiguration,
        now: Date
    ) async throws -> [LoginEvent] {
        requestedAccessTokens.append(accessToken)
        return try result.get()
    }

    func requestCount() -> Int {
        requestedAccessTokens.count
    }

    func accessTokens() -> [String] {
        requestedAccessTokens
    }
}

private actor StubGoogleOAuthTokenRefresher: GoogleOAuthTokenRefresher {
    private let result: Result<GoogleOAuthToken, Error>
    private var tokens: [String] = []

    init(result: Result<GoogleOAuthToken, Error>) {
        self.result = result
    }

    func refreshToken(
        configuration: GoogleOAuthConfiguration,
        refreshToken: String
    ) async throws -> GoogleOAuthToken {
        tokens.append(refreshToken)
        return try result.get()
    }

    func receivedRefreshTokens() -> [String] {
        tokens
    }
}

private final class InMemorySecureStore: SecureStore, @unchecked Sendable {
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
