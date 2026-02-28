import CryptoKit
import XCTest
import SecuPersoData
import SecuPersoDomain

final class MicrosoftOutlookOAuthServiceTests: XCTestCase {
    func testConnectSuccessPersistsTokenAndMarksConnected() async throws {
        let harness = try await makeHarness()
        let authSession = ScriptedAuthorizationSession { startURL, _ in
            let state = try XCTUnwrap(Self.queryItem(named: "state", in: startURL))
            return URL(string: "secuperso://oauth?code=test-code&state=\(state)")!
        }
        let tokenExchanger = StubTokenExchanger(
            result: .success(
                MicrosoftOAuthToken(
                    accessToken: "access-token",
                    refreshToken: "refresh-token",
                    expiresIn: 3600,
                    scope: "User.Read",
                    tokenType: "Bearer"
                )
            )
        )

        let service = MicrosoftOutlookOAuthService(
            coordinator: harness.coordinator,
            configuration: harness.configuration,
            authorizationSession: authSession,
            tokenExchanger: tokenExchanger,
            tokenStore: harness.tokenStore
        )

        let updates = await collectUpdates(from: await service.beginConnection())
        XCTAssertEqual(updates.last?.state, .connected)
        XCTAssertEqual(updates.last?.message, "Microsoft account connected.")
        XCTAssertNotNil(try harness.tokenStore.load())

        let connections = try await harness.coordinator.listProviderConnections()
        XCTAssertEqual(connections.first(where: { $0.id == .outlook })?.state, .connected)
    }

    func testConnectWithoutConfigurationReturnsSetupError() async throws {
        let harness = try await makeHarness()
        let authSession = ScriptedAuthorizationSession { _, _ in
            XCTFail("Authorization session should not be called when config is missing.")
            return URL(string: "secuperso://oauth")!
        }

        let service = MicrosoftOutlookOAuthService(
            coordinator: harness.coordinator,
            configuration: nil,
            authorizationSession: authSession,
            tokenExchanger: StubTokenExchanger(
                result: .success(
                    MicrosoftOAuthToken(
                        accessToken: "unused",
                        refreshToken: nil,
                        expiresIn: 3600,
                        scope: nil,
                        tokenType: "Bearer"
                    )
                )
            ),
            tokenStore: harness.tokenStore
        )

        let updates = await collectUpdates(from: await service.beginConnection())
        XCTAssertEqual(updates.last?.state, .error)
        XCTAssertEqual(
            updates.last?.message,
            "Microsoft OAuth is not configured. Set MS_ENTRA_CLIENT_ID in app settings."
        )
    }

    func testUserCancelReturnsDisconnectedWithoutPersistingToken() async throws {
        let harness = try await makeHarness()
        let authSession = ScriptedAuthorizationSession { _, _ in
            throw OAuthAuthorizationSessionError.cancelled
        }

        let service = MicrosoftOutlookOAuthService(
            coordinator: harness.coordinator,
            configuration: harness.configuration,
            authorizationSession: authSession,
            tokenExchanger: StubTokenExchanger(
                result: .success(
                    MicrosoftOAuthToken(
                        accessToken: "unused",
                        refreshToken: nil,
                        expiresIn: 3600,
                        scope: nil,
                        tokenType: "Bearer"
                    )
                )
            ),
            tokenStore: harness.tokenStore
        )

        let updates = await collectUpdates(from: await service.beginConnection())
        XCTAssertEqual(updates.last?.state, .disconnected)
        XCTAssertEqual(updates.last?.message, "Sign-in canceled.")
        XCTAssertNil(try harness.tokenStore.load())
    }

    func testTokenExchangeFailureReturnsErrorAndDoesNotPersistToken() async throws {
        let harness = try await makeHarness()
        let authSession = ScriptedAuthorizationSession { startURL, _ in
            let state = try XCTUnwrap(Self.queryItem(named: "state", in: startURL))
            return URL(string: "secuperso://oauth?code=test-code&state=\(state)")!
        }
        let tokenExchanger = StubTokenExchanger(result: .failure(StubError(message: "exchange failed")))

        let service = MicrosoftOutlookOAuthService(
            coordinator: harness.coordinator,
            configuration: harness.configuration,
            authorizationSession: authSession,
            tokenExchanger: tokenExchanger,
            tokenStore: harness.tokenStore
        )

        let updates = await collectUpdates(from: await service.beginConnection())
        XCTAssertEqual(updates.last?.state, .error)
        XCTAssertEqual(updates.last?.message, "Microsoft sign-in failed. Please try again.")
        XCTAssertNil(try harness.tokenStore.load())
    }

    func testDisconnectClearsTokenAndMarksProviderDisconnected() async throws {
        let harness = try await makeHarness()
        let service = MicrosoftOutlookOAuthService(
            coordinator: harness.coordinator,
            configuration: harness.configuration,
            authorizationSession: ScriptedAuthorizationSession { _, _ in
                URL(string: "secuperso://oauth")!
            },
            tokenExchanger: StubTokenExchanger(
                result: .success(
                    MicrosoftOAuthToken(
                        accessToken: "unused",
                        refreshToken: nil,
                        expiresIn: 3600,
                        scope: nil,
                        tokenType: "Bearer"
                    )
                )
            ),
            tokenStore: harness.tokenStore
        )

        try harness.tokenStore.save(
            MicrosoftOAuthToken(
                accessToken: "seed-token",
                refreshToken: "seed-refresh",
                expiresIn: 3600,
                scope: "User.Read",
                tokenType: "Bearer"
            )
        )

        try await service.disconnect()

        XCTAssertNil(try harness.tokenStore.load())
        let connections = try await harness.coordinator.listProviderConnections()
        XCTAssertEqual(connections.first(where: { $0.id == .outlook })?.state, .disconnected)
    }

    func testHybridServiceKeepsGoogleMockFlowUnchanged() async throws {
        let harness = try await makeHarness()
        let fallback = MockProviderConnectionService(coordinator: harness.coordinator)
        let outlook = MicrosoftOutlookOAuthService(
            coordinator: harness.coordinator,
            configuration: nil,
            authorizationSession: ScriptedAuthorizationSession { _, _ in
                URL(string: "secuperso://oauth")!
            },
            tokenExchanger: StubTokenExchanger(
                result: .success(
                    MicrosoftOAuthToken(
                        accessToken: "unused",
                        refreshToken: nil,
                        expiresIn: 3600,
                        scope: nil,
                        tokenType: "Bearer"
                    )
                )
            ),
            tokenStore: harness.tokenStore
        )
        let service = HybridProviderConnectionService(
            fallbackService: fallback,
            outlookService: outlook
        )

        let updates = await collectUpdates(from: await service.beginConnection(for: .google))
        XCTAssertEqual(updates.last?.state, .connected)
        XCTAssertEqual(updates.last?.message, "Provider connected successfully.")
    }

    private static func queryItem(named name: String, in url: URL) -> String? {
        URLComponents(url: url, resolvingAgainstBaseURL: false)?
            .queryItems?
            .first(where: { $0.name == name })?
            .value
    }

    private func collectUpdates(from stream: AsyncStream<ProviderConnectionUpdate>) async -> [ProviderConnectionUpdate] {
        var updates: [ProviderConnectionUpdate] = []
        for await update in stream {
            updates.append(update)
        }
        return updates
    }

    private func makeHarness() async throws -> TestHarness {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let exposuresURL = directory.appendingPathComponent("exposures.json")
        let loginsURL = directory.appendingPathComponent("login_events.json")
        let providersURL = directory.appendingPathComponent("providers.json")

        try "{\"clean\":[],\"moderate\":[],\"critical\":[]}".write(to: exposuresURL, atomically: true, encoding: .utf8)
        try "{\"clean\":[],\"moderate\":[],\"critical\":[]}".write(to: loginsURL, atomically: true, encoding: .utf8)
        try "[{\"id\":\"google\",\"displayName\":\"Google\",\"details\":\"Mock\"},{\"id\":\"outlook\",\"displayName\":\"Outlook\",\"details\":\"Mock\"},{\"id\":\"other\",\"displayName\":\"Other\",\"details\":\"Mock\"}]".write(to: providersURL, atomically: true, encoding: .utf8)

        let loader = FixtureDataLoader(
            exposuresURL: exposuresURL,
            loginEventsURL: loginsURL,
            providersURL: providersURL
        )
        let database = try EncryptedSQLiteDatabase(
            databaseURL: directory.appendingPathComponent("secuperso.sqlite"),
            key: SymmetricKey(size: .bits256)
        )
        let coordinator = MockDataCoordinator(
            fixtureLoader: loader,
            database: database
        )
        _ = try await coordinator.loadProviderCatalog()

        let secureStore = InMemorySecureStore()
        let tokenStore = MicrosoftOAuthTokenStore(
            secureStore: secureStore,
            storageKey: "test.microsoft.oauth.token"
        )

        let configuration = MicrosoftOAuthConfiguration(
            clientID: "test-client-id",
            tenantID: "common",
            redirectURI: URL(string: "secuperso://oauth")!,
            scopes: ["openid", "profile", "offline_access", "User.Read"]
        )

        return TestHarness(
            coordinator: coordinator,
            configuration: configuration,
            tokenStore: tokenStore
        )
    }
}

private struct TestHarness {
    let coordinator: MockDataCoordinator
    let configuration: MicrosoftOAuthConfiguration
    let tokenStore: MicrosoftOAuthTokenStore
}

private struct StubError: Error {
    let message: String
}

private final class ScriptedAuthorizationSession: OAuthAuthorizationSession, @unchecked Sendable {
    typealias Handler = @Sendable (_ startURL: URL, _ callbackScheme: String) throws -> URL

    private let handler: Handler

    init(handler: @escaping Handler) {
        self.handler = handler
    }

    func authenticate(startURL: URL, callbackScheme: String) async throws -> URL {
        try handler(startURL, callbackScheme)
    }
}

private final class StubTokenExchanger: MicrosoftOAuthTokenExchanger, @unchecked Sendable {
    private let result: Result<MicrosoftOAuthToken, Error>

    init(result: Result<MicrosoftOAuthToken, Error>) {
        self.result = result
    }

    func exchangeCode(
        configuration: MicrosoftOAuthConfiguration,
        authorizationCode: String,
        codeVerifier: String
    ) async throws -> MicrosoftOAuthToken {
        try result.get()
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
