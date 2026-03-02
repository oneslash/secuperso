import CryptoKit
import XCTest
import SecuPersoData
import SecuPersoDomain

final class GoogleOAuthServiceTests: XCTestCase {
    func testConnectSuccessPersistsTokenAndMarksConnected() async throws {
        let harness = try await makeHarness()
        let authSession = GoogleScriptedAuthorizationSession { startURL, _ in
            let state = try XCTUnwrap(Self.queryItem(named: "state", in: startURL))
            return URL(string: "secuperso://oauth?code=test-code&state=\(state)")!
        }
        let tokenExchanger = GoogleStubTokenExchanger(
            result: .success(
                GoogleOAuthToken(
                    accessToken: "access-token",
                    refreshToken: "refresh-token",
                    expiresIn: 3600,
                    scope: "openid profile email",
                    tokenType: "Bearer"
                )
            )
        )

        let service = GoogleOAuthService(
            coordinator: harness.coordinator,
            configuration: harness.configuration,
            authorizationSession: authSession,
            tokenExchanger: tokenExchanger,
            tokenStore: harness.tokenStore
        )

        let updates = await collectUpdates(from: await service.beginConnection())
        XCTAssertEqual(updates.last?.state, .connected)
        XCTAssertEqual(updates.last?.message, "Google account connected.")
        XCTAssertNotNil(try harness.tokenStore.load())

        let connections = try await harness.coordinator.listProviderConnections()
        XCTAssertEqual(connections.first(where: { $0.id == .google })?.state, .connected)
    }

    func testConnectWithoutConfigurationReturnsSetupError() async throws {
        let harness = try await makeHarness()
        let authSession = GoogleScriptedAuthorizationSession { _, _ in
            XCTFail("Authorization session should not be called when config is missing.")
            return URL(string: "secuperso://oauth")!
        }

        let service = GoogleOAuthService(
            coordinator: harness.coordinator,
            configuration: nil,
            authorizationSession: authSession,
            tokenExchanger: GoogleStubTokenExchanger(
                result: .success(
                    GoogleOAuthToken(
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
            "Google OAuth is not configured. Set GOOGLE_OAUTH_CLIENT_ID in app settings."
        )
    }

    func testUserCancelReturnsDisconnectedWithoutPersistingToken() async throws {
        let harness = try await makeHarness()
        let authSession = GoogleScriptedAuthorizationSession { _, _ in
            throw OAuthAuthorizationSessionError.cancelled
        }

        let service = GoogleOAuthService(
            coordinator: harness.coordinator,
            configuration: harness.configuration,
            authorizationSession: authSession,
            tokenExchanger: GoogleStubTokenExchanger(
                result: .success(
                    GoogleOAuthToken(
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
        let authSession = GoogleScriptedAuthorizationSession { startURL, _ in
            let state = try XCTUnwrap(Self.queryItem(named: "state", in: startURL))
            return URL(string: "secuperso://oauth?code=test-code&state=\(state)")!
        }
        let tokenExchanger = GoogleStubTokenExchanger(result: .failure(GoogleStubError(message: "exchange failed")))

        let service = GoogleOAuthService(
            coordinator: harness.coordinator,
            configuration: harness.configuration,
            authorizationSession: authSession,
            tokenExchanger: tokenExchanger,
            tokenStore: harness.tokenStore
        )

        let updates = await collectUpdates(from: await service.beginConnection())
        XCTAssertEqual(updates.last?.state, .error)
        XCTAssertEqual(updates.last?.message, "Google sign-in failed. Please try again.")
        XCTAssertNil(try harness.tokenStore.load())
    }

    func testDisconnectClearsTokenAndMarksProviderDisconnected() async throws {
        let harness = try await makeHarness()
        let service = GoogleOAuthService(
            coordinator: harness.coordinator,
            configuration: harness.configuration,
            authorizationSession: GoogleScriptedAuthorizationSession { _, _ in
                URL(string: "secuperso://oauth")!
            },
            tokenExchanger: GoogleStubTokenExchanger(
                result: .success(
                    GoogleOAuthToken(
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
            GoogleOAuthToken(
                accessToken: "seed-token",
                refreshToken: "seed-refresh",
                expiresIn: 3600,
                scope: "openid profile email",
                tokenType: "Bearer"
            )
        )

        try await service.disconnect()

        XCTAssertNil(try harness.tokenStore.load())
        let connections = try await harness.coordinator.listProviderConnections()
        XCTAssertEqual(connections.first(where: { $0.id == .google })?.state, .disconnected)
    }

    func testHybridServiceKeepsOtherMockFlowUnchanged() async throws {
        let harness = try await makeHarness()
        let fallback = MockProviderConnectionService(coordinator: harness.coordinator)
        let google = GoogleOAuthService(
            coordinator: harness.coordinator,
            configuration: nil,
            authorizationSession: GoogleScriptedAuthorizationSession { _, _ in
                URL(string: "secuperso://oauth")!
            },
            tokenExchanger: GoogleStubTokenExchanger(
                result: .success(
                    GoogleOAuthToken(
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
        let outlook = MicrosoftOutlookOAuthService(
            coordinator: harness.coordinator,
            configuration: nil,
            authorizationSession: GoogleScriptedAuthorizationSession { _, _ in
                URL(string: "secuperso://oauth")!
            },
            tokenExchanger: GoogleMicrosoftStubTokenExchanger(
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
            tokenStore: MicrosoftOAuthTokenStore(
                secureStore: GoogleInMemorySecureStore(),
                storageKey: "test.microsoft.oauth.tokens"
            )
        )
        let service = HybridProviderConnectionService(
            fallbackService: fallback,
            googleService: google,
            outlookService: outlook
        )

        let updates = await collectUpdates(from: await service.beginConnection(for: .other))
        XCTAssertEqual(updates.last?.state, .error)
        XCTAssertEqual(updates.last?.message, "Provider connection failed in mock flow.")
    }

    func testHybridServiceRoutesGoogleToGoogleOAuthFlow() async throws {
        let harness = try await makeHarness()
        let fallback = MockProviderConnectionService(coordinator: harness.coordinator)
        let google = GoogleOAuthService(
            coordinator: harness.coordinator,
            configuration: nil,
            authorizationSession: GoogleScriptedAuthorizationSession { _, _ in
                URL(string: "secuperso://oauth")!
            },
            tokenExchanger: GoogleStubTokenExchanger(
                result: .success(
                    GoogleOAuthToken(
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
        let outlook = MicrosoftOutlookOAuthService(
            coordinator: harness.coordinator,
            configuration: nil,
            authorizationSession: GoogleScriptedAuthorizationSession { _, _ in
                URL(string: "secuperso://oauth")!
            },
            tokenExchanger: GoogleMicrosoftStubTokenExchanger(
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
            tokenStore: MicrosoftOAuthTokenStore(
                secureStore: GoogleInMemorySecureStore(),
                storageKey: "test.microsoft.oauth.tokens"
            )
        )
        let service = HybridProviderConnectionService(
            fallbackService: fallback,
            googleService: google,
            outlookService: outlook
        )

        let updates = await collectUpdates(from: await service.beginConnection(for: .google))
        XCTAssertEqual(updates.last?.state, .error)
        XCTAssertEqual(
            updates.last?.message,
            "Google OAuth is not configured. Set GOOGLE_OAUTH_CLIENT_ID in app settings."
        )
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

    private func makeHarness() async throws -> GoogleTestHarness {
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

        let secureStore = GoogleInMemorySecureStore()
        let tokenStore = GoogleOAuthTokenStore(
            secureStore: secureStore,
            storageKey: "test.google.oauth.tokens"
        )

        let configuration = GoogleOAuthConfiguration(
            clientID: "test-client-id",
            redirectURI: URL(string: "secuperso://oauth")!,
            scopes: ["openid", "profile", "email"]
        )

        return GoogleTestHarness(
            coordinator: coordinator,
            configuration: configuration,
            tokenStore: tokenStore
        )
    }
}

private struct GoogleTestHarness {
    let coordinator: MockDataCoordinator
    let configuration: GoogleOAuthConfiguration
    let tokenStore: GoogleOAuthTokenStore
}

private struct GoogleStubError: Error {
    let message: String
}

private final class GoogleScriptedAuthorizationSession: OAuthAuthorizationSession, @unchecked Sendable {
    typealias Handler = @Sendable (_ startURL: URL, _ callbackScheme: String) throws -> URL

    private let handler: Handler

    init(handler: @escaping Handler) {
        self.handler = handler
    }

    func authenticate(startURL: URL, callbackScheme: String) async throws -> URL {
        try handler(startURL, callbackScheme)
    }
}

private final class GoogleStubTokenExchanger: GoogleOAuthTokenExchanger, @unchecked Sendable {
    private let result: Result<GoogleOAuthToken, Error>

    init(result: Result<GoogleOAuthToken, Error>) {
        self.result = result
    }

    func exchangeCode(
        configuration: GoogleOAuthConfiguration,
        authorizationCode: String,
        codeVerifier: String
    ) async throws -> GoogleOAuthToken {
        try result.get()
    }
}

private final class GoogleMicrosoftStubTokenExchanger: MicrosoftOAuthTokenExchanger, @unchecked Sendable {
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

private final class GoogleInMemorySecureStore: SecureStore, @unchecked Sendable {
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
