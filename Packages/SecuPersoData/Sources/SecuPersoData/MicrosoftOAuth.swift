import CryptoKit
import Foundation
import SecuPersoDomain

public struct MicrosoftOAuthConfiguration: Equatable, Sendable {
    public var clientID: String
    public var tenantID: String
    public var redirectURI: URL
    public var scopes: [String]

    public init(
        clientID: String,
        tenantID: String = "common",
        redirectURI: URL,
        scopes: [String] = ["openid", "profile", "offline_access", "User.Read"]
    ) {
        self.clientID = clientID
        self.tenantID = tenantID
        self.redirectURI = redirectURI
        self.scopes = scopes
    }
}

public enum OAuthAuthorizationSessionError: Error, Sendable {
    case cancelled
    case failed(message: String)
}

public protocol OAuthAuthorizationSession: Sendable {
    func authenticate(startURL: URL, callbackScheme: String) async throws -> URL
}

public struct MicrosoftOAuthToken: Codable, Equatable, Sendable {
    public var accessToken: String
    public var refreshToken: String?
    public var expiresIn: Int
    public var scope: String?
    public var tokenType: String

    public init(
        accessToken: String,
        refreshToken: String?,
        expiresIn: Int,
        scope: String?,
        tokenType: String
    ) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.expiresIn = expiresIn
        self.scope = scope
        self.tokenType = tokenType
    }
}

public struct StoredMicrosoftOAuthToken: Codable, Equatable, Sendable {
    public var token: MicrosoftOAuthToken
    public var obtainedAt: Date

    public init(token: MicrosoftOAuthToken, obtainedAt: Date) {
        self.token = token
        self.obtainedAt = obtainedAt
    }
}

public final class MicrosoftOAuthTokenStore: @unchecked Sendable {
    private let secureStore: any SecureStore
    private let storageKey: String
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(
        secureStore: any SecureStore,
        storageKey: String = "com.secuperso.app.microsoft.oauth.tokens"
    ) {
        self.secureStore = secureStore
        self.storageKey = storageKey
        decoder.dateDecodingStrategy = .iso8601
        encoder.dateEncodingStrategy = .iso8601
    }

    public func load() throws -> StoredMicrosoftOAuthToken? {
        guard let data = try secureStore.read(storageKey) else {
            return nil
        }
        return try decoder.decode(StoredMicrosoftOAuthToken.self, from: data)
    }

    public func save(_ token: MicrosoftOAuthToken, obtainedAt: Date = Date()) throws {
        let payload = StoredMicrosoftOAuthToken(token: token, obtainedAt: obtainedAt)
        let data = try encoder.encode(payload)
        try secureStore.write(data, for: storageKey)
    }

    public func clear() throws {
        try secureStore.delete(storageKey)
    }
}

public protocol MicrosoftOAuthTokenExchanger: Sendable {
    func exchangeCode(
        configuration: MicrosoftOAuthConfiguration,
        authorizationCode: String,
        codeVerifier: String
    ) async throws -> MicrosoftOAuthToken
}

public final class URLSessionMicrosoftOAuthTokenExchanger: MicrosoftOAuthTokenExchanger, @unchecked Sendable {
    private let session: URLSession
    private let decoder = JSONDecoder()

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func exchangeCode(
        configuration: MicrosoftOAuthConfiguration,
        authorizationCode: String,
        codeVerifier: String
    ) async throws -> MicrosoftOAuthToken {
        let endpoint = Self.tokenEndpoint(forTenantID: configuration.tenantID)

        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = Self.formBody(
            [
                ("client_id", configuration.clientID),
                ("scope", configuration.scopes.joined(separator: " ")),
                ("code", authorizationCode),
                ("redirect_uri", configuration.redirectURI.absoluteString),
                ("grant_type", "authorization_code"),
                ("code_verifier", codeVerifier)
            ]
        )

        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw MicrosoftOAuthFlowError.tokenExchangeFailed("Microsoft token endpoint returned an invalid response.")
        }

        guard (200...299).contains(httpResponse.statusCode) else {
            let payload = try? decoder.decode(TokenErrorPayload.self, from: data)
            let message = payload?.errorDescription ?? payload?.error ?? "Microsoft token exchange failed."
            throw MicrosoftOAuthFlowError.tokenExchangeFailed(message)
        }

        let payload: TokenSuccessPayload
        do {
            payload = try decoder.decode(TokenSuccessPayload.self, from: data)
        } catch {
            throw MicrosoftOAuthFlowError.tokenExchangeFailed("Microsoft token response could not be decoded.")
        }

        guard !payload.accessToken.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw MicrosoftOAuthFlowError.tokenExchangeFailed("Microsoft token response did not include an access token.")
        }
        guard payload.expiresIn > 0 else {
            throw MicrosoftOAuthFlowError.tokenExchangeFailed("Microsoft token response returned an invalid expiry.")
        }

        return MicrosoftOAuthToken(
            accessToken: payload.accessToken,
            refreshToken: payload.refreshToken,
            expiresIn: payload.expiresIn,
            scope: payload.scope,
            tokenType: payload.tokenType
        )
    }

    private static func tokenEndpoint(forTenantID tenantID: String) -> URL {
        let sanitizedTenant = tenantID.trimmingCharacters(in: .whitespacesAndNewlines)
        let tenant = sanitizedTenant.isEmpty ? "common" : sanitizedTenant
        return URL(string: "https://login.microsoftonline.com/\(tenant)/oauth2/v2.0/token")!
    }

    private static func formBody(_ fields: [(String, String)]) -> Data {
        let pairs = fields.map { key, value in
            "\(formEncode(key))=\(formEncode(value))"
        }
        return Data(pairs.joined(separator: "&").utf8)
    }

    private static func formEncode(_ value: String) -> String {
        let disallowed = CharacterSet(charactersIn: ":#[]@!$&'()*+,;=").union(.whitespacesAndNewlines)
        let allowed = CharacterSet.urlQueryAllowed.subtracting(disallowed)
        return value.addingPercentEncoding(withAllowedCharacters: allowed)?
            .replacingOccurrences(of: " ", with: "+") ?? value
    }
}

public final class MicrosoftOutlookOAuthService: @unchecked Sendable {
    private let coordinator: MockDataCoordinator
    private let configuration: MicrosoftOAuthConfiguration?
    private let authorizationSession: any OAuthAuthorizationSession
    private let tokenExchanger: any MicrosoftOAuthTokenExchanger
    private let tokenStore: MicrosoftOAuthTokenStore

    public init(
        coordinator: MockDataCoordinator,
        configuration: MicrosoftOAuthConfiguration?,
        authorizationSession: any OAuthAuthorizationSession,
        tokenExchanger: any MicrosoftOAuthTokenExchanger,
        tokenStore: MicrosoftOAuthTokenStore
    ) {
        self.coordinator = coordinator
        self.configuration = configuration
        self.authorizationSession = authorizationSession
        self.tokenExchanger = tokenExchanger
        self.tokenStore = tokenStore
    }

    public func beginConnection() async -> AsyncStream<ProviderConnectionUpdate> {
        AsyncStream { continuation in
            let task = Task {
                defer { continuation.finish() }

                await emit(
                    state: .connecting,
                    message: "Opening Microsoft sign-in...",
                    continuation: continuation
                )

                guard let configuration else {
                    await emit(
                        state: .error,
                        message: "Microsoft OAuth is not configured. Set MS_ENTRA_CLIENT_ID in app settings.",
                        continuation: continuation
                    )
                    return
                }

                do {
                    let callbackScheme = try Self.callbackScheme(from: configuration)
                    let challenge = PKCEChallenge.make()
                    let stateToken = Self.makeStateToken()
                    let authorizeURL = try Self.authorizeURL(
                        configuration: configuration,
                        state: stateToken,
                        codeChallenge: challenge.codeChallenge
                    )

                    await emit(
                        state: .connecting,
                        message: "Waiting for Microsoft consent...",
                        continuation: continuation
                    )

                    let callbackURL = try await authorizationSession.authenticate(
                        startURL: authorizeURL,
                        callbackScheme: callbackScheme
                    )
                    try Task.checkCancellation()
                    let code = try Self.authorizationCode(
                        callbackURL: callbackURL,
                        expectedState: stateToken
                    )

                    await emit(
                        state: .connecting,
                        message: "Exchanging authorization code...",
                        continuation: continuation
                    )

                    let token = try await tokenExchanger.exchangeCode(
                        configuration: configuration,
                        authorizationCode: code,
                        codeVerifier: challenge.codeVerifier
                    )
                    try Task.checkCancellation()
                    try tokenStore.save(token)

                    await emit(
                        state: .connected,
                        message: "Microsoft account connected.",
                        continuation: continuation
                    )
                } catch is CancellationError {
                    return
                } catch OAuthAuthorizationSessionError.cancelled {
                    await emit(
                        state: .disconnected,
                        message: "Sign-in canceled.",
                        continuation: continuation
                    )
                } catch let error as MicrosoftOAuthFlowError {
                    await emit(
                        state: error.state,
                        message: error.userMessage,
                        continuation: continuation
                    )
                } catch {
                    await emit(
                        state: .error,
                        message: "Microsoft sign-in failed. Please try again.",
                        continuation: continuation
                    )
                }
            }

            continuation.onTermination = { @Sendable _ in
                task.cancel()
            }
        }
    }

    public func disconnect() async throws {
        try tokenStore.clear()
        try await coordinator.updateProviderState(.outlook, state: .disconnected)
    }

    private func emit(
        state: ConnectionState,
        message: String,
        continuation: AsyncStream<ProviderConnectionUpdate>.Continuation
    ) async {
        try? await coordinator.updateProviderState(.outlook, state: state)
        continuation.yield(ProviderConnectionUpdate(state: state, message: message))
    }

    private static func callbackScheme(from configuration: MicrosoftOAuthConfiguration) throws -> String {
        let scheme = configuration.redirectURI.scheme?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !scheme.isEmpty else {
            throw MicrosoftOAuthFlowError.invalidRedirectURI
        }
        return scheme
    }

    private static func authorizeURL(
        configuration: MicrosoftOAuthConfiguration,
        state: String,
        codeChallenge: String
    ) throws -> URL {
        let tenant = configuration.tenantID.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedTenant = tenant.isEmpty ? "common" : tenant

        var components = URLComponents(
            string: "https://login.microsoftonline.com/\(normalizedTenant)/oauth2/v2.0/authorize"
        )
        components?.queryItems = [
            URLQueryItem(name: "client_id", value: configuration.clientID),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "redirect_uri", value: configuration.redirectURI.absoluteString),
            URLQueryItem(name: "response_mode", value: "query"),
            URLQueryItem(name: "scope", value: configuration.scopes.joined(separator: " ")),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256")
        ]

        guard let url = components?.url else {
            throw MicrosoftOAuthFlowError.invalidAuthorizeURL
        }
        return url
    }

    private static func authorizationCode(
        callbackURL: URL,
        expectedState: String
    ) throws -> String {
        guard let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false) else {
            throw MicrosoftOAuthFlowError.authorizationCodeMissing
        }

        let items = components.queryItems ?? []
        if let error = items.first(where: { $0.name == "error" })?.value {
            if error == "access_denied" {
                throw OAuthAuthorizationSessionError.cancelled
            }
            let description = items.first(where: { $0.name == "error_description" })?.value ?? error
            throw MicrosoftOAuthFlowError.authorizationRejected(description)
        }

        let returnedState = items.first(where: { $0.name == "state" })?.value
        guard returnedState == expectedState else {
            throw MicrosoftOAuthFlowError.stateMismatch
        }

        guard let code = items.first(where: { $0.name == "code" })?.value, !code.isEmpty else {
            throw MicrosoftOAuthFlowError.authorizationCodeMissing
        }
        return code
    }

    private static func makeStateToken() -> String {
        let bytes = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })
        return bytes.base64URLEncodedString()
    }
}

public final class HybridProviderConnectionService: ProviderConnectionService, ProviderConnectionReadableService, @unchecked Sendable {
    private let fallbackService: MockProviderConnectionService
    private let outlookService: MicrosoftOutlookOAuthService

    public init(
        fallbackService: MockProviderConnectionService,
        outlookService: MicrosoftOutlookOAuthService
    ) {
        self.fallbackService = fallbackService
        self.outlookService = outlookService
    }

    public func beginConnection(for provider: ProviderID) async -> AsyncStream<ProviderConnectionUpdate> {
        if provider == .outlook {
            return await outlookService.beginConnection()
        }
        return await fallbackService.beginConnection(for: provider)
    }

    public func disconnect(_ provider: ProviderID) async throws {
        if provider == .outlook {
            try await outlookService.disconnect()
        } else {
            try await fallbackService.disconnect(provider)
        }
    }

    public func connections() async throws -> [ProviderConnection] {
        try await fallbackService.connections()
    }
}

private enum MicrosoftOAuthFlowError: Error {
    case invalidRedirectURI
    case invalidAuthorizeURL
    case authorizationRejected(String)
    case stateMismatch
    case authorizationCodeMissing
    case tokenExchangeFailed(String)

    var state: ConnectionState {
        switch self {
        case .authorizationRejected(let code) where code == "access_denied":
            return .disconnected
        default:
            return .error
        }
    }

    var userMessage: String {
        switch self {
        case .invalidRedirectURI:
            return "Microsoft OAuth redirect URI is invalid."
        case .invalidAuthorizeURL:
            return "Microsoft OAuth authorize URL could not be built."
        case .authorizationRejected(let message):
            return "Microsoft sign-in was rejected: \(message)"
        case .stateMismatch:
            return "Microsoft sign-in response failed validation."
        case .authorizationCodeMissing:
            return "Microsoft sign-in did not return an authorization code."
        case .tokenExchangeFailed(let message):
            return "Microsoft token exchange failed: \(message)"
        }
    }
}

private struct PKCEChallenge {
    let codeVerifier: String
    let codeChallenge: String

    static func make() -> PKCEChallenge {
        let verifierData = Data((0..<64).map { _ in UInt8.random(in: .min ... .max) })
        let verifier = verifierData.base64URLEncodedString()
        let digest = SHA256.hash(data: Data(verifier.utf8))
        let challenge = Data(digest).base64URLEncodedString()
        return PKCEChallenge(codeVerifier: verifier, codeChallenge: challenge)
    }
}

private struct TokenSuccessPayload: Decodable {
    let tokenType: String
    let scope: String?
    let expiresIn: Int
    let accessToken: String
    let refreshToken: String?

    enum CodingKeys: String, CodingKey {
        case tokenType = "token_type"
        case scope
        case expiresIn = "expires_in"
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
    }
}

private struct TokenErrorPayload: Decodable {
    let error: String?
    let errorDescription: String?

    enum CodingKeys: String, CodingKey {
        case error
        case errorDescription = "error_description"
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
