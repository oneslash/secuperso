import CryptoKit
import Foundation
import SecuPersoDomain

public struct GoogleOAuthConfiguration: Equatable, Sendable {
    public var clientID: String
    public var clientSecret: String?
    public var redirectURI: URL
    public var scopes: [String]
    public var accessType: String
    public var includeGrantedScopes: Bool
    public var prompt: String

    public init(
        clientID: String,
        clientSecret: String? = nil,
        redirectURI: URL,
        scopes: [String] = ["openid", "profile", "email"],
        accessType: String = "offline",
        includeGrantedScopes: Bool = true,
        prompt: String = "consent"
    ) {
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.redirectURI = redirectURI
        self.scopes = scopes
        self.accessType = accessType
        self.includeGrantedScopes = includeGrantedScopes
        self.prompt = prompt
    }
}

public struct GoogleOAuthToken: Codable, Equatable, Sendable {
    public var accessToken: String
    public var refreshToken: String?
    public var expiresIn: Int
    public var scope: String?
    public var tokenType: String
    public var idToken: String?

    public init(
        accessToken: String,
        refreshToken: String?,
        expiresIn: Int,
        scope: String?,
        tokenType: String,
        idToken: String? = nil
    ) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.expiresIn = expiresIn
        self.scope = scope
        self.tokenType = tokenType
        self.idToken = idToken
    }
}

public struct StoredGoogleOAuthToken: Codable, Equatable, Sendable {
    public var token: GoogleOAuthToken
    public var obtainedAt: Date

    public init(token: GoogleOAuthToken, obtainedAt: Date) {
        self.token = token
        self.obtainedAt = obtainedAt
    }
}

public final class GoogleOAuthTokenStore: @unchecked Sendable {
    private let secureStore: any SecureStore
    private let storageKey: String
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(
        secureStore: any SecureStore,
        storageKey: String = "com.secuperso.app.google.oauth.tokens"
    ) {
        self.secureStore = secureStore
        self.storageKey = storageKey
        decoder.dateDecodingStrategy = .iso8601
        encoder.dateEncodingStrategy = .iso8601
    }

    public func load() throws -> StoredGoogleOAuthToken? {
        guard let data = try secureStore.read(storageKey) else {
            return nil
        }
        return try decoder.decode(StoredGoogleOAuthToken.self, from: data)
    }

    public func save(_ token: GoogleOAuthToken, obtainedAt: Date = Date()) throws {
        let payload = StoredGoogleOAuthToken(token: token, obtainedAt: obtainedAt)
        let data = try encoder.encode(payload)
        try secureStore.write(data, for: storageKey)
    }

    public func clear() throws {
        try secureStore.delete(storageKey)
    }
}

public protocol GoogleOAuthTokenExchanger: Sendable {
    func exchangeCode(
        configuration: GoogleOAuthConfiguration,
        authorizationCode: String,
        codeVerifier: String
    ) async throws -> GoogleOAuthToken
}

public final class URLSessionGoogleOAuthTokenExchanger: GoogleOAuthTokenExchanger, @unchecked Sendable {
    private let session: URLSession
    private let decoder = JSONDecoder()

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func exchangeCode(
        configuration: GoogleOAuthConfiguration,
        authorizationCode: String,
        codeVerifier: String
    ) async throws -> GoogleOAuthToken {
        var request = URLRequest(url: URL(string: "https://oauth2.googleapis.com/token")!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        var fields: [(String, String)] = [
            ("client_id", configuration.clientID),
            ("code", authorizationCode),
            ("redirect_uri", configuration.redirectURI.absoluteString),
            ("grant_type", "authorization_code"),
            ("code_verifier", codeVerifier)
        ]
        if let clientSecret = configuration.clientSecret?.trimmingCharacters(in: .whitespacesAndNewlines),
           !clientSecret.isEmpty {
            fields.append(("client_secret", clientSecret))
        }
        request.httpBody = Self.formBody(fields)

        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw GoogleOAuthFlowError.tokenExchangeFailed("Google token endpoint returned an invalid response.")
        }

        guard (200...299).contains(httpResponse.statusCode) else {
            let payload = try? decoder.decode(GoogleTokenErrorPayload.self, from: data)
            let message = payload?.errorDescription ?? payload?.error ?? "Google token exchange failed."
            throw GoogleOAuthFlowError.tokenExchangeFailed(message)
        }

        let payload: GoogleTokenSuccessPayload
        do {
            payload = try decoder.decode(GoogleTokenSuccessPayload.self, from: data)
        } catch {
            throw GoogleOAuthFlowError.tokenExchangeFailed("Google token response could not be decoded.")
        }

        guard !payload.accessToken.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw GoogleOAuthFlowError.tokenExchangeFailed("Google token response did not include an access token.")
        }
        guard payload.expiresIn > 0 else {
            throw GoogleOAuthFlowError.tokenExchangeFailed("Google token response returned an invalid expiry.")
        }

        return GoogleOAuthToken(
            accessToken: payload.accessToken,
            refreshToken: payload.refreshToken,
            expiresIn: payload.expiresIn,
            scope: payload.scope,
            tokenType: payload.tokenType,
            idToken: payload.idToken
        )
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

public protocol GoogleOAuthTokenRefresher: Sendable {
    func refreshToken(
        configuration: GoogleOAuthConfiguration,
        refreshToken: String
    ) async throws -> GoogleOAuthToken
}

public final class URLSessionGoogleOAuthTokenRefresher: GoogleOAuthTokenRefresher, @unchecked Sendable {
    private let session: URLSession
    private let decoder = JSONDecoder()

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func refreshToken(
        configuration: GoogleOAuthConfiguration,
        refreshToken: String
    ) async throws -> GoogleOAuthToken {
        var fields: [(String, String)] = [
            ("client_id", configuration.clientID),
            ("refresh_token", refreshToken),
            ("grant_type", "refresh_token")
        ]
        if let clientSecret = configuration.clientSecret?.trimmingCharacters(in: .whitespacesAndNewlines),
           !clientSecret.isEmpty {
            fields.append(("client_secret", clientSecret))
        }

        var request = URLRequest(url: URL(string: "https://oauth2.googleapis.com/token")!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = Self.formBody(fields)

        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw GoogleOAuthFlowError.tokenExchangeFailed("Google token refresh returned an invalid response.")
        }

        guard (200...299).contains(httpResponse.statusCode) else {
            let payload = try? decoder.decode(GoogleTokenErrorPayload.self, from: data)
            let message = payload?.errorDescription ?? payload?.error ?? "Google token refresh failed."
            throw GoogleOAuthFlowError.tokenExchangeFailed(message)
        }

        let payload: GoogleTokenSuccessPayload
        do {
            payload = try decoder.decode(GoogleTokenSuccessPayload.self, from: data)
        } catch {
            throw GoogleOAuthFlowError.tokenExchangeFailed("Google token refresh response could not be decoded.")
        }

        guard !payload.accessToken.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw GoogleOAuthFlowError.tokenExchangeFailed("Google token refresh response did not include an access token.")
        }
        guard payload.expiresIn > 0 else {
            throw GoogleOAuthFlowError.tokenExchangeFailed("Google token refresh response returned an invalid expiry.")
        }

        return GoogleOAuthToken(
            accessToken: payload.accessToken,
            refreshToken: payload.refreshToken ?? refreshToken,
            expiresIn: payload.expiresIn,
            scope: payload.scope,
            tokenType: payload.tokenType,
            idToken: payload.idToken
        )
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

public final class GoogleOAuthService: @unchecked Sendable {
    private let coordinator: MockDataCoordinator
    private let configuration: GoogleOAuthConfiguration?
    private let authorizationSession: any OAuthAuthorizationSession
    private let tokenExchanger: any GoogleOAuthTokenExchanger
    private let tokenStore: GoogleOAuthTokenStore

    public init(
        coordinator: MockDataCoordinator,
        configuration: GoogleOAuthConfiguration?,
        authorizationSession: any OAuthAuthorizationSession,
        tokenExchanger: any GoogleOAuthTokenExchanger,
        tokenStore: GoogleOAuthTokenStore
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
                    message: "Opening Google sign-in...",
                    continuation: continuation
                )

                guard let configuration else {
                    await emit(
                        state: .error,
                        message: "Google OAuth is not configured. Set GOOGLE_OAUTH_CLIENT_ID in app settings.",
                        continuation: continuation
                    )
                    return
                }

                do {
                    let callbackScheme = try Self.callbackScheme(from: configuration)
                    let challenge = GooglePKCEChallenge.make()
                    let stateToken = Self.makeStateToken()
                    let authorizeURL = try Self.authorizeURL(
                        configuration: configuration,
                        state: stateToken,
                        codeChallenge: challenge.codeChallenge
                    )

                    await emit(
                        state: .connecting,
                        message: "Waiting for Google consent...",
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
                        message: "Google account connected.",
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
                } catch let error as GoogleOAuthFlowError {
                    await emit(
                        state: error.state,
                        message: error.userMessage,
                        continuation: continuation
                    )
                } catch {
                    await emit(
                        state: .error,
                        message: "Google sign-in failed. Please try again.",
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
        try await coordinator.updateProviderState(.google, state: .disconnected)
    }

    private func emit(
        state: ConnectionState,
        message: String,
        continuation: AsyncStream<ProviderConnectionUpdate>.Continuation
    ) async {
        try? await coordinator.updateProviderState(.google, state: state)
        continuation.yield(ProviderConnectionUpdate(state: state, message: message))
    }

    private static func callbackScheme(from configuration: GoogleOAuthConfiguration) throws -> String {
        let scheme = configuration.redirectURI.scheme?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !scheme.isEmpty else {
            throw GoogleOAuthFlowError.invalidRedirectURI
        }
        return scheme
    }

    private static func authorizeURL(
        configuration: GoogleOAuthConfiguration,
        state: String,
        codeChallenge: String
    ) throws -> URL {
        var queryItems = [
            URLQueryItem(name: "client_id", value: configuration.clientID),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "redirect_uri", value: configuration.redirectURI.absoluteString),
            URLQueryItem(name: "scope", value: configuration.scopes.joined(separator: " ")),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "access_type", value: configuration.accessType),
            URLQueryItem(name: "include_granted_scopes", value: configuration.includeGrantedScopes ? "true" : "false")
        ]

        let prompt = configuration.prompt.trimmingCharacters(in: .whitespacesAndNewlines)
        if !prompt.isEmpty {
            queryItems.append(URLQueryItem(name: "prompt", value: prompt))
        }

        var components = URLComponents(string: "https://accounts.google.com/o/oauth2/v2/auth")
        components?.queryItems = queryItems

        guard let url = components?.url else {
            throw GoogleOAuthFlowError.invalidAuthorizeURL
        }
        return url
    }

    private static func authorizationCode(
        callbackURL: URL,
        expectedState: String
    ) throws -> String {
        guard let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false) else {
            throw GoogleOAuthFlowError.authorizationCodeMissing
        }

        let items = components.queryItems ?? []
        if let error = items.first(where: { $0.name == "error" })?.value {
            if error == "access_denied" {
                throw OAuthAuthorizationSessionError.cancelled
            }
            let description = items.first(where: { $0.name == "error_description" })?.value ?? error
            throw GoogleOAuthFlowError.authorizationRejected(description)
        }

        let returnedState = items.first(where: { $0.name == "state" })?.value
        guard returnedState == expectedState else {
            throw GoogleOAuthFlowError.stateMismatch
        }

        guard let code = items.first(where: { $0.name == "code" })?.value, !code.isEmpty else {
            throw GoogleOAuthFlowError.authorizationCodeMissing
        }
        return code
    }

    private static func makeStateToken() -> String {
        let bytes = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })
        return GoogleOAuthEncoding.base64URL(bytes)
    }
}

private enum GoogleOAuthFlowError: Error {
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
            return "Google OAuth redirect URI is invalid."
        case .invalidAuthorizeURL:
            return "Google OAuth authorize URL could not be built."
        case .authorizationRejected(let message):
            return "Google sign-in was rejected: \(message)"
        case .stateMismatch:
            return "Google sign-in response failed validation."
        case .authorizationCodeMissing:
            return "Google sign-in did not return an authorization code."
        case .tokenExchangeFailed(let message):
            return "Google token exchange failed: \(message)"
        }
    }
}

private struct GooglePKCEChallenge {
    let codeVerifier: String
    let codeChallenge: String

    static func make() -> GooglePKCEChallenge {
        let verifierData = Data((0..<64).map { _ in UInt8.random(in: .min ... .max) })
        let verifier = GoogleOAuthEncoding.base64URL(verifierData)
        let digest = SHA256.hash(data: Data(verifier.utf8))
        let challenge = GoogleOAuthEncoding.base64URL(Data(digest))
        return GooglePKCEChallenge(codeVerifier: verifier, codeChallenge: challenge)
    }
}

private enum GoogleOAuthEncoding {
    static func base64URL(_ value: Data) -> String {
        value.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private struct GoogleTokenSuccessPayload: Decodable {
    let tokenType: String
    let scope: String?
    let expiresIn: Int
    let accessToken: String
    let refreshToken: String?
    let idToken: String?

    enum CodingKeys: String, CodingKey {
        case tokenType = "token_type"
        case scope
        case expiresIn = "expires_in"
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case idToken = "id_token"
    }
}

private struct GoogleTokenErrorPayload: Decodable {
    let error: String?
    let errorDescription: String?

    enum CodingKeys: String, CodingKey {
        case error
        case errorDescription = "error_description"
    }
}
