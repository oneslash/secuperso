import CryptoKit
import Foundation
import SecuPersoData
import SecuPersoDomain
import SecuPersoFeatures

@MainActor
final class AppContainer {
    let viewModel: SecurityConsoleViewModel
    let exposureViewModel: ExposureViewModel

    init(bundle: Bundle = .main) throws {
        let exposureURL = try Self.fixtureURL(named: "exposures", bundle: bundle)
        let loginURL = try Self.fixtureURL(named: "login_events", bundle: bundle)
        let providerURL = try Self.fixtureURL(named: "providers", bundle: bundle)

        let fixtureLoader = FixtureDataLoader(
            exposuresURL: exposureURL,
            loginEventsURL: loginURL,
            providersURL: providerURL
        )

        let secureStore = KeychainSecureStore(service: "com.secuperso.app")
        let keyProvider = EncryptionKeyProvider(secureStore: secureStore, keyIdentifier: "com.secuperso.app.db-key")
        let encryptionKey = try keyProvider.loadOrCreateKey()

        let database = try EncryptedSQLiteDatabase(
            databaseURL: try Self.databaseURL(),
            key: encryptionKey
        )

        let coordinator = MockDataCoordinator(
            fixtureLoader: fixtureLoader,
            database: database,
            initialScenario: .moderate
        )

        let exposureService = HaveIBeenPwnedExposureMonitoringService(
            secureStore: secureStore,
            database: database
        )
        let fallbackLoginService = MockLoginActivityService(coordinator: coordinator)
        let incidentService = MockIncidentService(coordinator: coordinator)
        let fallbackProviderConnectionService = MockProviderConnectionService(coordinator: coordinator)
        let googleOAuthConfiguration = Self.googleOAuthConfiguration(bundle: bundle)
        let googleTokenStore = GoogleOAuthTokenStore(secureStore: secureStore)
        let googleOAuthService = GoogleOAuthService(
            coordinator: coordinator,
            configuration: googleOAuthConfiguration,
            authorizationSession: WebAuthenticationSessionAdapter(),
            tokenExchanger: URLSessionGoogleOAuthTokenExchanger(),
            tokenStore: googleTokenStore
        )
        let loginService = GoogleWorkspaceLoginActivityService(
            fallbackService: fallbackLoginService,
            oauthConfiguration: googleOAuthConfiguration,
            tokenStore: googleTokenStore,
            tokenRefresher: URLSessionGoogleOAuthTokenRefresher(),
            historyClient: URLSessionGoogleWorkspaceLoginHistoryClient(),
            historyConfiguration: Self.googleWorkspaceLoginHistoryConfiguration(bundle: bundle)
        )
        let microsoftOAuthConfiguration = Self.microsoftOAuthConfiguration(bundle: bundle)
        let microsoftTokenStore = MicrosoftOAuthTokenStore(secureStore: secureStore)
        let microsoftOutlookService = MicrosoftOutlookOAuthService(
            coordinator: coordinator,
            configuration: microsoftOAuthConfiguration,
            authorizationSession: WebAuthenticationSessionAdapter(),
            tokenExchanger: URLSessionMicrosoftOAuthTokenExchanger(),
            tokenStore: microsoftTokenStore
        )
        let providerConnectionService = HybridProviderConnectionService(
            fallbackService: fallbackProviderConnectionService,
            googleService: googleOAuthService,
            outlookService: microsoftOutlookService
        )
        let providerCatalogService = MockProviderCatalogService(coordinator: coordinator)
        let scenarioControlService = MockScenarioControlService(coordinator: coordinator)
        let loginActionService = MockLoginEventActionService(coordinator: coordinator)

        let notificationManager = LocalNotificationManager()
        let securityViewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerConnectionService,
            providerConnectionReadableService: providerConnectionService,
            providerCatalogService: providerCatalogService,
            scenarioControlService: scenarioControlService,
            loginEventActionService: loginActionService,
            initialScenario: .moderate,
            highRiskNotifier: { snapshot in
                await notificationManager.notifyHighRisk(snapshot: snapshot)
            }
        )
        self.viewModel = securityViewModel
        self.exposureViewModel = ExposureViewModel(
            monitoredEmailService: exposureService,
            exposureConfigurationService: exposureService,
            refreshAction: {
                await securityViewModel.refreshAll()
            }
        )
    }

    private static func fixtureURL(named name: String, bundle: Bundle) throws -> URL {
        if let url = bundle.url(forResource: name, withExtension: "json", subdirectory: "Fixtures") {
            return url
        }
        if let url = bundle.url(forResource: name, withExtension: "json") {
            return url
        }

        if let resourceRoot = bundle.resourceURL {
            let targetFilename = "\(name).json"
            if let enumerator = FileManager.default.enumerator(
                at: resourceRoot,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ) {
                for case let candidate as URL in enumerator where candidate.lastPathComponent == targetFilename {
                    return candidate
                }
            }
        }

        throw SecuPersoDataError.fixtureFileMissing("\(name).json")
    }

    private static func databaseURL() throws -> URL {
        let appSupport = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        let directory = appSupport.appendingPathComponent("SecuPerso", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("secuperso.sqlite", isDirectory: false)
    }

    private static func microsoftOAuthConfiguration(bundle: Bundle) -> MicrosoftOAuthConfiguration? {
        guard let rawClientID = bundle.object(forInfoDictionaryKey: "MS_ENTRA_CLIENT_ID") as? String else {
            return nil
        }
        let clientID = rawClientID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clientID.isEmpty else {
            return nil
        }

        let tenantID = (
            bundle.object(forInfoDictionaryKey: "MS_ENTRA_TENANT_ID") as? String
        )?.trimmingCharacters(in: .whitespacesAndNewlines)
            ?? "common"

        let redirectURIString = (
            bundle.object(forInfoDictionaryKey: "MS_ENTRA_REDIRECT_URI") as? String
        )?.trimmingCharacters(in: .whitespacesAndNewlines)
            ?? "secuperso://oauth"
        guard let redirectURI = URL(string: redirectURIString) else {
            return nil
        }

        let scopesString = (
            bundle.object(forInfoDictionaryKey: "MS_ENTRA_SCOPES") as? String
        )?.trimmingCharacters(in: .whitespacesAndNewlines)
            ?? "openid profile offline_access User.Read"
        let scopes = scopesString
            .split(whereSeparator: \.isWhitespace)
            .map(String.init)
        let resolvedScopes = scopes.isEmpty
            ? ["openid", "profile", "offline_access", "User.Read"]
            : scopes

        return MicrosoftOAuthConfiguration(
            clientID: clientID,
            tenantID: tenantID.isEmpty ? "common" : tenantID,
            redirectURI: redirectURI,
            scopes: resolvedScopes
        )
    }

    private static func googleOAuthConfiguration(bundle: Bundle) -> GoogleOAuthConfiguration? {
        guard let rawClientID = bundle.object(forInfoDictionaryKey: "GOOGLE_OAUTH_CLIENT_ID") as? String else {
            return nil
        }
        let clientID = rawClientID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clientID.isEmpty else {
            return nil
        }

        let redirectURIString = (
            bundle.object(forInfoDictionaryKey: "GOOGLE_OAUTH_REDIRECT_URI") as? String
        )?.trimmingCharacters(in: .whitespacesAndNewlines)
            ?? "secuperso://oauth"
        guard let redirectURI = URL(string: redirectURIString) else {
            return nil
        }

        let scopesString = (
            bundle.object(forInfoDictionaryKey: "GOOGLE_OAUTH_SCOPES") as? String
        )?.trimmingCharacters(in: .whitespacesAndNewlines)
            ?? "openid profile email"
        let scopes = scopesString
            .split(whereSeparator: \.isWhitespace)
            .map(String.init)
        let resolvedScopes = scopes.isEmpty ? ["openid", "profile", "email"] : scopes

        let clientSecretValue = (
            bundle.object(forInfoDictionaryKey: "GOOGLE_OAUTH_CLIENT_SECRET") as? String
        )?.trimmingCharacters(in: .whitespacesAndNewlines)
        let clientSecret = (clientSecretValue?.isEmpty == false) ? clientSecretValue : nil

        return GoogleOAuthConfiguration(
            clientID: clientID,
            clientSecret: clientSecret,
            redirectURI: redirectURI,
            scopes: resolvedScopes
        )
    }

    private static func googleWorkspaceLoginHistoryConfiguration(bundle: Bundle) -> GoogleWorkspaceLoginHistoryConfiguration {
        let lookbackDays = bundle.object(forInfoDictionaryKey: "GOOGLE_WORKSPACE_LOGIN_LOOKBACK_DAYS") as? Int ?? 30
        let maxResults = bundle.object(forInfoDictionaryKey: "GOOGLE_WORKSPACE_LOGIN_MAX_RESULTS") as? Int ?? 200
        let maxPages = bundle.object(forInfoDictionaryKey: "GOOGLE_WORKSPACE_LOGIN_MAX_PAGES") as? Int ?? 5

        return GoogleWorkspaceLoginHistoryConfiguration(
            lookbackDays: lookbackDays,
            maxResultsPerPage: maxResults,
            maxPages: maxPages
        )
    }
}
