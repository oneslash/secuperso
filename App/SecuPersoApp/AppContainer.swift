import CryptoKit
import Foundation
import SecuPersoData
import SecuPersoDomain
import SecuPersoFeatures

@MainActor
final class AppContainer {
    let viewModel: SecurityConsoleViewModel

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
        let loginService = MockLoginActivityService(coordinator: coordinator)
        let incidentService = MockIncidentService(coordinator: coordinator)
        let providerConnectionService = MockProviderConnectionService(coordinator: coordinator)
        let providerCatalogService = MockProviderCatalogService(coordinator: coordinator)
        let scenarioControlService = MockScenarioControlService(coordinator: coordinator)
        let loginActionService = MockLoginEventActionService(coordinator: coordinator)

        let notificationManager = LocalNotificationManager()
        self.viewModel = SecurityConsoleViewModel(
            exposureService: exposureService,
            loginActivityService: loginService,
            incidentService: incidentService,
            incidentReadableService: incidentService,
            providerConnectionService: providerConnectionService,
            providerConnectionReadableService: providerConnectionService,
            providerCatalogService: providerCatalogService,
            scenarioControlService: scenarioControlService,
            loginEventActionService: loginActionService,
            exposureConfigurationService: exposureService,
            initialScenario: .moderate,
            highRiskNotifier: { snapshot in
                await notificationManager.notifyHighRisk(snapshot: snapshot)
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
}
