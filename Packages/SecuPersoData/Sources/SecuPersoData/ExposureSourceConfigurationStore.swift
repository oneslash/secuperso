import Foundation
import SecuPersoDomain

final class SendableUserDefaults: @unchecked Sendable {
    let raw: UserDefaults

    init(_ raw: UserDefaults) {
        self.raw = raw
    }
}

actor ExposureSourceConfigurationStore: Sendable {
    private let secureStore: any SecureStore
    private let preferences: SendableUserDefaults
    private let apiKeyIdentifier: String
    private let userAgentDefaultsKey: String
    private let legacyEmailDefaultsKey: String
    private let defaultUserAgent: String

    init(
        secureStore: any SecureStore,
        preferences: SendableUserDefaults,
        apiKeyIdentifier: String,
        userAgentDefaultsKey: String,
        legacyEmailDefaultsKey: String,
        defaultUserAgent: String
    ) {
        self.secureStore = secureStore
        self.preferences = preferences
        self.apiKeyIdentifier = apiKeyIdentifier
        self.userAgentDefaultsKey = userAgentDefaultsKey
        self.legacyEmailDefaultsKey = legacyEmailDefaultsKey
        self.defaultUserAgent = defaultUserAgent
    }

    func loadConfiguration() throws -> ExposureSourceConfiguration {
        let apiKeyData = try secureStore.read(apiKeyIdentifier)
        let apiKey = apiKeyData.flatMap { String(data: $0, encoding: .utf8) } ?? ""
        let storedUserAgent = preferences.raw.string(forKey: userAgentDefaultsKey) ?? ""
        let userAgent = storedUserAgent.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? defaultUserAgent
            : storedUserAgent

        return ExposureSourceConfiguration(apiKey: apiKey, userAgent: userAgent)
    }

    func saveConfiguration(_ configuration: ExposureSourceConfiguration) throws {
        try secureStore.write(Data(configuration.apiKey.utf8), for: apiKeyIdentifier)
        preferences.raw.set(configuration.userAgent, forKey: userAgentDefaultsKey)
    }

    func loadLegacyMonitoredEmail() -> String {
        preferences.raw.string(forKey: legacyEmailDefaultsKey) ?? ""
    }
}
