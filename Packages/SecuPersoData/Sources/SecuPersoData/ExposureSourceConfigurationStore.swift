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
    private let emailDefaultsKey: String
    private let userAgentDefaultsKey: String
    private let defaultUserAgent: String

    init(
        secureStore: any SecureStore,
        preferences: SendableUserDefaults,
        apiKeyIdentifier: String,
        emailDefaultsKey: String,
        userAgentDefaultsKey: String,
        defaultUserAgent: String
    ) {
        self.secureStore = secureStore
        self.preferences = preferences
        self.apiKeyIdentifier = apiKeyIdentifier
        self.emailDefaultsKey = emailDefaultsKey
        self.userAgentDefaultsKey = userAgentDefaultsKey
        self.defaultUserAgent = defaultUserAgent
    }

    func loadConfiguration() throws -> ExposureSourceConfiguration {
        let apiKeyData = try secureStore.read(apiKeyIdentifier)
        let apiKey = apiKeyData.flatMap { String(data: $0, encoding: .utf8) } ?? ""
        let email = preferences.raw.string(forKey: emailDefaultsKey) ?? ""
        let storedUserAgent = preferences.raw.string(forKey: userAgentDefaultsKey) ?? ""
        let userAgent = storedUserAgent.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? defaultUserAgent
            : storedUserAgent

        return ExposureSourceConfiguration(apiKey: apiKey, email: email, userAgent: userAgent)
    }

    func saveConfiguration(_ configuration: ExposureSourceConfiguration) throws {
        try secureStore.write(Data(configuration.apiKey.utf8), for: apiKeyIdentifier)
        preferences.raw.set(configuration.email, forKey: emailDefaultsKey)
        preferences.raw.set(configuration.userAgent, forKey: userAgentDefaultsKey)
    }
}
