import CryptoKit
import Foundation
import SecuPersoDomain

public final class HaveIBeenPwnedExposureMonitoringService: ExposureMonitoringService, ExposureSourceConfigurationService, @unchecked Sendable {
    public typealias DataLoader = @Sendable (URLRequest) async throws -> (Data, URLResponse)

    private static let criticalDataClasses: Set<String> = [
        "passwords",
        "password hints",
        "bank account numbers",
        "credit cards",
        "payment histories",
        "security questions and answers",
        "social security numbers"
    ]
    private static let highRiskDataClasses: Set<String> = [
        "dates of birth",
        "geographic locations",
        "ip addresses",
        "phone numbers",
        "physical addresses",
        "passport numbers",
        "medical records"
    ]
    private static let defaultUserAgent = "SecuPersoApp/1.0"

    private let configurationStore: ExposureSourceConfigurationStore
    private let baseURL: URL
    private let database: EncryptedSQLiteDatabase?
    private let dataLoader: DataLoader
    private let nowProvider: @Sendable () -> Date
    private let streamStore = StreamStore<[ExposureRecord]>(initialValue: [])

    public init(
        secureStore: any SecureStore,
        preferences: UserDefaults = .standard,
        apiKeyIdentifier: String = "com.secuperso.app.hibp.api-key",
        emailDefaultsKey: String = "com.secuperso.app.hibp.email",
        userAgentDefaultsKey: String = "com.secuperso.app.hibp.user-agent",
        baseURL: URL = URL(string: "https://haveibeenpwned.com")!,
        database: EncryptedSQLiteDatabase? = nil,
        dataLoader: DataLoader? = nil,
        nowProvider: @escaping @Sendable () -> Date = Date.init
    ) {
        self.configurationStore = ExposureSourceConfigurationStore(
            secureStore: secureStore,
            preferences: SendableUserDefaults(preferences),
            apiKeyIdentifier: apiKeyIdentifier,
            emailDefaultsKey: emailDefaultsKey,
            userAgentDefaultsKey: userAgentDefaultsKey,
            defaultUserAgent: Self.defaultUserAgent
        )
        self.baseURL = baseURL
        self.database = database
        self.dataLoader = dataLoader ?? { request in
            try await URLSession.shared.data(for: request)
        }
        self.nowProvider = nowProvider
    }

    public func loadConfiguration() async throws -> ExposureSourceConfiguration {
        let configuration = try await configurationStore.loadConfiguration()
        return Self.sanitize(configuration)
    }

    public func saveConfiguration(_ configuration: ExposureSourceConfiguration) async throws {
        let sanitized = Self.sanitize(configuration)
        try await configurationStore.saveConfiguration(sanitized)
    }

    public func refresh() async throws -> [ExposureRecord] {
        let rawConfiguration = try await loadConfiguration()
        let sanitized = Self.sanitize(rawConfiguration)

        guard sanitized.isComplete else {
            if let database {
                try database.replaceExposures([])
            }
            streamStore.publish([])
            return []
        }

        let configuration = try HaveIBeenPwnedRequestConfiguration(
            apiKey: sanitized.apiKey,
            monitoredEmail: sanitized.email,
            userAgent: sanitized.userAgent,
            baseURL: baseURL
        )

        let exposures = try await fetchExposures(using: configuration)
        if let database {
            try database.replaceExposures(exposures)
            try database.appendAuditEvent("Refreshed exposures from HIBP for \(sanitized.email)")
        }
        streamStore.publish(exposures)
        return exposures
    }

    public func stream() -> AsyncStream<[ExposureRecord]> {
        streamStore.makeStream()
    }

    private func fetchExposures(using configuration: HaveIBeenPwnedRequestConfiguration) async throws -> [ExposureRecord] {
        let request = try makeRequest(using: configuration)
        let (data, response) = try await dataLoader(request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw SecuPersoDataError.remoteResponseInvalid
        }

        switch httpResponse.statusCode {
        case 200:
            let decoder = JSONDecoder()
            do {
                let breaches = try decoder.decode([HIBPBreach].self, from: data)
                let now = nowProvider()
                return breaches
                    .map { Self.mapBreach($0, email: configuration.monitoredEmail, now: now) }
                    .sorted(by: { $0.foundAt > $1.foundAt })
            } catch {
                throw SecuPersoDataError.remoteDecodeFailure
            }
        case 404:
            return []
        case 401:
            throw SecuPersoDataError.remoteRequestRejected(
                statusCode: 401,
                message: "HIBP key was rejected. Update the API key in Settings."
            )
        case 403:
            throw SecuPersoDataError.remoteRequestRejected(
                statusCode: 403,
                message: "HIBP rejected the request. Verify user-agent in Settings."
            )
        case 429:
            throw SecuPersoDataError.remoteRequestRejected(
                statusCode: 429,
                message: "HIBP rate limit reached. Retry later."
            )
        default:
            throw SecuPersoDataError.remoteRequestRejected(
                statusCode: httpResponse.statusCode,
                message: "HIBP request failed."
            )
        }
    }

    private func makeRequest(using configuration: HaveIBeenPwnedRequestConfiguration) throws -> URLRequest {
        let encodedEmail = Self.encodePathComponent(configuration.monitoredEmail)
        guard var components = URLComponents(url: configuration.baseURL, resolvingAgainstBaseURL: false) else {
            throw SecuPersoDataError.invalidRemoteConfiguration("Unable to construct HIBP endpoint URL.")
        }

        components.path = "/api/v3/breachedaccount/\(encodedEmail)"
        components.queryItems = [URLQueryItem(name: "truncateResponse", value: "false")]

        guard let url = components.url else {
            throw SecuPersoDataError.invalidRemoteConfiguration("Unable to build HIBP endpoint URL.")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue(configuration.apiKey, forHTTPHeaderField: "hibp-api-key")
        request.setValue(configuration.userAgent, forHTTPHeaderField: "user-agent")
        request.setValue("application/json", forHTTPHeaderField: "accept")
        request.timeoutInterval = 15
        return request
    }

    private static func encodePathComponent(_ value: String) -> String {
        let disallowed = CharacterSet(charactersIn: "/")
        let allowed = CharacterSet.urlPathAllowed.subtracting(disallowed)
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }

    private static func mapBreach(_ breach: HIBPBreach, email: String, now: Date) -> ExposureRecord {
        let sourceTitle = breach.title?.trimmingCharacters(in: .whitespacesAndNewlines)
        let source = (sourceTitle?.isEmpty == false ? sourceTitle : breach.name) ?? "Unknown breach"
        let foundAt = parseDate(breach.addedDate)
            ?? parseDate(breach.modifiedDate)
            ?? parseDate(breach.breachDate)
            ?? now

        return ExposureRecord(
            id: deterministicID(email: email, breachName: breach.name, breachDate: breach.breachDate),
            email: email,
            source: source,
            foundAt: foundAt,
            severity: severity(for: breach),
            status: .open,
            remediation: remediation(for: breach, source: source)
        )
    }

    private static func severity(for breach: HIBPBreach) -> ExposureSeverity {
        let normalizedClasses = Set((breach.dataClasses ?? []).map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        })

        if breach.isSensitive == true || breach.isStealerLog == true || breach.isMalware == true {
            return .critical
        }
        if !criticalDataClasses.isDisjoint(with: normalizedClasses) {
            return .critical
        }
        if (breach.pwnCount ?? 0) >= 50_000_000 {
            return .critical
        }
        if !highRiskDataClasses.isDisjoint(with: normalizedClasses) {
            return .high
        }
        if (breach.pwnCount ?? 0) >= 1_000_000 {
            return .high
        }
        if breach.isSpamList == true {
            return .low
        }
        return .medium
    }

    private static func remediation(for breach: HIBPBreach, source: String) -> String {
        let normalizedClasses = Set((breach.dataClasses ?? []).map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        })
        var actions: [String] = [
            "Rotate credentials for affected \(source) accounts and avoid password reuse.",
            "Enable MFA or passkeys on critical accounts."
        ]

        if normalizedClasses.contains("passwords") || normalizedClasses.contains("password hints") {
            actions.append("Invalidate active sessions and update all reused passwords.")
        }
        if normalizedClasses.contains("credit cards")
            || normalizedClasses.contains("bank account numbers")
            || normalizedClasses.contains("payment histories") {
            actions.append("Monitor financial accounts and consider card replacement if activity is suspicious.")
        }
        if normalizedClasses.contains("phone numbers") || normalizedClasses.contains("physical addresses") {
            actions.append("Be alert for targeted phishing and account recovery fraud attempts.")
        }

        return actions.joined(separator: " ")
    }

    private static func deterministicID(email: String, breachName: String, breachDate: String) -> UUID {
        let value = "\(email.lowercased())|\(breachName.lowercased())|\(breachDate)"
        let digest = SHA256.hash(data: Data(value.utf8))
        let bytes = Array(digest.prefix(16))
        var uuidBytes: [UInt8] = bytes
        uuidBytes[6] = (uuidBytes[6] & 0x0F) | 0x40
        uuidBytes[8] = (uuidBytes[8] & 0x3F) | 0x80

        return UUID(uuid: (
            uuidBytes[0], uuidBytes[1], uuidBytes[2], uuidBytes[3],
            uuidBytes[4], uuidBytes[5], uuidBytes[6], uuidBytes[7],
            uuidBytes[8], uuidBytes[9], uuidBytes[10], uuidBytes[11],
            uuidBytes[12], uuidBytes[13], uuidBytes[14], uuidBytes[15]
        ))
    }

    private static func parseDate(_ rawValue: String?) -> Date? {
        guard let rawValue = rawValue?.trimmingCharacters(in: .whitespacesAndNewlines), !rawValue.isEmpty else {
            return nil
        }

        let withFractionalSeconds = ISO8601DateFormatter()
        withFractionalSeconds.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = withFractionalSeconds.date(from: rawValue) {
            return date
        }

        let plainISO = ISO8601DateFormatter()
        if let date = plainISO.date(from: rawValue) {
            return date
        }

        let dateOnly = DateFormatter()
        dateOnly.calendar = Calendar(identifier: .iso8601)
        dateOnly.locale = Locale(identifier: "en_US_POSIX")
        dateOnly.timeZone = TimeZone(secondsFromGMT: 0)
        dateOnly.dateFormat = "yyyy-MM-dd"
        return dateOnly.date(from: rawValue)
    }

    private static func sanitize(_ configuration: ExposureSourceConfiguration) -> ExposureSourceConfiguration {
        let apiKey = configuration.apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
        let email = configuration.email.trimmingCharacters(in: .whitespacesAndNewlines)

        var userAgent = configuration.userAgent.trimmingCharacters(in: .whitespacesAndNewlines)
        if userAgent.isEmpty {
            userAgent = defaultUserAgent
        }

        return ExposureSourceConfiguration(apiKey: apiKey, email: email, userAgent: userAgent)
    }

}

private struct HaveIBeenPwnedRequestConfiguration: Sendable {
    let apiKey: String
    let monitoredEmail: String
    let userAgent: String
    let baseURL: URL

    init(
        apiKey: String,
        monitoredEmail: String,
        userAgent: String,
        baseURL: URL
    ) throws {
        guard !apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw SecuPersoDataError.invalidRemoteConfiguration("HIBP API key is empty.")
        }
        guard !monitoredEmail.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw SecuPersoDataError.invalidRemoteConfiguration("HIBP monitored email is empty.")
        }
        guard !userAgent.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw SecuPersoDataError.invalidRemoteConfiguration("HIBP user-agent is empty.")
        }

        self.apiKey = apiKey
        self.monitoredEmail = monitoredEmail
        self.userAgent = userAgent
        self.baseURL = baseURL
    }
}

private struct HIBPBreach: Decodable, Sendable {
    let name: String
    let title: String?
    let breachDate: String
    let addedDate: String?
    let modifiedDate: String?
    let pwnCount: Int?
    let dataClasses: [String]?
    let isSensitive: Bool?
    let isSpamList: Bool?
    let isStealerLog: Bool?
    let isMalware: Bool?

    enum CodingKeys: String, CodingKey {
        case name = "Name"
        case title = "Title"
        case breachDate = "BreachDate"
        case addedDate = "AddedDate"
        case modifiedDate = "ModifiedDate"
        case pwnCount = "PwnCount"
        case dataClasses = "DataClasses"
        case isSensitive = "IsSensitive"
        case isSpamList = "IsSpamList"
        case isStealerLog = "IsStealerLog"
        case isMalware = "IsMalware"
    }
}
