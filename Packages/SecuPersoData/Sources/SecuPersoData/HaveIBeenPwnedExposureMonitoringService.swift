import CryptoKit
import Foundation
import SecuPersoDomain

public final class HaveIBeenPwnedExposureMonitoringService: ExposureMonitoringService, ExposureSourceConfigurationService, MonitoredEmailService, @unchecked Sendable {
    public typealias DataLoader = @Sendable (URLRequest) async throws -> (Data, URLResponse)
    public typealias Sleeper = @Sendable (Duration) async throws -> Void

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
    private let requestInterval: Duration
    private let sleeper: Sleeper
    private let streamStore = StreamStore<[ExposureRecord]>(initialValue: [])
    private let migrationState = MigrationState()

    public init(
        secureStore: any SecureStore,
        preferences: UserDefaults = .standard,
        apiKeyIdentifier: String = "com.secuperso.app.hibp.api-key",
        emailDefaultsKey: String = "com.secuperso.app.hibp.email",
        userAgentDefaultsKey: String = "com.secuperso.app.hibp.user-agent",
        baseURL: URL = URL(string: "https://haveibeenpwned.com")!,
        database: EncryptedSQLiteDatabase? = nil,
        dataLoader: DataLoader? = nil,
        nowProvider: @escaping @Sendable () -> Date = Date.init,
        requestInterval: Duration = .seconds(2),
        sleeper: Sleeper? = nil
    ) {
        self.configurationStore = ExposureSourceConfigurationStore(
            secureStore: secureStore,
            preferences: SendableUserDefaults(preferences),
            apiKeyIdentifier: apiKeyIdentifier,
            userAgentDefaultsKey: userAgentDefaultsKey,
            legacyEmailDefaultsKey: emailDefaultsKey,
            defaultUserAgent: Self.defaultUserAgent
        )
        self.baseURL = baseURL
        self.database = database
        self.dataLoader = dataLoader ?? { request in
            try await URLSession.shared.data(for: request)
        }
        self.nowProvider = nowProvider
        self.requestInterval = requestInterval
        self.sleeper = sleeper ?? { duration in
            try await Task.sleep(for: duration)
        }
    }

    public func loadConfiguration() async throws -> ExposureSourceConfiguration {
        let configuration = try await configurationStore.loadConfiguration()
        return Self.sanitize(configuration)
    }

    public func saveConfiguration(_ configuration: ExposureSourceConfiguration) async throws {
        let sanitized = Self.sanitize(configuration)
        try await configurationStore.saveConfiguration(sanitized)
    }

    public func listMonitoredEmails() async throws -> [MonitoredEmailAddress] {
        try await migrateLegacyMonitoredEmailIfNeeded()
        guard let database else {
            return []
        }

        return try database.fetchMonitoredEmails()
    }

    public func addMonitoredEmail(_ email: String, providerHint: ProviderID) async throws -> MonitoredEmailAddress {
        guard let database else {
            throw SecuPersoDataError.sqliteFailure("Monitored email storage is unavailable.")
        }

        try await migrateLegacyMonitoredEmailIfNeeded()

        let normalizedEmail = Self.normalizeEmail(email)
        guard !normalizedEmail.isEmpty else {
            throw SecuPersoDataError.invalidRemoteConfiguration("Monitored email cannot be empty.")
        }
        guard Self.isValidEmail(normalizedEmail) else {
            throw SecuPersoDataError.invalidRemoteConfiguration("Monitored email format is invalid.")
        }

        let existing = try database.fetchMonitoredEmails()
        if existing.contains(where: { Self.normalizeEmail($0.email) == normalizedEmail }) {
            throw SecuPersoDataError.duplicateMonitoredEmail
        }

        let monitoredEmail = MonitoredEmailAddress(
            id: UUID(),
            email: normalizedEmail,
            providerHint: providerHint,
            isEnabled: true,
            createdAt: nowProvider(),
            lastCheckedAt: nil
        )

        try database.upsertMonitoredEmail(monitoredEmail)
        try database.appendAuditEvent("Added monitored email: \(normalizedEmail)")
        return monitoredEmail
    }

    public func setMonitoredEmailEnabled(id: UUID, isEnabled: Bool) async throws {
        guard let database else {
            throw SecuPersoDataError.sqliteFailure("Monitored email storage is unavailable.")
        }

        guard var existing = try database.fetchMonitoredEmail(id: id) else {
            throw SecuPersoDataError.monitoredEmailNotFound(id)
        }

        existing.isEnabled = isEnabled
        try database.upsertMonitoredEmail(existing)

        if !isEnabled {
            let scopeFingerprint = database.emailFingerprint(for: existing.email)
            try database.replaceExposures(forEmailFingerprint: scopeFingerprint, findingRecords: [])
            streamStore.publish(try database.fetchExposures())
        }

        try database.appendAuditEvent("Updated monitored email \(existing.email) enabled=\(isEnabled)")
    }

    public func removeMonitoredEmail(id: UUID) async throws {
        guard let database else {
            throw SecuPersoDataError.sqliteFailure("Monitored email storage is unavailable.")
        }

        guard let monitored = try database.fetchMonitoredEmail(id: id) else {
            throw SecuPersoDataError.monitoredEmailNotFound(id)
        }

        try database.removeMonitoredEmail(id: id)
        try database.appendAuditEvent("Removed monitored email: \(monitored.email)")
        streamStore.publish(try database.fetchExposures())
    }

    public func refresh() async throws -> [ExposureRecord] {
        let rawConfiguration = try await loadConfiguration()
        let configuration = Self.sanitize(rawConfiguration)

        guard configuration.isComplete else {
            if let database {
                try database.replaceExposures([])
            }
            streamStore.publish([])
            return []
        }

        let enabledEmails = try await listMonitoredEmails()
            .filter(\.isEnabled)

        guard !enabledEmails.isEmpty else {
            if let database {
                try database.replaceExposures([])
            }
            streamStore.publish([])
            return []
        }

        guard let database else {
            throw SecuPersoDataError.sqliteFailure("Exposure refresh requires local database support.")
        }

        var attemptedCount = 0
        var succeededCount = 0
        var failedCount = 0
        var warnings: [String] = []

        for (index, monitoredEmail) in enabledEmails.enumerated() {
            if index > 0 {
                try await sleeper(requestInterval)
            }

            attemptedCount += 1
            do {
                let outcome = try await fetchExposureOutcome(email: monitoredEmail.email, configuration: configuration)
                let scopeFingerprint = database.emailFingerprint(for: monitoredEmail.email)

                switch outcome {
                case .findings(let records):
                    try database.replaceExposures(forEmailFingerprint: scopeFingerprint, findingRecords: records)
                case .clear:
                    try database.replaceExposures(forEmailFingerprint: scopeFingerprint, findingRecords: [])
                }

                var updatedMonitored = monitoredEmail
                updatedMonitored.lastCheckedAt = nowProvider()
                try database.upsertMonitoredEmail(updatedMonitored)
                succeededCount += 1
            } catch let error as SecuPersoDataError {
                if case .exposureBatchAborted(let reason) = error {
                    try database.appendAuditEvent(
                        "Exposure refresh aborted after \(attemptedCount) email(s): \(reason)"
                    )
                    throw error
                }
                failedCount += 1
                warnings.append("\(monitoredEmail.email): \(error.localizedDescription)")
            } catch {
                failedCount += 1
                warnings.append("\(monitoredEmail.email): \(error.localizedDescription)")
            }
        }

        let exposures = try database.fetchExposures()
        streamStore.publish(exposures)

        var audit = "Refreshed HIBP exposures for \(enabledEmails.count) monitored email(s); success=\(succeededCount), failed=\(failedCount), open=\(exposures.filter { $0.status == .open }.count)."
        if !warnings.isEmpty {
            let warningSuffix = warnings.joined(separator: " | ")
            audit += " Warnings: \(warningSuffix)"
        }
        try database.appendAuditEvent(audit)

        return exposures
    }

    public func stream() -> AsyncStream<[ExposureRecord]> {
        streamStore.makeStream()
    }

    private func migrateLegacyMonitoredEmailIfNeeded() async throws {
        guard let database else { return }
        guard await migrationState.markMigrationAsNeeded() else {
            return
        }

        do {
            let existing = try database.fetchMonitoredEmails()
            guard existing.isEmpty else {
                return
            }

            let legacyEmail = Self.normalizeEmail(await configurationStore.loadLegacyMonitoredEmail())
            guard !legacyEmail.isEmpty else {
                return
            }

            guard Self.isValidEmail(legacyEmail) else {
                try database.appendAuditEvent("Skipped invalid legacy monitored email during migration.")
                return
            }

            let migrated = MonitoredEmailAddress(
                id: UUID(),
                email: legacyEmail,
                providerHint: .other,
                isEnabled: true,
                createdAt: nowProvider(),
                lastCheckedAt: nil
            )
            try database.upsertMonitoredEmail(migrated)
            try database.appendAuditEvent("Migrated legacy monitored email configuration into monitored email store.")
        } catch {
            throw SecuPersoDataError.migrationFailure(error.localizedDescription)
        }
    }

    private func fetchExposureOutcome(
        email: String,
        configuration: ExposureSourceConfiguration
    ) async throws -> ExposureFetchOutcome {
        let request = try makeRequest(email: email, configuration: configuration)
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
                let findings = breaches
                    .map { Self.mapBreach($0, email: email, now: now) }
                    .sorted(by: { $0.foundAt > $1.foundAt })
                return .findings(findings)
            } catch {
                throw SecuPersoDataError.remoteDecodeFailure
            }
        case 404:
            return .clear
        case 401:
            throw SecuPersoDataError.exposureBatchAborted(
                reason: "HIBP key was rejected. Update the API key in Settings."
            )
        case 403:
            throw SecuPersoDataError.exposureBatchAborted(
                reason: "HIBP rejected the request. Verify user-agent in Settings."
            )
        case 429:
            let retryAfter = httpResponse.value(forHTTPHeaderField: "Retry-After")
            let suffix = retryAfter.map { " Retry after \($0) seconds." } ?? ""
            throw SecuPersoDataError.exposureBatchAborted(
                reason: "HIBP rate limit reached.\(suffix)"
            )
        case 500...599:
            throw SecuPersoDataError.remoteRequestRejected(
                statusCode: httpResponse.statusCode,
                message: "HIBP is temporarily unavailable."
            )
        default:
            throw SecuPersoDataError.remoteRequestRejected(
                statusCode: httpResponse.statusCode,
                message: "HIBP request failed."
            )
        }
    }

    private func makeRequest(email: String, configuration: ExposureSourceConfiguration) throws -> URLRequest {
        let encodedEmail = Self.encodePathComponent(email)
        guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else {
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

    private static func normalizeEmail(_ email: String) -> String {
        email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    private static func isValidEmail(_ email: String) -> Bool {
        let pattern = "^[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
        return email.range(of: pattern, options: .regularExpression) != nil
    }

    private static func sanitize(_ configuration: ExposureSourceConfiguration) -> ExposureSourceConfiguration {
        let apiKey = configuration.apiKey.trimmingCharacters(in: .whitespacesAndNewlines)

        var userAgent = configuration.userAgent.trimmingCharacters(in: .whitespacesAndNewlines)
        if userAgent.isEmpty {
            userAgent = defaultUserAgent
        }

        return ExposureSourceConfiguration(apiKey: apiKey, userAgent: userAgent)
    }
}

private actor MigrationState {
    private var didAttemptMigration = false

    func markMigrationAsNeeded() -> Bool {
        guard !didAttemptMigration else {
            return false
        }
        didAttemptMigration = true
        return true
    }
}

private enum ExposureFetchOutcome {
    case findings([ExposureRecord])
    case clear
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
