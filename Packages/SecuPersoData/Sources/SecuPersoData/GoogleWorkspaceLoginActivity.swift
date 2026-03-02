import CryptoKit
import Foundation
import SecuPersoDomain

public struct GoogleWorkspaceLoginHistoryConfiguration: Equatable, Sendable {
    public var lookbackDays: Int
    public var maxResultsPerPage: Int
    public var maxPages: Int

    public init(
        lookbackDays: Int = 30,
        maxResultsPerPage: Int = 200,
        maxPages: Int = 5
    ) {
        self.lookbackDays = lookbackDays
        self.maxResultsPerPage = maxResultsPerPage
        self.maxPages = maxPages
    }

    var normalizedLookbackDays: Int {
        min(max(lookbackDays, 1), 180)
    }

    var normalizedMaxResultsPerPage: Int {
        min(max(maxResultsPerPage, 1), 1000)
    }

    var normalizedMaxPages: Int {
        max(maxPages, 1)
    }
}

public protocol GoogleWorkspaceLoginHistoryClient: Sendable {
    func fetchLoginEvents(
        accessToken: String,
        configuration: GoogleWorkspaceLoginHistoryConfiguration,
        now: Date
    ) async throws -> [LoginEvent]
}

public final class GoogleWorkspaceLoginActivityService: LoginActivityService, @unchecked Sendable {
    private enum RemoteFetchOutcome {
        case unavailable
        case success([LoginEvent])
    }

    private static let adminReportsAuditReadScope = "https://www.googleapis.com/auth/admin.reports.audit.readonly"

    private let fallbackService: any LoginActivityService
    private let oauthConfiguration: GoogleOAuthConfiguration?
    private let tokenStore: GoogleOAuthTokenStore
    private let tokenRefresher: (any GoogleOAuthTokenRefresher)?
    private let historyClient: any GoogleWorkspaceLoginHistoryClient
    private let historyConfiguration: GoogleWorkspaceLoginHistoryConfiguration
    private let nowProvider: @Sendable () -> Date
    private let streamStore = StreamStore<[LoginEvent]>(initialValue: [])

    public init(
        fallbackService: any LoginActivityService,
        oauthConfiguration: GoogleOAuthConfiguration?,
        tokenStore: GoogleOAuthTokenStore,
        tokenRefresher: (any GoogleOAuthTokenRefresher)? = nil,
        historyClient: any GoogleWorkspaceLoginHistoryClient,
        historyConfiguration: GoogleWorkspaceLoginHistoryConfiguration = GoogleWorkspaceLoginHistoryConfiguration(),
        nowProvider: @escaping @Sendable () -> Date = Date.init
    ) {
        self.fallbackService = fallbackService
        self.oauthConfiguration = oauthConfiguration
        self.tokenStore = tokenStore
        self.tokenRefresher = tokenRefresher
        self.historyClient = historyClient
        self.historyConfiguration = historyConfiguration
        self.nowProvider = nowProvider
    }

    public func refresh() async throws -> [LoginEvent] {
        let fallbackEvents = try await fallbackService.refresh()
        let now = nowProvider()
        let remoteOutcome = await fetchRemoteGoogleEvents(now: now)
        let merged = merge(fallbackEvents: fallbackEvents, remoteOutcome: remoteOutcome)
        streamStore.publish(merged)
        return merged
    }

    public func stream() -> AsyncStream<[LoginEvent]> {
        streamStore.makeStream()
    }

    private func fetchRemoteGoogleEvents(now: Date) async -> RemoteFetchOutcome {
        guard let accessToken = await loadAccessToken(now: now) else {
            return .unavailable
        }

        do {
            let remoteEvents = try await historyClient.fetchLoginEvents(
                accessToken: accessToken,
                configuration: historyConfiguration,
                now: now
            )
            return .success(remoteEvents)
        } catch {
            return .unavailable
        }
    }

    private func loadAccessToken(now: Date) async -> String? {
        guard var storedToken = try? tokenStore.load() else {
            return nil
        }

        let expiresAt = storedToken.obtainedAt.addingTimeInterval(Double(storedToken.token.expiresIn))
        let shouldRefresh = expiresAt <= now.addingTimeInterval(120)
        if shouldRefresh,
           let refreshToken = storedToken.token.refreshToken?.trimmingCharacters(in: .whitespacesAndNewlines),
           !refreshToken.isEmpty,
           let oauthConfiguration,
           let tokenRefresher,
           let refreshed = try? await tokenRefresher.refreshToken(
               configuration: oauthConfiguration,
               refreshToken: refreshToken
           ) {
            do {
                try tokenStore.save(refreshed, obtainedAt: now)
                storedToken = StoredGoogleOAuthToken(token: refreshed, obtainedAt: now)
            } catch {
                storedToken = StoredGoogleOAuthToken(token: refreshed, obtainedAt: now)
            }
        }

        guard hasRequiredScope(storedToken.token.scope) else {
            return nil
        }

        let accessToken = storedToken.token.accessToken.trimmingCharacters(in: .whitespacesAndNewlines)
        return accessToken.isEmpty ? nil : accessToken
    }

    private func hasRequiredScope(_ scope: String?) -> Bool {
        guard let scope else {
            return true
        }

        let values = Set(
            scope.split(whereSeparator: \.isWhitespace)
                .map(String.init)
        )
        return values.contains(Self.adminReportsAuditReadScope)
    }

    private func merge(
        fallbackEvents: [LoginEvent],
        remoteOutcome: RemoteFetchOutcome
    ) -> [LoginEvent] {
        let merged: [LoginEvent]
        switch remoteOutcome {
        case .unavailable:
            merged = fallbackEvents
        case .success(let remoteGoogleEvents):
            let nonGoogleFallback = fallbackEvents.filter { $0.provider != .google }
            merged = nonGoogleFallback + remoteGoogleEvents
        }

        return merged.sorted(by: { $0.occurredAt > $1.occurredAt })
    }
}

public final class URLSessionGoogleWorkspaceLoginHistoryClient: GoogleWorkspaceLoginHistoryClient, @unchecked Sendable {
    private let session: URLSession
    private let decoder = JSONDecoder()

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func fetchLoginEvents(
        accessToken: String,
        configuration: GoogleWorkspaceLoginHistoryConfiguration,
        now: Date
    ) async throws -> [LoginEvent] {
        let lookbackWindow = TimeInterval(configuration.normalizedLookbackDays * 86_400)
        let startTime = now.addingTimeInterval(-lookbackWindow)

        var pageToken: String?
        var pageCount = 0
        var eventsByID: [UUID: LoginEvent] = [:]

        repeat {
            pageCount += 1

            let page = try await fetchPage(
                accessToken: accessToken,
                startTime: startTime,
                maxResults: configuration.normalizedMaxResultsPerPage,
                pageToken: pageToken
            )
            for event in mapLoginEvents(from: page.activities, now: now) {
                if let existing = eventsByID[event.id], existing.occurredAt >= event.occurredAt {
                    continue
                }
                eventsByID[event.id] = event
            }

            pageToken = page.nextPageToken
        } while pageToken != nil && pageCount < configuration.normalizedMaxPages

        return eventsByID.values.sorted(by: { $0.occurredAt > $1.occurredAt })
    }

    private func fetchPage(
        accessToken: String,
        startTime: Date,
        maxResults: Int,
        pageToken: String?
    ) async throws -> GoogleWorkspaceActivityPage {
        var components = URLComponents(string: "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login")
        var queryItems = [
            URLQueryItem(name: "startTime", value: GoogleWorkspaceDateFormatter.string(from: startTime)),
            URLQueryItem(name: "maxResults", value: String(maxResults))
        ]
        if let pageToken {
            queryItems.append(URLQueryItem(name: "pageToken", value: pageToken))
        }
        components?.queryItems = queryItems

        guard let url = components?.url else {
            throw SecuPersoDataError.remoteResponseInvalid
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw SecuPersoDataError.remoteResponseInvalid
        }

        guard (200...299).contains(httpResponse.statusCode) else {
            let message = extractGoogleErrorMessage(from: data) ?? "Google Workspace login history request failed."
            throw SecuPersoDataError.remoteRequestRejected(statusCode: httpResponse.statusCode, message: message)
        }

        do {
            let payload = try decoder.decode(GoogleWorkspaceActivityPagePayload.self, from: data)
            let activities = payload.items ?? []
            return GoogleWorkspaceActivityPage(
                activities: activities,
                nextPageToken: payload.nextPageToken
            )
        } catch {
            throw SecuPersoDataError.remoteDecodeFailure
        }
    }

    private func mapLoginEvents(from activities: [GoogleWorkspaceActivity], now: Date) -> [LoginEvent] {
        var events: [LoginEvent] = []

        for activity in activities {
            let occurredAt = GoogleWorkspaceDateFormatter.date(from: activity.id?.time) ?? now
            let ipAddress = normalized(activity.ipAddress) ?? "Unknown"
            let actorEmail = normalized(activity.actor?.email)
            let actorID = normalized(activity.actor?.profileID) ?? normalized(activity.actor?.key)

            let sourceEvents = (activity.events ?? []).enumerated().filter { _, event in
                isLoginLike(event: event)
            }

            if sourceEvents.isEmpty {
                let stableInput = [
                    activity.id?.uniqueQualifier ?? "",
                    activity.id?.time ?? "",
                    actorEmail ?? "",
                    ipAddress,
                    "generic-login"
                ].joined(separator: "|")
                let identifier = stableUUID(from: stableInput)
                events.append(
                    LoginEvent(
                        id: identifier,
                        provider: .google,
                        providerAccountID: actorID,
                        providerAccountEmail: actorEmail,
                        occurredAt: occurredAt,
                        device: "Google account activity",
                        ipAddress: ipAddress,
                        location: "Unknown region",
                        reason: "Google login activity event.",
                        suspicious: false,
                        expected: true
                    )
                )
                continue
            }

            for (index, event) in sourceEvents {
                let suspicious = isSuspicious(event: event)
                let location = parameterValue(
                    names: ["location", "country", "region", "city", "geo_location"],
                    in: event
                ) ?? "Unknown region"
                let device = parameterValue(
                    names: ["device", "device_type", "platform", "os", "browser_type", "login_type"],
                    in: event
                ) ?? "Google account activity"

                let reason: String
                if suspicious {
                    reason = "Google flagged sign-in event \(event.name) as suspicious."
                } else {
                    reason = "Google sign-in event: \(event.name)."
                }

                let stableInput = [
                    activity.id?.uniqueQualifier ?? "",
                    activity.id?.time ?? "",
                    event.name,
                    String(index),
                    actorEmail ?? "",
                    ipAddress
                ].joined(separator: "|")
                let identifier = stableUUID(from: stableInput)

                events.append(
                    LoginEvent(
                        id: identifier,
                        provider: .google,
                        providerAccountID: actorID,
                        providerAccountEmail: actorEmail,
                        occurredAt: occurredAt,
                        device: device,
                        ipAddress: ipAddress,
                        location: location,
                        reason: reason,
                        suspicious: suspicious,
                        expected: !suspicious
                    )
                )
            }
        }

        return events
    }

    private func isLoginLike(event: GoogleWorkspaceActivityEvent) -> Bool {
        let name = event.name.lowercased()
        let type = event.type?.lowercased() ?? ""
        if type == "login" {
            return true
        }
        return name.contains("login")
            || name.contains("sign_in")
            || name.contains("signin")
            || name.contains("authentication")
    }

    private func isSuspicious(event: GoogleWorkspaceActivityEvent) -> Bool {
        let name = event.name.lowercased()
        if name.contains("suspicious") || name.contains("risky") || name.contains("anomal") {
            return true
        }
        if parameterBool(
            names: ["is_suspicious", "is_risky", "suspicious", "risky"],
            in: event
        ) == true {
            return true
        }
        let riskLevel = parameterValue(names: ["risk_level", "risk"], in: event)?.lowercased()
        if riskLevel == "high" || riskLevel == "critical" {
            return true
        }
        return false
    }

    private func parameterValue(
        names: [String],
        in event: GoogleWorkspaceActivityEvent
    ) -> String? {
        let expectedNames = Set(names.map { $0.lowercased() })
        for parameter in event.parameters ?? [] where expectedNames.contains(parameter.name.lowercased()) {
            if let value = normalized(parameter.value) {
                return value
            }
            if let value = normalized(parameter.intValue) {
                return value
            }
            if let value = parameter.multiValue?.compactMap(normalized).first {
                return value
            }
        }
        return nil
    }

    private func parameterBool(
        names: [String],
        in event: GoogleWorkspaceActivityEvent
    ) -> Bool? {
        let expectedNames = Set(names.map { $0.lowercased() })
        for parameter in event.parameters ?? [] where expectedNames.contains(parameter.name.lowercased()) {
            if let boolValue = parameter.boolValue {
                return boolValue
            }
            if let raw = normalized(parameter.value) {
                let lowered = raw.lowercased()
                if lowered == "true" || lowered == "1" {
                    return true
                }
                if lowered == "false" || lowered == "0" {
                    return false
                }
            }
        }
        return nil
    }

    private func extractGoogleErrorMessage(from data: Data) -> String? {
        if let envelope = try? decoder.decode(GoogleErrorEnvelope.self, from: data) {
            return envelope.error?.message ?? envelope.error?.status
        }
        return nil
    }

    private func normalized(_ value: String?) -> String? {
        guard let value else {
            return nil
        }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private func stableUUID(from value: String) -> UUID {
        let digest = SHA256.hash(data: Data(value.utf8))
        var bytes = Array(digest.prefix(16))
        bytes[6] = (bytes[6] & 0x0F) | 0x40
        bytes[8] = (bytes[8] & 0x3F) | 0x80

        let uuid = uuid_t(
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        )
        return UUID(uuid: uuid)
    }
}

private struct GoogleWorkspaceActivityPage {
    let activities: [GoogleWorkspaceActivity]
    let nextPageToken: String?
}

private struct GoogleWorkspaceActivityPagePayload: Decodable {
    let items: [GoogleWorkspaceActivity]?
    let nextPageToken: String?
}

private struct GoogleWorkspaceActivity: Decodable, Sendable {
    let id: GoogleWorkspaceActivityID?
    let actor: GoogleWorkspaceActivityActor?
    let ipAddress: String?
    let events: [GoogleWorkspaceActivityEvent]?
}

private struct GoogleWorkspaceActivityID: Decodable, Sendable {
    let time: String?
    let uniqueQualifier: String?
}

private struct GoogleWorkspaceActivityActor: Decodable, Sendable {
    let email: String?
    let profileID: String?
    let key: String?

    enum CodingKeys: String, CodingKey {
        case email
        case profileID = "profileId"
        case key
    }
}

private struct GoogleWorkspaceActivityEvent: Decodable, Sendable {
    let type: String?
    let name: String
    let parameters: [GoogleWorkspaceActivityEventParameter]?
}

private struct GoogleWorkspaceActivityEventParameter: Decodable, Sendable {
    let name: String
    let value: String?
    let boolValue: Bool?
    let intValue: String?
    let multiValue: [String]?

    enum CodingKeys: String, CodingKey {
        case name
        case value
        case boolValue
        case intValue
        case multiValue
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        value = try container.decodeIfPresent(String.self, forKey: .value)
        intValue = try container.decodeIfPresent(String.self, forKey: .intValue)
        multiValue = try container.decodeIfPresent([String].self, forKey: .multiValue)

        if let directBool = try container.decodeIfPresent(Bool.self, forKey: .boolValue) {
            boolValue = directBool
        } else if let boolString = try container.decodeIfPresent(String.self, forKey: .boolValue) {
            let normalized = boolString.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if normalized == "true" || normalized == "1" {
                boolValue = true
            } else if normalized == "false" || normalized == "0" {
                boolValue = false
            } else {
                boolValue = nil
            }
        } else {
            boolValue = nil
        }
    }
}

private struct GoogleErrorEnvelope: Decodable {
    let error: GoogleErrorPayload?
}

private struct GoogleErrorPayload: Decodable {
    let message: String?
    let status: String?
}

private enum GoogleWorkspaceDateFormatter {
    static func string(from date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter.string(from: date)
    }

    static func date(from value: String?) -> Date? {
        guard let value else {
            return nil
        }

        let formatterWithFractions = ISO8601DateFormatter()
        formatterWithFractions.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        formatterWithFractions.timeZone = TimeZone(secondsFromGMT: 0)
        if let date = formatterWithFractions.date(from: value) {
            return date
        }

        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter.date(from: value)
    }
}
