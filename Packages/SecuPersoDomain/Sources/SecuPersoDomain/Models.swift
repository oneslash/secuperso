import Foundation

public enum ProviderID: String, Codable, CaseIterable, Sendable, Identifiable {
    case google
    case outlook
    case other

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .google:
            return "Google"
        case .outlook:
            return "Outlook"
        case .other:
            return "Other"
        }
    }
}

public enum RiskLevel: String, Codable, CaseIterable, Sendable {
    case low
    case medium
    case high
}

public enum ConnectionState: String, Codable, Sendable {
    case disconnected
    case connecting
    case connected
    case error
}

public enum ExposureSeverity: String, Codable, CaseIterable, Sendable {
    case low
    case medium
    case high
    case critical
}

public enum ExposureStatus: String, Codable, CaseIterable, Sendable {
    case open
    case resolved
}

public struct ExposureRecord: Identifiable, Codable, Hashable, Sendable {
    public var id: UUID
    public var email: String
    public var source: String
    public var foundAt: Date
    public var severity: ExposureSeverity
    public var status: ExposureStatus
    public var remediation: String

    public init(
        id: UUID,
        email: String,
        source: String,
        foundAt: Date,
        severity: ExposureSeverity,
        status: ExposureStatus,
        remediation: String
    ) {
        self.id = id
        self.email = email
        self.source = source
        self.foundAt = foundAt
        self.severity = severity
        self.status = status
        self.remediation = remediation
    }
}

public struct LoginEvent: Identifiable, Codable, Hashable, Sendable {
    public var id: UUID
    public var provider: ProviderID
    public var occurredAt: Date
    public var device: String
    public var ipAddress: String
    public var location: String
    public var reason: String
    public var suspicious: Bool
    public var expected: Bool

    public init(
        id: UUID,
        provider: ProviderID,
        occurredAt: Date,
        device: String,
        ipAddress: String,
        location: String,
        reason: String,
        suspicious: Bool,
        expected: Bool
    ) {
        self.id = id
        self.provider = provider
        self.occurredAt = occurredAt
        self.device = device
        self.ipAddress = ipAddress
        self.location = location
        self.reason = reason
        self.suspicious = suspicious
        self.expected = expected
    }
}

public enum IncidentStatus: String, Codable, CaseIterable, Sendable {
    case open
    case resolved
}

public struct IncidentCase: Identifiable, Codable, Hashable, Sendable {
    public var id: UUID
    public var title: String
    public var severity: RiskLevel
    public var createdAt: Date
    public var status: IncidentStatus
    public var linkedLoginEventID: UUID
    public var notes: String
    public var resolvedAt: Date?

    public init(
        id: UUID,
        title: String,
        severity: RiskLevel,
        createdAt: Date,
        status: IncidentStatus,
        linkedLoginEventID: UUID,
        notes: String,
        resolvedAt: Date?
    ) {
        self.id = id
        self.title = title
        self.severity = severity
        self.createdAt = createdAt
        self.status = status
        self.linkedLoginEventID = linkedLoginEventID
        self.notes = notes
        self.resolvedAt = resolvedAt
    }
}

public struct RiskSnapshot: Codable, Hashable, Sendable {
    public var score: Int
    public var level: RiskLevel
    public var lastUpdatedAt: Date

    public init(score: Int, level: RiskLevel, lastUpdatedAt: Date) {
        self.score = score
        self.level = level
        self.lastUpdatedAt = lastUpdatedAt
    }
}

public struct ProviderConnection: Identifiable, Codable, Hashable, Sendable {
    public var id: ProviderID
    public var state: ConnectionState
    public var lastUpdatedAt: Date

    public init(id: ProviderID, state: ConnectionState, lastUpdatedAt: Date) {
        self.id = id
        self.state = state
        self.lastUpdatedAt = lastUpdatedAt
    }
}

public struct ProviderDescriptor: Identifiable, Codable, Hashable, Sendable {
    public var id: ProviderID
    public var displayName: String
    public var details: String

    public init(id: ProviderID, displayName: String, details: String) {
        self.id = id
        self.displayName = displayName
        self.details = details
    }
}

public struct ExposureSourceConfiguration: Codable, Hashable, Sendable {
    public var apiKey: String
    public var email: String
    public var userAgent: String

    public init(
        apiKey: String = "",
        email: String = "",
        userAgent: String = "SecuPersoApp/1.0"
    ) {
        self.apiKey = apiKey
        self.email = email
        self.userAgent = userAgent
    }

    public var isComplete: Bool {
        !apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !email.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !userAgent.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}

public enum FixtureScenario: String, Codable, CaseIterable, Sendable {
    case clean
    case moderate
    case critical

    public var title: String {
        rawValue.capitalized
    }
}
