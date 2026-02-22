import Foundation

public enum AppSection: String, CaseIterable, Identifiable {
    case overview
    case emailExposure
    case loginActivity
    case settings

    public var id: String { rawValue }

    var title: String {
        switch self {
        case .overview:
            return "Overview"
        case .emailExposure:
            return "Email Exposure"
        case .loginActivity:
            return "Login Activity"
        case .settings:
            return "Settings"
        }
    }

    var symbol: String {
        switch self {
        case .overview:
            return "shield.lefthalf.filled"
        case .emailExposure:
            return "envelope.badge"
        case .loginActivity:
            return "person.badge.shield.checkmark"
        case .settings:
            return "gearshape"
        }
    }
}

public enum ExposureFilter: String, CaseIterable, Identifiable {
    case all
    case open
    case resolved
    case highSeverity

    public var id: String { rawValue }

    var title: String {
        switch self {
        case .all:
            return "All"
        case .open:
            return "Open"
        case .resolved:
            return "Resolved"
        case .highSeverity:
            return "High"
        }
    }
}

public struct TimelineEvent: Identifiable, Hashable {
    public enum Kind: String {
        case exposure
        case login
        case incident
    }

    public var id: String { "\(kind.rawValue)-\(title)-\(date.timeIntervalSince1970)" }
    public let kind: Kind
    public let title: String
    public let details: String
    public let date: Date
}

public struct SecurityConsoleError: Identifiable, Equatable, Sendable {
    public enum Context: String, Sendable {
        case refreshAll
        case setScenario
        case beginConnectFlow
        case disconnectProvider
        case markLoginAsExpected
        case saveExposureSourceConfiguration
        case createIncident
        case resolveIncident
        case loadStaticData
        case reloadConnections
        case unknown
    }

    public let id: UUID
    public let context: Context
    public let message: String
    public let underlyingType: String

    public init(
        id: UUID = UUID(),
        context: Context,
        message: String,
        underlyingType: String = "Custom"
    ) {
        self.id = id
        self.context = context
        self.message = message
        self.underlyingType = underlyingType
    }

    init(context: Context, error: any Error) {
        self.init(
            context: context,
            message: error.localizedDescription,
            underlyingType: String(reflecting: type(of: error))
        )
    }
}
