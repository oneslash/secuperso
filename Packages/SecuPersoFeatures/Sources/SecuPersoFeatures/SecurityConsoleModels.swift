import Foundation
import SecuPersoDomain

public enum AppSection: String, CaseIterable, Identifiable, Sendable {
    case overview
    case activity
    case exposure
    case integrations

    public static let primaryCases: [AppSection] = [.overview, .activity, .exposure, .integrations]
    public static let utilityCases: [AppSection] = []

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .overview:
            return "Overview"
        case .activity:
            return "Activity"
        case .exposure:
            return "Exposure"
        case .integrations:
            return "Integrations"
        }
    }

    public var symbol: String {
        switch self {
        case .overview:
            return "shield.lefthalf.filled"
        case .activity:
            return "clock.arrow.trianglehead.counterclockwise.rotate.90"
        case .exposure:
            return "envelope.badge.shield.half.filled"
        case .integrations:
            return "link.badge.plus"
        }
    }
}

public enum ActivityFeedFilter: String, CaseIterable, Identifiable, Sendable {
    case needsAttention
    case all

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .needsAttention:
            return "Needs attention"
        case .all:
            return "All activity"
        }
    }
}

public enum ExposureFindingFilter: String, CaseIterable, Identifiable, Sendable {
    case atRisk
    case allOpen

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .atRisk:
            return "At risk"
        case .allOpen:
            return "All open"
        }
    }
}

public struct SectionBadgeCounts: Equatable, Sendable {
    public let activity: Int
    public let exposure: Int
    public let integrations: Int

    public init(activity: Int, exposure: Int, integrations: Int) {
        self.activity = activity
        self.exposure = exposure
        self.integrations = integrations
    }

    public func value(for section: AppSection) -> Int? {
        switch section {
        case .overview:
            return nil
        case .activity:
            return activity
        case .exposure:
            return exposure
        case .integrations:
            return integrations
        }
    }
}

public struct OverviewSummary: Equatable, Sendable {
    public let riskScore: Int
    public let riskLevel: RiskLevel
    public let stateLabel: String
    public let headline: String
    public let detail: String
    public let lastUpdatedAt: Date

    public init(
        riskScore: Int,
        riskLevel: RiskLevel,
        stateLabel: String,
        headline: String,
        detail: String,
        lastUpdatedAt: Date
    ) {
        self.riskScore = riskScore
        self.riskLevel = riskLevel
        self.stateLabel = stateLabel
        self.headline = headline
        self.detail = detail
        self.lastUpdatedAt = lastUpdatedAt
    }
}

public struct OverviewRiskDriver: Identifiable, Equatable, Sendable {
    public enum Emphasis: String, Sendable {
        case calm
        case caution
        case critical
    }

    public let id: String
    public let title: String
    public let detail: String
    public let emphasis: Emphasis

    public init(id: String, title: String, detail: String, emphasis: Emphasis) {
        self.id = id
        self.title = title
        self.detail = detail
        self.emphasis = emphasis
    }
}

public struct NextAction: Equatable, Sendable {
    public enum Kind: Equatable, Sendable {
        case reviewHighRiskExposure(exposureID: UUID)
        case reviewSuspiciousLogin(loginID: UUID)
        case reviewIncident(incidentID: UUID)
        case connectProvider(providerID: ProviderID)
        case runSecurityCheck
    }

    public let kind: Kind
    public let title: String
    public let detail: String
    public let buttonTitle: String
    public let destinationSection: AppSection

    public init(kind: Kind, title: String, detail: String, buttonTitle: String, destinationSection: AppSection) {
        self.kind = kind
        self.title = title
        self.detail = detail
        self.buttonTitle = buttonTitle
        self.destinationSection = destinationSection
    }
}

public struct AccountCardSummary: Identifiable, Equatable, Sendable {
    public var id: ProviderID { providerID }
    public let providerID: ProviderID
    public let providerName: String
    public let details: String
    public let connectionState: ConnectionState
    public let suspiciousLoginCount: Int
    public let latestLoginAt: Date?
    public let latestLoginSummary: String?
    public let needsAttention: Bool

    public init(
        providerID: ProviderID,
        providerName: String,
        details: String,
        connectionState: ConnectionState,
        suspiciousLoginCount: Int,
        latestLoginAt: Date?,
        latestLoginSummary: String?,
        needsAttention: Bool
    ) {
        self.providerID = providerID
        self.providerName = providerName
        self.details = details
        self.connectionState = connectionState
        self.suspiciousLoginCount = suspiciousLoginCount
        self.latestLoginAt = latestLoginAt
        self.latestLoginSummary = latestLoginSummary
        self.needsAttention = needsAttention
    }
}

public struct ExposureSummary: Equatable, Sendable {
    public let openCount: Int
    public let highRiskOpenCount: Int
    public let affectedEmailCount: Int
    public let mostRecentAt: Date?
    public let headline: String
    public let detail: String

    public init(
        openCount: Int,
        highRiskOpenCount: Int,
        affectedEmailCount: Int,
        mostRecentAt: Date?,
        headline: String,
        detail: String
    ) {
        self.openCount = openCount
        self.highRiskOpenCount = highRiskOpenCount
        self.affectedEmailCount = affectedEmailCount
        self.mostRecentAt = mostRecentAt
        self.headline = headline
        self.detail = detail
    }
}

public struct ExposureFindingsGroup: Identifiable, Equatable, Sendable {
    public var id: String { email }
    public let email: String
    public let findings: [ExposureRecord]

    public init(email: String, findings: [ExposureRecord]) {
        self.email = email
        self.findings = findings
    }
}

public struct OverviewSignalsProjection: Equatable, Sendable {
    public let suspiciousSignInCount: Int
    public let openIncidentCount: Int
    public let connectedProviderCount: Int
    public let totalProviderCount: Int

    public init(
        suspiciousSignInCount: Int,
        openIncidentCount: Int,
        connectedProviderCount: Int,
        totalProviderCount: Int
    ) {
        self.suspiciousSignInCount = suspiciousSignInCount
        self.openIncidentCount = openIncidentCount
        self.connectedProviderCount = connectedProviderCount
        self.totalProviderCount = totalProviderCount
    }
}

public struct ExposureFindingsProjectionRow: Identifiable, Equatable, Sendable {
    public let id: UUID
    public let email: String
    public let source: String
    public let foundAt: Date
    public let severity: ExposureSeverity
    public let remediation: String

    public init(
        id: UUID,
        email: String,
        source: String,
        foundAt: Date,
        severity: ExposureSeverity,
        remediation: String
    ) {
        self.id = id
        self.email = email
        self.source = source
        self.foundAt = foundAt
        self.severity = severity
        self.remediation = remediation
    }
}

public struct ActivityInspectorProjection: Identifiable, Equatable, Sendable {
    public let id: String
    public let title: String
    public let categoryLabel: String
    public let statusText: String
    public let severity: ActivityFeedItem.Severity
    public let detail: String
    public let occurredAt: Date
    public let linkedContext: String?
    public let actions: [ActivityFeedAction]

    public init(
        id: String,
        title: String,
        categoryLabel: String,
        statusText: String,
        severity: ActivityFeedItem.Severity,
        detail: String,
        occurredAt: Date,
        linkedContext: String?,
        actions: [ActivityFeedAction]
    ) {
        self.id = id
        self.title = title
        self.categoryLabel = categoryLabel
        self.statusText = statusText
        self.severity = severity
        self.detail = detail
        self.occurredAt = occurredAt
        self.linkedContext = linkedContext
        self.actions = actions
    }
}

public struct ExposureInspectorProjection: Identifiable, Equatable, Sendable {
    public let id: UUID
    public let email: String
    public let source: String
    public let severity: ExposureSeverity
    public let foundAt: Date
    public let remediation: String
    public let monitoringSummary: String
    public let relatedOpenFindingCount: Int

    public init(
        id: UUID,
        email: String,
        source: String,
        severity: ExposureSeverity,
        foundAt: Date,
        remediation: String,
        monitoringSummary: String,
        relatedOpenFindingCount: Int
    ) {
        self.id = id
        self.email = email
        self.source = source
        self.severity = severity
        self.foundAt = foundAt
        self.remediation = remediation
        self.monitoringSummary = monitoringSummary
        self.relatedOpenFindingCount = relatedOpenFindingCount
    }
}

public struct ProviderInspectorProjection: Identifiable, Equatable, Sendable {
    public let id: ProviderID
    public let providerName: String
    public let providerDetails: String
    public let connectionState: ConnectionState
    public let statusText: String
    public let attentionReason: String?
    public let suspiciousLoginCount: Int
    public let latestLoginSummary: String?
    public let latestLoginAt: Date?
    public let coverageSummary: String

    public init(
        id: ProviderID,
        providerName: String,
        providerDetails: String,
        connectionState: ConnectionState,
        statusText: String,
        attentionReason: String?,
        suspiciousLoginCount: Int,
        latestLoginSummary: String?,
        latestLoginAt: Date?,
        coverageSummary: String
    ) {
        self.id = id
        self.providerName = providerName
        self.providerDetails = providerDetails
        self.connectionState = connectionState
        self.statusText = statusText
        self.attentionReason = attentionReason
        self.suspiciousLoginCount = suspiciousLoginCount
        self.latestLoginSummary = latestLoginSummary
        self.latestLoginAt = latestLoginAt
        self.coverageSummary = coverageSummary
    }
}

public struct ActivityFeedItem: Identifiable, Equatable, Sendable {
    public enum Kind: String, Sendable {
        case exposure
        case login
        case incident
    }

    public enum Severity: String, Sendable {
        case neutral
        case caution
        case warning
    }

    public let id: String
    public let kind: Kind
    public let date: Date
    public let title: String
    public let detail: String
    public let severity: Severity
    public let needsAttention: Bool
    public let actions: [ActivityFeedAction]

    public init(
        id: String,
        kind: Kind,
        date: Date,
        title: String,
        detail: String,
        severity: Severity,
        needsAttention: Bool,
        actions: [ActivityFeedAction]
    ) {
        self.id = id
        self.kind = kind
        self.date = date
        self.title = title
        self.detail = detail
        self.severity = severity
        self.needsAttention = needsAttention
        self.actions = actions
    }
}

public struct ActivityPreviewProjection: Identifiable, Equatable, Sendable {
    public var id: String { item.id }
    public let item: ActivityFeedItem

    public init(item: ActivityFeedItem) {
        self.item = item
    }
}

public struct ActivityFeedAction: Identifiable, Equatable, Hashable, Sendable {
    public let id: String
    public let title: String
    public let kind: PendingConfirmationAction.Kind

    public init(id: String, title: String, kind: PendingConfirmationAction.Kind) {
        self.id = id
        self.title = title
        self.kind = kind
    }
}

public struct PendingConfirmationAction: Identifiable, Equatable, Sendable {
    public enum Kind: Equatable, Hashable, Sendable {
        case markLoginAsExpected(loginID: UUID)
        case createIncident(loginID: UUID)
        case resolveIncident(incidentID: UUID)
    }

    public let id: String
    public let title: String
    public let message: String
    public let confirmTitle: String
    public let isDestructive: Bool
    public let kind: Kind

    public init(
        title: String,
        message: String,
        confirmTitle: String,
        isDestructive: Bool,
        kind: Kind
    ) {
        self.id = kind.identifier
        self.title = title
        self.message = message
        self.confirmTitle = confirmTitle
        self.isDestructive = isDestructive
        self.kind = kind
    }
}

private extension PendingConfirmationAction.Kind {
    var identifier: String {
        switch self {
        case let .markLoginAsExpected(loginID):
            return "mark-login-\(loginID.uuidString)"
        case let .createIncident(loginID):
            return "create-incident-\(loginID.uuidString)"
        case let .resolveIncident(incidentID):
            return "resolve-incident-\(incidentID.uuidString)"
        }
    }
}

public struct TimelineEvent: Identifiable, Hashable {
    public enum Kind: String {
        case exposure
        case login
        case incident
    }

    public let id: String
    public let kind: Kind
    public let title: String
    public let details: String
    public let date: Date

    public init(id: String, kind: Kind, title: String, details: String, date: Date) {
        self.id = id
        self.kind = kind
        self.title = title
        self.details = details
        self.date = date
    }
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

    public var title: String {
        switch context {
        case .refreshAll:
            return "Unable to refresh security data"
        case .setScenario:
            return "Unable to switch the demo scenario"
        case .beginConnectFlow:
            return "Unable to start provider connection"
        case .disconnectProvider:
            return "Unable to disconnect provider"
        case .markLoginAsExpected:
            return "Unable to confirm this sign-in"
        case .saveExposureSourceConfiguration:
            return "Unable to save exposure source settings"
        case .createIncident:
            return "Unable to create incident"
        case .resolveIncident:
            return "Unable to resolve incident"
        case .loadStaticData:
            return "Unable to load secure workspace"
        case .reloadConnections:
            return "Unable to reload provider connections"
        case .unknown:
            return "Unexpected error"
        }
    }

    public var recoverySuggestion: String {
        switch context {
        case .refreshAll:
            return "Check your provider connections and try refreshing again."
        case .setScenario:
            return "Keep the current mock scenario selected, then try switching again."
        case .beginConnectFlow:
            return "Retry the provider connection. If it keeps failing, verify the provider settings."
        case .disconnectProvider:
            return "Retry the disconnect action. The provider may still be connected."
        case .markLoginAsExpected:
            return "Leave the sign-in flagged for review until it can be confirmed."
        case .saveExposureSourceConfiguration:
            return "Verify the API key and User-Agent, then save again."
        case .createIncident:
            return "Retry incident creation after reviewing the suspicious sign-in details."
        case .resolveIncident:
            return "Keep the incident open until the action succeeds."
        case .loadStaticData:
            return "Retry loading the app. If the issue persists, check local data and configuration."
        case .reloadConnections:
            return "Retry after a refresh to confirm the latest provider status."
        case .unknown:
            return "Retry the action. If the issue persists, inspect the underlying configuration."
        }
    }
}

public struct OperationFeedback: Equatable, Sendable {
    public enum Tone: String, Sendable {
        case info
        case success
        case warning
        case error
    }

    public let tone: Tone
    public let message: String

    public init(tone: Tone, message: String) {
        self.tone = tone
        self.message = message
    }
}
