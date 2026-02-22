import Foundation

public struct RiskScoringEngine: Sendable {
    public init() {}

    public func score(
        exposures: [ExposureRecord],
        logins: [LoginEvent],
        incidents: [IncidentCase],
        now: Date = Date()
    ) -> RiskSnapshot {
        let exposureScore = exposures
            .filter { $0.status == .open }
            .reduce(0) { partialResult, record in
                partialResult + weight(for: record.severity)
            }

        let suspiciousLogins = logins.filter { $0.suspicious || !$0.expected }
        let loginScore = suspiciousLogins.count * 15

        let burstThreshold = now.addingTimeInterval(-(24 * 60 * 60))
        let burstScore = suspiciousLogins.filter { $0.occurredAt >= burstThreshold }.count >= 2 ? 10 : 0

        let unresolvedIncidents = incidents.filter { $0.status == .open }
        let incidentPenalty = unresolvedIncidents.count * 10

        let total = min(100, max(0, exposureScore + loginScore + burstScore + incidentPenalty))
        let level: RiskLevel
        switch total {
        case 70...100:
            level = .high
        case 30...69:
            level = .medium
        default:
            level = .low
        }

        return RiskSnapshot(score: total, level: level, lastUpdatedAt: now)
    }

    private func weight(for severity: ExposureSeverity) -> Int {
        switch severity {
        case .critical:
            return 30
        case .high:
            return 20
        case .medium:
            return 10
        case .low:
            return 5
        }
    }
}
