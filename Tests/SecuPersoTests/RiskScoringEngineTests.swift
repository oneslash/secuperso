import XCTest
import SecuPersoDomain

final class RiskScoringEngineTests: XCTestCase {
    private let engine = RiskScoringEngine()

    func testLowRiskScenarioProducesLowLevel() {
        let snapshot = engine.score(exposures: [], logins: [], incidents: [], now: Self.fixedNow)

        XCTAssertEqual(snapshot.score, 0)
        XCTAssertEqual(snapshot.level, .low)
    }

    func testMediumRiskBoundary() {
        let exposures = [
            ExposureRecord(
                id: UUID(),
                email: "owner@example.com",
                source: "Mock",
                foundAt: Self.fixedNow,
                severity: .high,
                status: .open,
                remediation: "Rotate password"
            )
        ]
        let logins = [
            LoginEvent(
                id: UUID(),
                provider: .google,
                occurredAt: Self.fixedNow,
                device: "Unknown",
                ipAddress: "198.51.100.10",
                location: "Unknown",
                reason: "Risky",
                suspicious: true,
                expected: false
            )
        ]

        let snapshot = engine.score(exposures: exposures, logins: logins, incidents: [], now: Self.fixedNow)

        XCTAssertEqual(snapshot.score, 35)
        XCTAssertEqual(snapshot.level, .medium)
    }

    func testHighRiskClampAtHundred() {
        let exposures = [
            ExposureRecord(id: UUID(), email: "a@example.com", source: "A", foundAt: Self.fixedNow, severity: .critical, status: .open, remediation: "X"),
            ExposureRecord(id: UUID(), email: "b@example.com", source: "B", foundAt: Self.fixedNow, severity: .critical, status: .open, remediation: "Y"),
            ExposureRecord(id: UUID(), email: "c@example.com", source: "C", foundAt: Self.fixedNow, severity: .high, status: .open, remediation: "Z")
        ]

        let logins = [
            LoginEvent(id: UUID(), provider: .google, occurredAt: Self.fixedNow, device: "Unknown", ipAddress: "1.1.1.1", location: "X", reason: "Risk", suspicious: true, expected: false),
            LoginEvent(id: UUID(), provider: .outlook, occurredAt: Self.fixedNow.addingTimeInterval(-1200), device: "Unknown", ipAddress: "2.2.2.2", location: "Y", reason: "Risk", suspicious: true, expected: false),
            LoginEvent(id: UUID(), provider: .google, occurredAt: Self.fixedNow.addingTimeInterval(-1800), device: "Unknown", ipAddress: "3.3.3.3", location: "Z", reason: "Risk", suspicious: true, expected: false)
        ]

        let incidents = [
            IncidentCase(id: UUID(), title: "A", severity: .high, createdAt: Self.fixedNow, status: .open, linkedLoginEventID: UUID(), notes: "", resolvedAt: nil),
            IncidentCase(id: UUID(), title: "B", severity: .high, createdAt: Self.fixedNow, status: .open, linkedLoginEventID: UUID(), notes: "", resolvedAt: nil)
        ]

        let snapshot = engine.score(exposures: exposures, logins: logins, incidents: incidents, now: Self.fixedNow)

        XCTAssertEqual(snapshot.score, 100)
        XCTAssertEqual(snapshot.level, .high)
    }

    private static let fixedNow = ISO8601DateFormatter().date(from: "2026-02-22T12:00:00Z")!
}
