import XCTest
import SecuPersoData
import SecuPersoDomain

final class FixtureDataLoaderTests: XCTestCase {
    func testLoadsModerateScenarioDeterministically() throws {
        let urls = try makeFixtureURLs()
        let loader = FixtureDataLoader(
            exposuresURL: urls.exposures,
            loginEventsURL: urls.logins,
            providersURL: urls.providers
        )

        let moderateExposures = try loader.loadExposures(for: .moderate)
        let moderateLogins = try loader.loadLoginEvents(for: .moderate)
        let providers = try loader.loadProviders()

        XCTAssertEqual(moderateExposures.count, 2)
        XCTAssertEqual(moderateLogins.count, 2)
        XCTAssertEqual(providers.count, 2)
        XCTAssertEqual(moderateExposures[0].id.uuidString, "A9E97D4D-9B5A-4596-A2DF-E80FDBAEEA11")
    }

    func testCorruptedFixtureThrowsDecodeError() throws {
        let urls = try makeFixtureURLs(corruptExposures: true)
        let loader = FixtureDataLoader(
            exposuresURL: urls.exposures,
            loginEventsURL: urls.logins,
            providersURL: urls.providers
        )

        XCTAssertThrowsError(try loader.loadExposures(for: .moderate)) { error in
            guard case SecuPersoDataError.fixtureDecodeFailure = error else {
                XCTFail("Expected fixtureDecodeFailure, got \(error)")
                return
            }
        }
    }

    private func makeFixtureURLs(corruptExposures: Bool = false) throws -> (exposures: URL, logins: URL, providers: URL) {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let exposuresURL = directory.appendingPathComponent("exposures.json")
        let loginsURL = directory.appendingPathComponent("login_events.json")
        let providersURL = directory.appendingPathComponent("providers.json")

        if corruptExposures {
            try "{invalid-json".write(to: exposuresURL, atomically: true, encoding: .utf8)
        } else {
            try """
            {
              "clean": [],
              "moderate": [
                {
                  "id": "A9E97D4D-9B5A-4596-A2DF-E80FDBAEEA11",
                  "email": "owner@example.com",
                  "source": "mock",
                  "foundAt": "2026-02-22T10:00:00Z",
                  "severity": "high",
                  "status": "open",
                  "remediation": "Rotate credentials"
                },
                {
                  "id": "A9E97D4D-9B5A-4596-A2DF-E80FDBAEEA12",
                  "email": "backup@example.com",
                  "source": "mock",
                  "foundAt": "2026-02-22T09:00:00Z",
                  "severity": "medium",
                  "status": "open",
                  "remediation": "Enable MFA"
                }
              ],
              "critical": []
            }
            """.write(to: exposuresURL, atomically: true, encoding: .utf8)
        }

        try """
        {
          "clean": [],
          "moderate": [
            {
              "id": "C01A25F9-1F37-4E02-B96D-FBDEAC04C111",
              "provider": "google",
              "occurredAt": "2026-02-22T09:00:00Z",
              "device": "Mac",
              "ipAddress": "203.0.113.10",
              "location": "US",
              "reason": "Expected",
              "suspicious": false,
              "expected": true
            },
            {
              "id": "C01A25F9-1F37-4E02-B96D-FBDEAC04C112",
              "provider": "outlook",
              "occurredAt": "2026-02-22T08:00:00Z",
              "device": "Windows",
              "ipAddress": "198.51.100.10",
              "location": "Unknown",
              "reason": "Risky",
              "suspicious": true,
              "expected": false
            }
          ],
          "critical": []
        }
        """.write(to: loginsURL, atomically: true, encoding: .utf8)

        try """
        [
          { "id": "google", "displayName": "Google", "details": "Mock Google" },
          { "id": "outlook", "displayName": "Outlook", "details": "Mock Outlook" }
        ]
        """.write(to: providersURL, atomically: true, encoding: .utf8)

        return (exposuresURL, loginsURL, providersURL)
    }
}
