import Foundation
import SecuPersoDomain

private struct ScenarioFixture<T: Decodable>: Decodable {
    let clean: [T]
    let moderate: [T]
    let critical: [T]

    func values(for scenario: FixtureScenario) -> [T] {
        switch scenario {
        case .clean:
            return clean
        case .moderate:
            return moderate
        case .critical:
            return critical
        }
    }
}

public final class FixtureDataLoader: @unchecked Sendable {
    private let exposuresURL: URL
    private let loginEventsURL: URL
    private let providersURL: URL

    private let decoder: JSONDecoder

    public init(exposuresURL: URL, loginEventsURL: URL, providersURL: URL) {
        self.exposuresURL = exposuresURL
        self.loginEventsURL = loginEventsURL
        self.providersURL = providersURL

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        self.decoder = decoder
    }

    public func loadExposures(for scenario: FixtureScenario) throws -> [ExposureRecord] {
        let fixture: ScenarioFixture<ExposureRecord> = try decodeScenarioFixture(at: exposuresURL)
        return fixture.values(for: scenario)
    }

    public func loadLoginEvents(for scenario: FixtureScenario) throws -> [LoginEvent] {
        let fixture: ScenarioFixture<LoginEvent> = try decodeScenarioFixture(at: loginEventsURL)
        return fixture.values(for: scenario)
    }

    public func loadProviders() throws -> [ProviderDescriptor] {
        try decodeRaw(at: providersURL, as: [ProviderDescriptor].self)
    }

    private func decodeScenarioFixture<T: Decodable>(at url: URL) throws -> ScenarioFixture<T> {
        try decodeRaw(at: url, as: ScenarioFixture<T>.self)
    }

    private func decodeRaw<T: Decodable>(at url: URL, as type: T.Type) throws -> T {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw SecuPersoDataError.fixtureFileMissing(url.lastPathComponent)
        }

        do {
            let data = try Data(contentsOf: url)
            return try decoder.decode(T.self, from: data)
        } catch {
            throw SecuPersoDataError.fixtureDecodeFailure(url.lastPathComponent)
        }
    }
}
