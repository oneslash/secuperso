import XCTest
import SecuPersoDomain
import SecuPersoFeatures

@MainActor
final class ExposureViewModelTests: XCTestCase {
    func testAddMonitoredEmailReloadsListAndRefreshes() async {
        let monitoredService = StubMonitoredEmailService()
        let configService = StubExposureConfigurationService()
        let refreshCounter = RefreshCounter()

        let viewModel = ExposureViewModel(
            monitoredEmailService: monitoredService,
            exposureConfigurationService: configService,
            refreshAction: {
                await refreshCounter.increment()
            }
        )

        viewModel.addMonitoredEmail(email: "owner@example.com")
        try? await Task.sleep(for: .milliseconds(50))

        XCTAssertEqual(viewModel.monitoredEmails.count, 1)
        XCTAssertEqual(viewModel.monitoredEmails.first?.email, "owner@example.com")
        XCTAssertEqual(viewModel.monitoredEmails.first?.providerHint, .other)
        let refreshCount = await refreshCounter.value
        XCTAssertEqual(refreshCount, 1)
    }

    func testSaveConfigurationStoresApiKeyAndRefreshes() async {
        let monitoredService = StubMonitoredEmailService()
        let configService = StubExposureConfigurationService()
        let refreshCounter = RefreshCounter()

        let viewModel = ExposureViewModel(
            monitoredEmailService: monitoredService,
            exposureConfigurationService: configService,
            refreshAction: {
                await refreshCounter.increment()
            }
        )

        viewModel.exposureSourceAPIKey = "abc"
        viewModel.exposureSourceUserAgent = "SecuPersoTests/1.0"
        viewModel.saveExposureSourceConfiguration()
        try? await Task.sleep(for: .milliseconds(50))

        let saved = await configService.savedConfiguration
        XCTAssertEqual(saved?.apiKey, "abc")
        XCTAssertEqual(saved?.userAgent, "SecuPersoTests/1.0")
        let refreshCount = await refreshCounter.value
        XCTAssertEqual(refreshCount, 1)
    }
}

private actor RefreshCounter {
    private(set) var value = 0

    func increment() {
        value += 1
    }
}

private actor MonitoredEmailState {
    var values: [MonitoredEmailAddress] = []

    func append(_ value: MonitoredEmailAddress) {
        values.append(value)
    }

    func setEnabled(id: UUID, isEnabled: Bool) {
        guard let index = values.firstIndex(where: { $0.id == id }) else {
            return
        }
        values[index].isEnabled = isEnabled
    }

    func remove(id: UUID) {
        values.removeAll(where: { $0.id == id })
    }
}

private final class StubMonitoredEmailService: MonitoredEmailService, @unchecked Sendable {
    private let state = MonitoredEmailState()

    func listMonitoredEmails() async throws -> [MonitoredEmailAddress] {
        await state.values
    }

    func addMonitoredEmail(_ email: String, providerHint: ProviderID) async throws -> MonitoredEmailAddress {
        let value = MonitoredEmailAddress(
            id: UUID(),
            email: email,
            providerHint: providerHint,
            isEnabled: true,
            createdAt: Date(),
            lastCheckedAt: nil
        )
        await state.append(value)
        return value
    }

    func setMonitoredEmailEnabled(id: UUID, isEnabled: Bool) async throws {
        await state.setEnabled(id: id, isEnabled: isEnabled)
    }

    func removeMonitoredEmail(id: UUID) async throws {
        await state.remove(id: id)
    }
}

private final class StubExposureConfigurationService: ExposureSourceConfigurationService, @unchecked Sendable {
    private let state = ConfigurationState()

    var savedConfiguration: ExposureSourceConfiguration? {
        get async {
            await state.savedConfiguration
        }
    }

    func loadConfiguration() async throws -> ExposureSourceConfiguration {
        await state.savedConfiguration ?? ExposureSourceConfiguration()
    }

    func saveConfiguration(_ configuration: ExposureSourceConfiguration) async throws {
        await state.save(configuration)
    }
}

private actor ConfigurationState {
    var savedConfiguration: ExposureSourceConfiguration?

    func save(_ configuration: ExposureSourceConfiguration) {
        savedConfiguration = configuration
    }
}
