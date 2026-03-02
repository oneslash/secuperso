import Foundation
import SecuPersoDomain

@MainActor
public final class ExposureViewModel: ObservableObject {
    @Published public private(set) var monitoredEmails: [MonitoredEmailAddress] = []
    public var exposureSourceAPIKey: String = ""
    public var exposureSourceUserAgent: String = "SecuPersoApp/1.0"
    @Published public private(set) var isWorking = false
    @Published public var inlineStatusMessage: String?

    private let monitoredEmailService: any MonitoredEmailService
    private let exposureConfigurationService: any ExposureSourceConfigurationService
    private let refreshAction: @Sendable () async -> Void
    private var started = false

    public var exposureSourceConfigured: Bool {
        !exposureSourceAPIKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    public init(
        monitoredEmailService: any MonitoredEmailService,
        exposureConfigurationService: any ExposureSourceConfigurationService,
        refreshAction: @escaping @Sendable () async -> Void
    ) {
        self.monitoredEmailService = monitoredEmailService
        self.exposureConfigurationService = exposureConfigurationService
        self.refreshAction = refreshAction
    }

    public func start() {
        guard !started else {
            return
        }
        started = true

        Task {
            await loadInitialState()
        }
    }

    public func loadInitialState() async {
        isWorking = true
        defer { isWorking = false }

        do {
            let configuration = try await exposureConfigurationService.loadConfiguration()
            exposureSourceAPIKey = configuration.apiKey
            exposureSourceUserAgent = configuration.userAgent
            monitoredEmails = try await monitoredEmailService.listMonitoredEmails()
        } catch {
            inlineStatusMessage = error.localizedDescription
        }
    }

    public func saveExposureSourceConfiguration() {
        Task {
            isWorking = true
            defer { isWorking = false }

            do {
                inlineStatusMessage = nil
                let configuration = ExposureSourceConfiguration(
                    apiKey: exposureSourceAPIKey,
                    userAgent: exposureSourceUserAgent
                )
                try await exposureConfigurationService.saveConfiguration(configuration)
                await refreshAction()
            } catch {
                inlineStatusMessage = error.localizedDescription
            }
        }
    }

    public func addMonitoredEmail(email: String, providerHint: ProviderID) {
        Task {
            isWorking = true
            defer { isWorking = false }

            do {
                inlineStatusMessage = nil
                _ = try await monitoredEmailService.addMonitoredEmail(email, providerHint: providerHint)
                monitoredEmails = try await monitoredEmailService.listMonitoredEmails()
                await refreshAction()
            } catch {
                inlineStatusMessage = error.localizedDescription
            }
        }
    }

    public func setMonitoredEmailEnabled(id: UUID, isEnabled: Bool) {
        Task {
            do {
                inlineStatusMessage = nil
                try await monitoredEmailService.setMonitoredEmailEnabled(id: id, isEnabled: isEnabled)
                monitoredEmails = try await monitoredEmailService.listMonitoredEmails()
                if isEnabled {
                    await refreshAction()
                }
            } catch {
                inlineStatusMessage = error.localizedDescription
            }
        }
    }

    public func removeMonitoredEmail(id: UUID) {
        Task {
            do {
                inlineStatusMessage = nil
                try await monitoredEmailService.removeMonitoredEmail(id: id)
                monitoredEmails = try await monitoredEmailService.listMonitoredEmails()
            } catch {
                inlineStatusMessage = error.localizedDescription
            }
        }
    }

    public func clearInlineStatusMessage() {
        inlineStatusMessage = nil
    }
}
