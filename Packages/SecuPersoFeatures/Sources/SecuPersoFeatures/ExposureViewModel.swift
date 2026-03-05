import Foundation
import SecuPersoDomain

@MainActor
public final class ExposureViewModel: ObservableObject {
    @Published public private(set) var monitoredEmails: [MonitoredEmailAddress] = []
    public var exposureSourceAPIKey: String = ""
    public var exposureSourceUserAgent: String = "SecuPersoApp/1.0"
    @Published public private(set) var isWorking = false
    @Published public private(set) var isSavingConfiguration = false
    @Published public private(set) var isUpdatingMonitoredEmails = false
    @Published public private(set) var configurationFeedback: OperationFeedback?
    @Published public private(set) var monitoredEmailsFeedback: OperationFeedback?
    @Published public private(set) var monitoredEmailComposerFocusToken = UUID()

    private let monitoredEmailService: any MonitoredEmailService
    private let exposureConfigurationService: any ExposureSourceConfigurationService
    private let refreshAction: @Sendable () async -> Void
    private var started = false

    public var exposureSourceConfigured: Bool {
        !exposureSourceAPIKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    public var inlineStatusMessage: String? {
        monitoredEmailsFeedback?.message ?? configurationFeedback?.message
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
            monitoredEmailsFeedback = OperationFeedback(tone: .error, message: error.localizedDescription)
        }
    }

    public func saveExposureSourceConfiguration() {
        Task {
            beginConfigurationWork()
            defer { endConfigurationWork() }

            do {
                configurationFeedback = nil
                let configuration = ExposureSourceConfiguration(
                    apiKey: exposureSourceAPIKey,
                    userAgent: exposureSourceUserAgent
                )
                try await exposureConfigurationService.saveConfiguration(configuration)
                await refreshAction()
                configurationFeedback = OperationFeedback(
                    tone: .success,
                    message: "Exposure source settings saved."
                )
            } catch {
                configurationFeedback = OperationFeedback(tone: .error, message: error.localizedDescription)
            }
        }
    }

    public func addMonitoredEmail(email: String) {
        Task {
            beginMonitoredEmailWork()
            defer { endMonitoredEmailWork() }

            do {
                monitoredEmailsFeedback = nil
                _ = try await monitoredEmailService.addMonitoredEmail(email, providerHint: .other)
                monitoredEmails = try await monitoredEmailService.listMonitoredEmails()
                await refreshAction()
                monitoredEmailsFeedback = OperationFeedback(
                    tone: .success,
                    message: "Added \(email) to monitored emails."
                )
            } catch {
                monitoredEmailsFeedback = OperationFeedback(tone: .error, message: error.localizedDescription)
            }
        }
    }

    public func setMonitoredEmailEnabled(id: UUID, isEnabled: Bool) {
        Task {
            beginMonitoredEmailWork()
            defer { endMonitoredEmailWork() }

            do {
                monitoredEmailsFeedback = nil
                try await monitoredEmailService.setMonitoredEmailEnabled(id: id, isEnabled: isEnabled)
                monitoredEmails = try await monitoredEmailService.listMonitoredEmails()
                if isEnabled {
                    await refreshAction()
                }
                monitoredEmailsFeedback = OperationFeedback(
                    tone: .info,
                    message: isEnabled ? "Monitoring resumed for this email." : "Monitoring paused for this email."
                )
            } catch {
                monitoredEmailsFeedback = OperationFeedback(tone: .error, message: error.localizedDescription)
            }
        }
    }

    public func removeMonitoredEmail(id: UUID) {
        Task {
            beginMonitoredEmailWork()
            defer { endMonitoredEmailWork() }

            do {
                monitoredEmailsFeedback = nil
                try await monitoredEmailService.removeMonitoredEmail(id: id)
                monitoredEmails = try await monitoredEmailService.listMonitoredEmails()
                monitoredEmailsFeedback = OperationFeedback(
                    tone: .info,
                    message: "Removed email from monitoring."
                )
            } catch {
                monitoredEmailsFeedback = OperationFeedback(tone: .error, message: error.localizedDescription)
            }
        }
    }

    public func clearInlineStatusMessage() {
        configurationFeedback = nil
        monitoredEmailsFeedback = nil
    }

    public func clearConfigurationFeedback() {
        configurationFeedback = nil
    }

    public func clearMonitoredEmailsFeedback() {
        monitoredEmailsFeedback = nil
    }

    public func requestMonitoredEmailComposerFocus() {
        monitoredEmailComposerFocusToken = UUID()
    }

    private func beginConfigurationWork() {
        isSavingConfiguration = true
        isWorking = true
    }

    private func endConfigurationWork() {
        isSavingConfiguration = false
        isWorking = isUpdatingMonitoredEmails
    }

    private func beginMonitoredEmailWork() {
        isUpdatingMonitoredEmails = true
        isWorking = true
    }

    private func endMonitoredEmailWork() {
        isUpdatingMonitoredEmails = false
        isWorking = isSavingConfiguration
    }
}
