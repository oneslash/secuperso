import Foundation
import UserNotifications
import SecuPersoDomain

actor LocalNotificationManager {
    private enum AuthorizationState {
        case unknown
        case granted
        case denied
    }

    private var authorizationState: AuthorizationState = .unknown

    func notifyHighRisk(snapshot: RiskSnapshot) async {
        guard await requestAuthorizationIfNeeded() else {
            return
        }

        let content = UNMutableNotificationContent()
        content.title = "SecuPerso: High Risk Detected"
        content.body = "Current risk score is \(snapshot.score). Open SecuPerso to review incidents."
        content.sound = .default

        let request = UNNotificationRequest(
            identifier: "high-risk-\(Int(snapshot.lastUpdatedAt.timeIntervalSince1970))",
            content: content,
            trigger: nil
        )

        try? await UNUserNotificationCenter.current().add(request)
    }

    private func requestAuthorizationIfNeeded() async -> Bool {
        switch authorizationState {
        case .granted:
            return true
        case .denied:
            return false
        case .unknown:
            break
        }

        do {
            let center = UNUserNotificationCenter.current()
            let settings = await center.notificationSettings()
            switch settings.authorizationStatus {
            case .authorized, .provisional, .ephemeral:
                authorizationState = .granted
                return true
            case .denied:
                authorizationState = .denied
                return false
            case .notDetermined:
                let granted = try await center.requestAuthorization(options: [.alert, .sound])
                authorizationState = granted ? .granted : .denied
                return granted
            @unknown default:
                authorizationState = .denied
                return false
            }
        } catch {
            authorizationState = .denied
            return false
        }
    }
}
