import Foundation
import UserNotifications
import SecuPersoDomain

actor LocalNotificationManager {
    private var requestedAuthorization = false

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
        if requestedAuthorization {
            return true
        }

        do {
            let granted = try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
            requestedAuthorization = true
            return granted
        } catch {
            return false
        }
    }
}
