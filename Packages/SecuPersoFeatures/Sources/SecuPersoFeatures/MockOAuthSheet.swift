import SwiftUI
import SecuPersoDomain
import SecuPersoUI

struct MockOAuthSheet: View {
    let provider: ProviderID
    let state: ConnectionState
    let message: String
    let dismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingM) {
            Text("Connect \(provider.displayName)")
                .font(.title2.weight(.semibold))

            Text("SecuPerso uses this connection to pull recent account activity and keep provider trust visible in the security console.")
                .font(DesignTokens.body)
                .foregroundStyle(DesignTokens.textSecondary)

            VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                Label("Review recent sign-ins", systemImage: "person.badge.shield.checkmark")
                Label("Improve provider coverage", systemImage: "link.badge.plus")
                Label("Keep connection state visible", systemImage: "shield.lefthalf.filled")
            }
            .font(DesignTokens.caption)
            .foregroundStyle(DesignTokens.textPrimary)

            HStack(spacing: DesignTokens.spacingS) {
                if state == .connecting {
                    ProgressView()
                } else if state == .connected {
                    Image(systemName: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                } else if state == .error {
                    Image(systemName: "xmark.seal.fill")
                        .foregroundStyle(.red)
                } else {
                    Image(systemName: "info.circle.fill")
                        .foregroundStyle(DesignTokens.brandTeal)
                }

                Text(message)
                    .font(DesignTokens.body)
                    .foregroundStyle(DesignTokens.textPrimary)
            }
            .padding(DesignTokens.spacingM)
            .background(
                RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius, style: .continuous)
                    .fill(DesignTokens.surfaceSecondary)
            )

            Text(nextStepCopy)
                .font(DesignTokens.caption)
                .foregroundStyle(DesignTokens.textSecondary)

            if state == .connected || state == .error {
                Button("Close") {
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
    }

    private var nextStepCopy: String {
        switch state {
        case .connecting:
            return "Complete the provider consent flow to return here with the updated status."
        case .connected:
            return "The provider is now connected. Return to the Integrations workspace to review coverage and recent sign-ins."
        case .error:
            return "The provider did not connect successfully. Close this sheet and retry from the selected provider."
        case .disconnected:
            return "Start the connection flow to give SecuPerso access to the selected provider."
        }
    }
}
