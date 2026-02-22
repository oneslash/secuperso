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

            HStack(spacing: DesignTokens.spacingS) {
                if state == .connecting {
                    ProgressView()
                } else if state == .connected {
                    Image(systemName: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                } else if state == .error {
                    Image(systemName: "xmark.seal.fill")
                        .foregroundStyle(.red)
                }

                Text(message)
            }

            if state == .connected || state == .error {
                Button("Close") {
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
    }
}
