import SwiftUI
import SecuPersoDomain
import SecuPersoUI

struct ActivityFeedRowView: View {
    let item: ActivityFeedItem
    var showsActions: Bool = false
    var onActionTap: ((ActivityFeedAction) -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
            HStack(alignment: .top, spacing: DesignTokens.spacingM) {
                Image(systemName: symbol(for: item.kind))
                    .foregroundStyle(color(for: item.severity))
                    .imageScale(.medium)
                    .frame(width: 26, height: 26)
                    .background(
                        Circle()
                            .fill(iconBackground(for: item.severity))
                    )
                    .padding(.top, 2)

                VStack(alignment: .leading, spacing: 2) {
                    Text(item.title)
                        .font(DesignTokens.bodyStrong)
                        .foregroundStyle(DesignTokens.textPrimary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                    Text(item.detail)
                        .font(.subheadline)
                        .foregroundStyle(DesignTokens.textSecondary)
                        .lineLimit(2)
                        .truncationMode(.tail)
                }

                Spacer(minLength: 0)

                VStack(alignment: .trailing, spacing: 4) {
                    Text(item.date, style: .relative)
                        .font(DesignTokens.caption)
                        .foregroundStyle(DesignTokens.textSecondary)
                    if item.needsAttention {
                        StatusPill(attentionLabel, tone: attentionTone)
                    }
                }
            }

            if showsActions, !item.actions.isEmpty {
                HStack(spacing: DesignTokens.spacingS) {
                    ForEach(item.actions) { action in
                        Button(action.title) {
                            onActionTap?(action)
                        }
                        .buttonStyle(.bordered)
                    }
                }
                .padding(.leading, 28)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, DesignTokens.spacingS)
    }

    private func symbol(for kind: ActivityFeedItem.Kind) -> String {
        switch kind {
        case .exposure:
            return "envelope.badge"
        case .login:
            return "person.badge.shield.checkmark"
        case .incident:
            return "exclamationmark.triangle"
        }
    }

    private func color(for severity: ActivityFeedItem.Severity) -> Color {
        switch severity {
        case .neutral:
            return DesignTokens.textSecondary
        case .caution:
            return DesignTokens.riskAmber
        case .warning:
            return DesignTokens.riskRed
        }
    }

    private func iconBackground(for severity: ActivityFeedItem.Severity) -> Color {
        switch severity {
        case .neutral:
            return DesignTokens.surfaceSecondary
        case .caution:
            return DesignTokens.riskAmber.opacity(0.16)
        case .warning:
            return DesignTokens.riskRed.opacity(0.14)
        }
    }

    private var attentionLabel: String {
        switch item.severity {
        case .warning:
            return "At risk"
        case .caution:
            return "Needs attention"
        case .neutral:
            return "Needs attention"
        }
    }

    private var attentionTone: StatusPillTone {
        switch item.severity {
        case .warning:
            return .critical
        case .caution:
            return .caution
        case .neutral:
            return .neutral
        }
    }
}

struct ProviderCardView: View {
    let account: AccountCardSummary
    let connect: () -> Void
    let disconnect: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
            HStack(spacing: DesignTokens.spacingS) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(account.providerName)
                        .font(DesignTokens.headlineMedium)
                        .foregroundStyle(DesignTokens.textPrimary)
                    Text(account.details)
                        .font(DesignTokens.caption)
                        .foregroundStyle(DesignTokens.textSecondary)
                }

                Spacer(minLength: 0)
                StatusPill(statusText, tone: statusTone)
            }

            Text("Connection: \(connectionLabel(for: account.connectionState)) · Suspicious sign-ins: \(account.suspiciousLoginCount)")
                .font(DesignTokens.caption)
                .foregroundStyle(DesignTokens.textSecondary)

            if let latestLoginSummary = account.latestLoginSummary, let latestLoginAt = account.latestLoginAt {
                Text("Last sign-in: \(latestLoginSummary) (\(latestLoginAt, style: .relative))")
                    .font(.subheadline)
                    .foregroundStyle(DesignTokens.textPrimary)
            } else {
                Text("No recent sign-ins for this provider.")
                    .font(.subheadline)
                    .foregroundStyle(DesignTokens.textSecondary)
            }

            if account.connectionState == .connected {
                Button("Disconnect") {
                    disconnect()
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            } else {
                Button("Connect") {
                    connect()
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
            }
        }
        .padding(DesignTokens.spacingS)
        .background(
            RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius, style: .continuous)
                .fill(DesignTokens.surfaceSecondary)
        )
        .overlay(
            RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius, style: .continuous)
                .stroke(DesignTokens.borderSubtle, lineWidth: DesignTokens.borderWidth)
        )
    }

    private var statusText: String {
        account.needsAttention ? "Needs attention" : connectionLabel(for: account.connectionState)
    }

    private var statusTone: StatusPillTone {
        account.needsAttention ? .caution : connectionTone(for: account.connectionState)
    }

    private func connectionLabel(for state: ConnectionState) -> String {
        switch state {
        case .connected:
            return "Connected"
        case .connecting:
            return "Connecting"
        case .error:
            return "Error"
        case .disconnected:
            return "Disconnected"
        }
    }

    private func connectionTone(for state: ConnectionState) -> StatusPillTone {
        switch state {
        case .connected:
            return .positive
        case .connecting:
            return .caution
        case .error:
            return .critical
        case .disconnected:
            return .neutral
        }
    }
}
