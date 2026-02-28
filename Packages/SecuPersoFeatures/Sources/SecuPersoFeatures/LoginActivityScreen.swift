import SwiftUI
import SecuPersoDomain
import SecuPersoUI

struct ActivityScreen: View {
    @ObservedObject var viewModel: SecurityConsoleViewModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: DesignTokens.spacingL) {
                connectedProvidersSection
                filterSection
                feedSection
            }
            .padding(DesignTokens.spacingL)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(DesignTokens.appBackground)
        .animation(.easeInOut(duration: 0.18), value: viewModel.filteredActivityFeed.map(\.id))
    }

    private var connectedProvidersSection: some View {
        SectionContainer(title: "Connected providers", subtitle: "Manage provider connections and review provider-level status.") {
            if viewModel.accountCards.isEmpty {
                Text("No providers configured yet.")
                    .foregroundStyle(DesignTokens.mutedForeground)
            } else {
                VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                    ForEach(viewModel.accountCards) { account in
                        providerCard(account)
                    }
                }
            }
        }
    }

    private func providerCard(_ account: AccountCardSummary) -> some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
            HStack(spacing: DesignTokens.spacingS) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(account.providerName)
                        .font(.headline)
                    Text(account.details)
                        .font(.caption)
                        .foregroundStyle(DesignTokens.mutedForeground)
                }

                Spacer(minLength: 0)

                StatusPill(connectionLabel(for: account.connectionState), tone: connectionTone(for: account.connectionState))
                if account.needsAttention {
                    StatusPill("Needs attention", tone: .caution)
                }
            }

            if let latestLoginSummary = account.latestLoginSummary, let latestLoginAt = account.latestLoginAt {
                Text("Last sign-in: \(latestLoginSummary) (\(latestLoginAt, style: .relative))")
                    .font(.subheadline)
            } else {
                Text("No recent sign-ins for this provider.")
                    .font(.subheadline)
                    .foregroundStyle(DesignTokens.mutedForeground)
            }

            Text("Suspicious sign-ins: \(account.suspiciousLoginCount)")
                .font(.caption)
                .foregroundStyle(DesignTokens.mutedForeground)

            if account.connectionState == .connected {
                Button("Disconnect") {
                    viewModel.disconnect(provider: account.providerID)
                }
                .buttonStyle(.bordered)
            } else {
                Button("Connect") {
                    viewModel.beginConnectFlow(for: account.providerID)
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(DesignTokens.spacingM)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius)
                .fill(DesignTokens.secondaryCardBackground)
        )
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

    private var filterSection: some View {
        SectionContainer(title: "Activity") {
            Picker("Scope", selection: $viewModel.activityFilter) {
                ForEach(ActivityFeedFilter.allCases) { filter in
                    Text(filter.title).tag(filter)
                }
            }
            .pickerStyle(.segmented)
        }
    }

    private var feedSection: some View {
        SectionContainer(title: "Recent events", subtitle: "Review suspicious sign-ins and open incidents.") {
            if viewModel.filteredActivityFeed.isEmpty {
                Text("No events in this view.")
                    .foregroundStyle(DesignTokens.mutedForeground)
            } else {
                VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                    ForEach(viewModel.filteredActivityFeed) { item in
                        feedRow(item)
                    }
                }
            }
        }
    }

    private func feedRow(_ item: ActivityFeedItem) -> some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingXS) {
            HStack(alignment: .top, spacing: DesignTokens.spacingS) {
                Image(systemName: symbol(for: item.kind))
                    .foregroundStyle(color(for: item.severity))
                    .frame(width: 18)
                    .padding(.top, 1)

                VStack(alignment: .leading, spacing: 2) {
                    Text(item.title)
                        .font(.subheadline.weight(.semibold))
                    Text(item.detail)
                        .font(.caption)
                        .foregroundStyle(DesignTokens.mutedForeground)
                }

                Spacer(minLength: 0)

                VStack(alignment: .trailing, spacing: 4) {
                    Text(item.date, style: .time)
                        .font(.caption)
                        .foregroundStyle(DesignTokens.mutedForeground)
                    if item.needsAttention {
                        StatusPill("Needs attention", tone: .caution)
                    }
                }
            }

            if !item.actions.isEmpty {
                HStack(spacing: DesignTokens.spacingS) {
                    ForEach(item.actions) { action in
                        Button(action.title) {
                            requestConfirmation(for: action)
                        }
                        .buttonStyle(.bordered)
                    }
                }
                .padding(.leading, 28)
            }
        }
        .padding(DesignTokens.spacingS)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius)
                .fill(DesignTokens.secondaryCardBackground)
        )
    }

    private func requestConfirmation(for action: ActivityFeedAction) {
        switch action.kind {
        case let .markLoginAsExpected(loginID):
            guard let login = viewModel.loginEvents.first(where: { $0.id == loginID }) else {
                return
            }
            viewModel.requestMarkAsMe(login)
        case let .createIncident(loginID):
            guard let login = viewModel.loginEvents.first(where: { $0.id == loginID }) else {
                return
            }
            viewModel.requestCreateIncident(login)
        case let .resolveIncident(incidentID):
            guard let incident = viewModel.incidents.first(where: { $0.id == incidentID }) else {
                return
            }
            viewModel.requestResolveIncident(incident)
        }
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
            return .secondary
        case .caution:
            return .orange
        case .warning:
            return .red
        }
    }
}
