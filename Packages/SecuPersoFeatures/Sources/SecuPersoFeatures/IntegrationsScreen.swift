import SwiftUI
import SecuPersoDomain
import SecuPersoUI

struct IntegrationsScreen: View {
    @ObservedObject var viewModel: IntegrationsViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingL) {
            coverageStrip

            HSplitView {
                providerListPane
                    .frame(minWidth: 340, idealWidth: 380)

                providerInspectorPane
                    .frame(minWidth: 380, idealWidth: 460, maxWidth: .infinity)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .padding(DesignTokens.spacingL)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(DesignTokens.appBackground)
    }

    // MARK: Coverage — inline stats, no cards

    private var coverageStrip: some View {
        HStack(spacing: DesignTokens.spacingXL) {
            coverageStat(
                value: "\(connectedCount)/\(totalCount)",
                label: "connected",
                detail: connectedCount == totalCount ? "Full coverage" : "Needs completion"
            )
            coverageStat(
                value: "\(attentionCount)",
                label: "need attention",
                detail: attentionCount == 0 ? "All clear" : "Review provider health"
            )
            coverageStat(
                value: "\(disconnectedCount)",
                label: "disconnected",
                detail: disconnectedCount == 0 ? "No gaps" : "Connect remaining"
            )
            Spacer(minLength: 0)
        }
        .padding(.vertical, DesignTokens.spacingXS)
    }

    private func coverageStat(value: String, label: String, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline, spacing: DesignTokens.spacingXS) {
                Text(value)
                    .font(.title3.weight(.semibold).monospacedDigit())
                    .foregroundStyle(DesignTokens.textPrimary)
                Text(label)
                    .font(DesignTokens.caption)
                    .foregroundStyle(DesignTokens.textSecondary)
            }
            Text(detail)
                .font(DesignTokens.caption)
                .foregroundStyle(DesignTokens.textSecondary)
        }
    }

    // MARK: Provider list — no SectionContainer wrapper

    private var providerListPane: some View {
        let filteredAccountCards = viewModel.filteredAccountCards

        return VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
            Text("Providers")
                .font(DesignTokens.sectionTitle)
                .foregroundStyle(DesignTokens.textPrimary)

            TextField("Search providers", text: $viewModel.providerSearchText)
                .textFieldStyle(.roundedBorder)

            if filteredAccountCards.isEmpty {
                IntegrationsEmptyState(
                    title: "No providers match",
                    detail: "Clear the search to see all providers."
                )
            } else {
                List(selection: providerSelection) {
                    ForEach(filteredAccountCards) { account in
                        ProviderSummaryRowView(account: account)
                            .tag(account.providerID)
                    }
                }
                .listStyle(.inset)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    // MARK: Provider inspector — no SectionContainer wrapper

    private var providerInspectorPane: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
            if let inspector = viewModel.selectedProviderInspector {
                ProviderInspectorView(
                    inspector: inspector,
                    isBusy: viewModel.providerActionInFlightID == inspector.id,
                    connect: { viewModel.beginConnectFlow(for: inspector.id) },
                    disconnect: { viewModel.disconnect(provider: inspector.id) }
                )
            } else {
                IntegrationsEmptyState(
                    title: "Select a provider",
                    detail: "Choose a provider to review its details."
                )
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .padding(.leading, DesignTokens.spacingM)
    }

    private var providerSelection: Binding<ProviderID?> {
        Binding(
            get: { viewModel.selectedProviderID },
            set: { viewModel.selectProvider(id: $0) }
        )
    }

    private var connectedCount: Int {
        viewModel.accountCards.filter { $0.connectionState == .connected }.count
    }

    private var disconnectedCount: Int {
        viewModel.accountCards.filter { $0.connectionState == .disconnected || $0.connectionState == .error }.count
    }

    private var attentionCount: Int {
        viewModel.accountCards.filter(\.needsAttention).count
    }

    private var totalCount: Int {
        max(viewModel.accountCards.count, 1)
    }
}

private struct ProviderSummaryRowView: View {
    let account: AccountCardSummary

    var body: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingXS) {
            HStack(spacing: DesignTokens.spacingS) {
                Text(account.providerName)
                    .font(DesignTokens.bodyStrong)
                    .foregroundStyle(DesignTokens.textPrimary)

                Spacer(minLength: 0)

                StatusPill(statusText, tone: statusTone)
            }

            Text(account.details)
                .font(DesignTokens.caption)
                .foregroundStyle(DesignTokens.textSecondary)

            Text("Suspicious sign-ins: \(account.suspiciousLoginCount)")
                .font(DesignTokens.caption)
                .foregroundStyle(DesignTokens.textSecondary)
        }
        .padding(.vertical, DesignTokens.spacingXS)
    }

    private var statusText: String {
        switch account.connectionState {
        case .connected where account.suspiciousLoginCount == 0:
            return "Connected"
        case .connected:
            return "Review"
        case .connecting:
            return "Connecting"
        case .error:
            return "Error"
        case .disconnected:
            return "Disconnected"
        }
    }

    private var statusTone: StatusPillTone {
        switch account.connectionState {
        case .connected where account.suspiciousLoginCount == 0:
            return .positive
        case .connected:
            return .caution
        case .connecting:
            return .caution
        case .error:
            return .critical
        case .disconnected:
            return .neutral
        }
    }
}

private struct ProviderInspectorView: View {
    let inspector: ProviderInspectorProjection
    let isBusy: Bool
    let connect: () -> Void
    let disconnect: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingM) {
            HStack(alignment: .top, spacing: DesignTokens.spacingS) {
                StatusPill(inspector.statusText, tone: statusTone)

                Spacer(minLength: 0)

                if isBusy {
                    ProgressView()
                        .controlSize(.small)
                }
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(inspector.providerName)
                    .font(DesignTokens.headlineLarge)
                    .foregroundStyle(DesignTokens.textPrimary)

                Text(inspector.providerDetails)
                    .font(DesignTokens.body)
                    .foregroundStyle(DesignTokens.textSecondary)
            }

            IntegrationsDetailBlock(title: "Coverage", value: inspector.coverageSummary)

            if let attentionReason = inspector.attentionReason {
                IntegrationsDetailBlock(title: "Needs attention", value: attentionReason)
            }

            if let latestLoginSummary = inspector.latestLoginSummary, let latestLoginAt = inspector.latestLoginAt {
                IntegrationsDetailBlock(
                    title: "Last sign-in",
                    value: "\(latestLoginSummary) · \(latestLoginAt.formatted(date: .abbreviated, time: .shortened))"
                )
            } else {
                IntegrationsDetailBlock(
                    title: "Last sign-in",
                    value: "No recent sign-ins are available for this provider yet."
                )
            }

            IntegrationsDetailBlock(
                title: "Suspicious sign-ins",
                value: "\(inspector.suspiciousLoginCount) sign-in(s) currently need review."
            )

            if inspector.connectionState == .connected {
                Button("Disconnect provider") {
                    disconnect()
                }
                .buttonStyle(.bordered)
                .controlSize(.regular)
                .disabled(isBusy)
            } else {
                Button {
                    connect()
                } label: {
                    if isBusy {
                        HStack(spacing: DesignTokens.spacingXS) {
                            ProgressView()
                                .controlSize(.small)
                            Text("Connecting")
                        }
                    } else {
                        Text("Connect provider")
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.regular)
                .tint(DesignTokens.brandTeal)
                .disabled(isBusy)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private var statusTone: StatusPillTone {
        switch inspector.connectionState {
        case .connected where inspector.suspiciousLoginCount == 0:
            return .positive
        case .connected:
            return .caution
        case .connecting:
            return .caution
        case .error:
            return .critical
        case .disconnected:
            return .neutral
        }
    }
}

private struct IntegrationsEmptyState: View {
    let title: String
    let detail: String

    var body: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
            Text(title)
                .font(DesignTokens.bodyStrong)
                .foregroundStyle(DesignTokens.textPrimary)

            Text(detail)
                .font(DesignTokens.caption)
                .foregroundStyle(DesignTokens.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .padding(.top, DesignTokens.spacingS)
    }
}

private struct IntegrationsDetailBlock: View {
    let title: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(DesignTokens.caption.weight(.semibold))
                .foregroundStyle(DesignTokens.textSecondary)

            Text(value)
                .font(DesignTokens.body)
                .foregroundStyle(DesignTokens.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
