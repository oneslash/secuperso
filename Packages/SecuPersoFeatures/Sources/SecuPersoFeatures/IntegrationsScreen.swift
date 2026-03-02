import SwiftUI
import SecuPersoUI

struct IntegrationsScreen: View {
    @ObservedObject var viewModel: SecurityConsoleViewModel

    private let metricColumns = Array(
        repeating: GridItem(.flexible(minimum: 120), spacing: DesignTokens.spacingS),
        count: 3
    )

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: DesignTokens.spacingL) {
                providerCoverageSection
                providerManagementSection
            }
            .padding(DesignTokens.spacingL)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(DesignTokens.appBackground)
    }

    private var providerCoverageSection: some View {
        SectionContainer(
            title: "Coverage",
            subtitle: "Connect providers to improve detection accuracy.",
            style: .flat
        ) {
            LazyVGrid(columns: metricColumns, spacing: DesignTokens.spacingS) {
                MetricCardView(
                    title: "Connected",
                    value: "\(connectedCount)/\(totalCount)",
                    subtitle: connectedCount == totalCount ? "Full coverage" : "Needs completion"
                )
                MetricCardView(
                    title: "Needs attention",
                    value: "\(attentionCount)",
                    subtitle: attentionCount == 0 ? "All clear" : "Review provider health"
                )
                MetricCardView(
                    title: "Disconnected",
                    value: "\(disconnectedCount)",
                    subtitle: disconnectedCount == 0 ? "No gaps" : "Connect remaining providers"
                )
            }
        }
    }

    private var providerManagementSection: some View {
        SectionContainer(
            title: "Manage providers",
            subtitle: "Link or disconnect account providers from one place.",
            style: .elevated
        ) {
            if viewModel.accountCards.isEmpty {
                Text("No providers configured yet.")
                    .foregroundStyle(DesignTokens.mutedForeground)
            } else {
                VStack(alignment: .leading, spacing: DesignTokens.spacingM) {
                    if viewModel.oauthState == .connecting {
                        ProgressView("Connecting provider...")
                            .controlSize(.small)
                    }

                    ForEach(viewModel.accountCards) { account in
                        ProviderCardView(
                            account: account,
                            connect: { viewModel.beginConnectFlow(for: account.providerID) },
                            disconnect: { viewModel.disconnect(provider: account.providerID) }
                        )

                        if account.id != viewModel.accountCards.last?.id {
                            Rectangle()
                                .fill(DesignTokens.borderSubtle)
                                .frame(height: 1)
                        }
                    }
                }
            }
        }
    }

    private var connectedCount: Int {
        viewModel.accountCards.filter { $0.connectionState == .connected }.count
    }

    private var disconnectedCount: Int {
        viewModel.accountCards.filter { $0.connectionState == .disconnected }.count
    }

    private var attentionCount: Int {
        viewModel.accountCards.filter(\.needsAttention).count
    }

    private var totalCount: Int {
        max(viewModel.accountCards.count, 1)
    }
}
