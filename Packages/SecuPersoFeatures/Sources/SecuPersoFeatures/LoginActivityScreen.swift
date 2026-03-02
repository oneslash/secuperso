import SwiftUI
import SecuPersoDomain
import SecuPersoUI

struct ActivityScreen: View {
    @ObservedObject var viewModel: SecurityConsoleViewModel

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: DesignTokens.spacingL) {
                filterSection
                feedSection
            }
            .padding(DesignTokens.spacingL)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(DesignTokens.appBackground)
    }

    private var filterSection: some View {
        SectionContainer(
            title: "Activity timeline",
            subtitle: "Filter events to focus on suspicious activity first.",
            style: .inset
        ) {
            Picker("Scope", selection: $viewModel.activityFilter) {
                ForEach(ActivityFeedFilter.allCases) { filter in
                    Text(filter.title).tag(filter)
                }
            }
            .pickerStyle(.segmented)
        }
    }

    private var feedSection: some View {
        SectionContainer(
            title: "Recent events",
            subtitle: "Focus on events marked Needs attention or At risk.",
            style: .elevated
        ) {
            if viewModel.filteredActivityFeed.isEmpty {
                Text("No events in this view.")
                    .foregroundStyle(DesignTokens.mutedForeground)
            } else {
                VStack(alignment: .leading, spacing: DesignTokens.spacingM) {
                    if viewModel.isRefreshing {
                        ProgressView("Refreshing events...")
                            .controlSize(.small)
                    }

                    Table(viewModel.filteredActivityFeed) {
                        TableColumn("Event") { item in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(item.title)
                                    .font(.subheadline.weight(.semibold))
                                Text(item.detail)
                                    .font(.caption)
                                    .foregroundStyle(DesignTokens.mutedForeground)
                                    .lineLimit(2)
                            }
                        }

                        TableColumn("Category") { item in
                            Text(kindLabel(for: item.kind))
                                .font(.caption)
                        }

                        TableColumn("Status") { item in
                            if item.needsAttention {
                                StatusPill(attentionLabel(for: item), tone: attentionTone(for: item))
                            } else {
                                Text("Normal")
                                    .font(.caption)
                                    .foregroundStyle(DesignTokens.mutedForeground)
                            }
                        }

                        TableColumn("When") { item in
                            Text(DisplayDateFormatter.shortDateTime.string(from: item.date))
                                .font(.caption)
                                .foregroundStyle(DesignTokens.mutedForeground)
                        }

                        TableColumn("Actions") { item in
                            HStack(spacing: DesignTokens.spacingXS) {
                                ForEach(item.actions) { action in
                                    Button(action.title) {
                                        requestConfirmation(for: action)
                                    }
                                    .buttonStyle(.bordered)
                                    .controlSize(.small)
                                }
                            }
                        }
                    }
                    .frame(minHeight: 320)
                    .padding(DesignTokens.spacingXS)
                    .background(
                        RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius, style: .continuous)
                            .fill(DesignTokens.surfaceTertiary)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius, style: .continuous)
                            .stroke(DesignTokens.borderSubtle, lineWidth: DesignTokens.borderWidth)
                    )
                }
            }
        }
    }

    private func kindLabel(for kind: ActivityFeedItem.Kind) -> String {
        switch kind {
        case .exposure:
            return "Exposure"
        case .login:
            return "Sign-in"
        case .incident:
            return "Incident"
        }
    }

    private func attentionLabel(for item: ActivityFeedItem) -> String {
        switch item.severity {
        case .warning:
            return "At risk"
        case .caution, .neutral:
            return "Needs attention"
        }
    }

    private func attentionTone(for item: ActivityFeedItem) -> StatusPillTone {
        switch item.severity {
        case .warning:
            return .critical
        case .caution:
            return .caution
        case .neutral:
            return .neutral
        }
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
}
