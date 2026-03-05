import SwiftUI
import SecuPersoDomain
import SecuPersoUI

struct ActivityScreen: View {
    @ObservedObject var viewModel: SecurityConsoleViewModel

    var body: some View {
        HSplitView {
            SectionContainer(
                title: "Activity timeline",
                subtitle: "Search and filter events to focus on suspicious activity first.",
                style: .elevated
            ) {
                VStack(alignment: .leading, spacing: DesignTokens.spacingM) {
                    HStack(spacing: DesignTokens.spacingS) {
                        Picker("Scope", selection: Binding(
                            get: { viewModel.activityFilter },
                            set: { viewModel.activityFilter = $0 }
                        )) {
                            ForEach(ActivityFeedFilter.allCases) { filter in
                                Text(filter.title).tag(filter)
                            }
                        }
                        .pickerStyle(.segmented)

                        TextField("Search events", text: Binding(
                            get: { viewModel.activitySearchText },
                            set: { viewModel.activitySearchText = $0 }
                        ))
                        .textFieldStyle(.roundedBorder)
                        .frame(minWidth: 180)
                    }

                    if viewModel.isRefreshing {
                        ProgressView("Refreshing events...")
                            .controlSize(.small)
                    }

                    if viewModel.filteredActivityFeed.isEmpty {
                        EmptyWorkspaceState(
                            title: "No events match this view",
                            detail: "Try widening the scope or clear the search to review more activity."
                        )
                    } else {
                        List(selection: activitySelection) {
                            ForEach(viewModel.filteredActivityFeed) { item in
                                ActivityFeedRowView(item: item)
                                    .tag(item.id)
                            }
                        }
                        .listStyle(.inset)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
            .frame(minWidth: 360, idealWidth: 400)

            SectionContainer(
                title: "Event details",
                subtitle: "Investigate the selected event and take action without leaving the workspace.",
                style: .flat
            ) {
                if let inspector = viewModel.selectedActivityInspector {
                    ActivityInspectorView(
                        inspector: inspector,
                        requestConfirmation: requestConfirmation(for:)
                    )
                } else {
                    EmptyWorkspaceState(
                        title: "Select an event",
                        detail: "Choose an event from the timeline to review context and actions."
                    )
                }
            }
            .frame(minWidth: 380, idealWidth: 460, maxWidth: .infinity)
        }
        .padding(DesignTokens.spacingL)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(DesignTokens.appBackground)
    }

    private var activitySelection: Binding<String?> {
        Binding(
            get: { viewModel.selectedActivityItemID },
            set: { viewModel.selectActivityItem(id: $0) }
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
}

private struct ActivityInspectorView: View {
    let inspector: ActivityInspectorProjection
    let requestConfirmation: (ActivityFeedAction) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingM) {
            HStack(alignment: .top, spacing: DesignTokens.spacingS) {
                StatusPill(inspector.statusText, tone: tone)

                Spacer(minLength: 0)

                VStack(alignment: .trailing, spacing: 2) {
                    Text(inspector.occurredAt, style: .relative)
                        .font(DesignTokens.caption.weight(.semibold))
                        .foregroundStyle(DesignTokens.textPrimary)

                    Text(inspector.occurredAt.formatted(date: .abbreviated, time: .shortened))
                        .font(DesignTokens.caption)
                        .foregroundStyle(DesignTokens.textSecondary)
                }
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(inspector.title)
                    .font(DesignTokens.headlineLarge)
                    .foregroundStyle(DesignTokens.textPrimary)

                Text(inspector.categoryLabel)
                    .font(DesignTokens.caption.weight(.semibold))
                    .foregroundStyle(DesignTokens.textSecondary)
            }

            DetailBlock(title: "Summary", value: inspector.detail)

            if let linkedContext = inspector.linkedContext {
                DetailBlock(title: "Linked context", value: linkedContext)
            }

            if inspector.actions.isEmpty {
                DetailBlock(
                    title: "Actions",
                    value: "No direct remediation is available for this event. Use the related workspace if further review is needed."
                )
            } else {
                VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                    Text("Actions")
                        .font(DesignTokens.bodyStrong)
                        .foregroundStyle(DesignTokens.textPrimary)

                    HStack(spacing: DesignTokens.spacingS) {
                        ForEach(inspector.actions) { action in
                            if action.kind.isDestructive {
                                Button(action.title) {
                                    requestConfirmation(action)
                                }
                                .buttonStyle(.borderedProminent)
                                .controlSize(.regular)
                            } else {
                                Button(action.title) {
                                    requestConfirmation(action)
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.regular)
                            }
                        }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private var tone: StatusPillTone {
        switch inspector.severity {
        case .warning:
            return .critical
        case .caution:
            return .caution
        case .neutral:
            return inspector.statusText == "Normal" ? .positive : .neutral
        }
    }
}

private struct EmptyWorkspaceState: View {
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

private struct DetailBlock: View {
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

private extension PendingConfirmationAction.Kind {
    var isDestructive: Bool {
        switch self {
        case .resolveIncident:
            return true
        case .markLoginAsExpected, .createIncident:
            return false
        }
    }
}
