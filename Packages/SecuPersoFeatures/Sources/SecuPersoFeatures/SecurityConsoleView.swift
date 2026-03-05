import Foundation
import SwiftUI
import SecuPersoUI

public struct SecurityConsoleView: View {
    @ObservedObject private var viewModel: SecurityConsoleViewModel
    private let exposureViewModel: ExposureViewModel
    private let selectedSectionBinding: Binding<AppSection>?
    @State private var localSelectedSection: AppSection = .overview
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    public init(
        viewModel: SecurityConsoleViewModel,
        exposureViewModel: ExposureViewModel,
        selectedSection: Binding<AppSection>? = nil
    ) {
        self.viewModel = viewModel
        self.exposureViewModel = exposureViewModel
        self.selectedSectionBinding = selectedSection
    }

    public var body: some View {
        NavigationSplitView {
            List(selection: selectedSectionProxy) {
                ForEach(AppSection.primaryCases) { section in
                    SidebarDestinationRow(
                        section: section,
                        badgeCount: viewModel.sectionBadgeCounts.value(for: section),
                        isSelected: section == selectedSection
                    )
                        .tag(section)
                }
            }
            .listStyle(.sidebar)
            .navigationTitle("SecuPerso")
        } detail: {
            contentView
                .animation(
                    reduceMotion ? nil : .spring(response: 0.35, dampingFraction: 0.8),
                    value: selectedSection
                )
                .navigationTitle(selectedSection.title)
                .toolbar {
                    ToolbarItem(placement: .primaryAction) {
                        RefreshToolbarControls(
                            lastRefreshAt: viewModel.lastRefreshAt,
                            isRefreshing: viewModel.isRefreshing
                        ) {
                            Task { await viewModel.refreshAll() }
                        }
                    }
                }
        }
        .globalOverlays(viewModel: viewModel)
        .onAppear {
            Task { @MainActor in
                await Task.yield()
                viewModel.start()
                exposureViewModel.start()
            }
        }
    }

    @ViewBuilder
    private var contentView: some View {
        switch selectedSection {
        case .overview:
            OverviewScreen(viewModel: viewModel, exposureViewModel: exposureViewModel) { destination in
                selectedSectionProxy.wrappedValue = destination
            }
        case .activity:
            ActivityScreen(viewModel: viewModel)
        case .exposure:
            ExposureScreen(viewModel: viewModel, exposureViewModel: exposureViewModel)
        case .integrations:
            IntegrationsScreen(viewModel: viewModel)
        }
    }

    private var selectedSectionProxy: Binding<AppSection> {
        selectedSectionBinding ?? $localSelectedSection
    }

    private var selectedSection: AppSection {
        selectedSectionProxy.wrappedValue
    }
}

private struct SidebarDestinationRow: View {
    let section: AppSection
    let badgeCount: Int?
    let isSelected: Bool

    var body: some View {
        HStack(spacing: DesignTokens.spacingS) {
            Label(section.title, systemImage: section.symbol)
                .font(.body.weight(isSelected ? .semibold : .regular))

            Spacer(minLength: 0)

            if let badgeCount, badgeCount > 0 {
                Text("\(badgeCount)")
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(
                        Capsule()
                            .fill(badgeBackgroundColor)
                    )
                    .overlay(
                        Capsule()
                            .stroke(badgeBorderColor, lineWidth: DesignTokens.borderWidth)
                    )
                    .foregroundStyle(badgeForegroundColor)
                    .accessibilityLabel("\(badgeCount) items")
            }
        }
    }

    private var badgeForegroundColor: Color {
        isSelected ? .white : DesignTokens.textPrimary
    }

    private var badgeBackgroundColor: Color {
        isSelected ? .white.opacity(0.18) : DesignTokens.surfaceSecondary
    }

    private var badgeBorderColor: Color {
        isSelected ? .white.opacity(0.42) : DesignTokens.borderStrong
    }
}

private struct RefreshToolbarControls: View {
    let lastRefreshAt: Date?
    let isRefreshing: Bool
    let refreshAction: () -> Void

    var body: some View {
        HStack(spacing: DesignTokens.spacingXS) {
            if let lastRefreshAt {
                LastRefreshIndicator(lastRefreshAt: lastRefreshAt, isRefreshing: isRefreshing)
            }

            Button(action: refreshAction) {
                HStack(spacing: DesignTokens.spacingXXS) {
                    if isRefreshing {
                        ProgressView()
                            .controlSize(.mini)
                    } else {
                        Image(systemName: "arrow.clockwise")
                    }
                    Text(isRefreshing ? "Refreshing" : "Refresh")
                }
                .font(DesignTokens.caption.weight(.semibold))
                .foregroundStyle(DesignTokens.textPrimary)
                .padding(.horizontal, DesignTokens.spacingS)
                .padding(.vertical, DesignTokens.spacingXS)
                .background(
                    LinearGradient(
                        colors: [
                            DesignTokens.brandTeal.opacity(0.2),
                            DesignTokens.brandTeal.opacity(0.1)
                        ],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    in: Capsule()
                )
                .overlay(
                    Capsule()
                        .strokeBorder(DesignTokens.brandTeal.opacity(0.35), lineWidth: 1)
                )
            }
            .buttonStyle(.plain)
            .help("Refresh now")
            .accessibilityLabel("Refresh data")
            .disabled(isRefreshing)
        }
    }
}

private struct LastRefreshIndicator: View {
    let lastRefreshAt: Date
    let isRefreshing: Bool

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            HStack(spacing: DesignTokens.spacingXS) {
                Circle()
                    .fill(isRefreshing ? DesignTokens.brandTeal : DesignTokens.brandTeal.opacity(0.65))
                    .frame(width: 7, height: 7)

                VStack(alignment: .leading, spacing: 1) {
                    Text(isRefreshing ? "Syncing..." : "Synced \(relativeRefreshText(reference: context.date))")
                        .font(DesignTokens.caption.weight(.semibold))
                        .foregroundStyle(DesignTokens.textPrimary)
                        .monospacedDigit()

                    Text(absoluteRefreshText)
                        .font(.caption2)
                        .foregroundStyle(DesignTokens.textSecondary)
                }
            }
            .padding(.horizontal, DesignTokens.spacingS)
            .padding(.vertical, DesignTokens.spacingXS)
            .background(DesignTokens.surfacePrimary, in: Capsule())
            .overlay(
                Capsule()
                    .strokeBorder(DesignTokens.borderSubtle, lineWidth: 1)
            )
            .shadow(color: DesignTokens.cardShadowColor, radius: 4, y: 1)
            .help("Last check \(lastRefreshAt.formatted(date: .abbreviated, time: .shortened))")
        }
    }

    private var absoluteRefreshText: String {
        if Calendar.current.isDateInToday(lastRefreshAt) {
            return "Today at \(lastRefreshAt.formatted(date: .omitted, time: .shortened))"
        }
        return lastRefreshAt.formatted(date: .abbreviated, time: .shortened)
    }

    private func relativeRefreshText(reference: Date) -> String {
        let elapsedSeconds = max(0, Int(reference.timeIntervalSince(lastRefreshAt).rounded(.down)))

        if elapsedSeconds < 5 {
            return "just now"
        }
        if elapsedSeconds < 60 {
            return "\(elapsedSeconds)s ago"
        }

        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter.localizedString(for: lastRefreshAt, relativeTo: reference)
    }
}

private extension View {
    @ViewBuilder
    func globalOverlays(viewModel: SecurityConsoleViewModel) -> some View {
        self
            .confirmationDialog(
                viewModel.pendingConfirmationAction?.title ?? "Confirm action",
                isPresented: Binding(
                    get: { viewModel.pendingConfirmationAction != nil },
                    set: { isPresented in
                        if !isPresented {
                            Task { @MainActor in
                                viewModel.cancelPendingAction()
                            }
                        }
                    }
                ),
                titleVisibility: .visible
            ) {
                if let action = viewModel.pendingConfirmationAction {
                    Button(action.confirmTitle, role: action.isDestructive ? .destructive : nil) {
                        viewModel.confirmPendingAction()
                    }
                }

                Button("Cancel", role: .cancel) {
                    viewModel.cancelPendingAction()
                }
            } message: {
                if let action = viewModel.pendingConfirmationAction {
                    Text(action.message)
                }
            }
            .sheet(item: Binding(
                get: { viewModel.oauthSheetProvider },
                set: { _ in
                    Task { @MainActor in
                        viewModel.dismissOAuthSheet()
                    }
                }
            )) { provider in
                MockOAuthSheet(
                    provider: provider,
                    state: viewModel.oauthState,
                    message: viewModel.oauthStatusText,
                    dismiss: viewModel.dismissOAuthSheet
                )
                .frame(width: 420)
                .padding(22)
            }
            .alert(
                viewModel.presentedError?.title ?? "Unexpected error",
                isPresented: Binding(
                    get: { viewModel.presentedError != nil },
                    set: { newValue in
                        if !newValue, viewModel.presentedError != nil {
                            Task { @MainActor in
                                viewModel.dismissError()
                            }
                        }
                    }
                )
            ) {
                Button("OK", role: .cancel) {}
            } message: {
                if let error = viewModel.presentedError {
                    Text("\(error.message)\n\n\(error.recoverySuggestion)")
                } else {
                    Text("Unknown error")
                }
            }
    }
}
