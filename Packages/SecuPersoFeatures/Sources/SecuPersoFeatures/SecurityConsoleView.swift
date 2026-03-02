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
                ForEach(AppSection.allCases) { section in
                    Label(section.title, systemImage: section.symbol)
                        .font(.body.weight(section == selectedSection ? .semibold : .regular))
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
                    ToolbarItemGroup(placement: .primaryAction) {
                        if let lastRefreshAt = viewModel.lastRefreshAt {
                            Label("Last check \(lastRefreshAt, style: .time)", systemImage: "clock")
                                .font(DesignTokens.caption)
                            .foregroundStyle(DesignTokens.textSecondary)
                        }

                        if viewModel.isRefreshing {
                            ProgressView()
                                .controlSize(.small)
                        }

                        Button {
                            Task { await viewModel.refreshAll() }
                        } label: {
                            Label("Refresh", systemImage: "arrow.clockwise")
                        }
                        .disabled(viewModel.isRefreshing)
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
            OverviewScreen(viewModel: viewModel) { destination in
                selectedSectionProxy.wrappedValue = destination
            }
        case .activity:
            ActivityScreen(viewModel: viewModel)
        case .exposure:
            ExposureScreen(viewModel: viewModel, exposureViewModel: exposureViewModel)
        case .integrations:
            IntegrationsScreen(viewModel: viewModel)
        case .settings:
            SettingsScreen(viewModel: viewModel, exposureViewModel: exposureViewModel)
        }
    }

    private var selectedSectionProxy: Binding<AppSection> {
        selectedSectionBinding ?? $localSelectedSection
    }

    private var selectedSection: AppSection {
        selectedSectionProxy.wrappedValue
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
                "Unexpected Error",
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
                Text(viewModel.presentedError?.message ?? "Unknown error")
            }
    }
}
