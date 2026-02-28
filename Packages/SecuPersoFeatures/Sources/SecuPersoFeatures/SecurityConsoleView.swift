import SwiftUI

public struct SecurityConsoleView: View {
    @ObservedObject private var viewModel: SecurityConsoleViewModel
    @ObservedObject private var exposureViewModel: ExposureViewModel
    @State private var selectedSection: AppSection = .overview

    public init(viewModel: SecurityConsoleViewModel, exposureViewModel: ExposureViewModel) {
        self.viewModel = viewModel
        self.exposureViewModel = exposureViewModel
    }

    public var body: some View {
        NavigationSplitView {
            List(selection: $selectedSection) {
                Section("Main") {
                    ForEach(AppSection.primaryCases) { section in
                        Label(section.title, systemImage: section.symbol)
                            .tag(section)
                    }
                }

                Section("Utility") {
                    ForEach(AppSection.utilityCases) { section in
                        Label(section.title, systemImage: section.symbol)
                            .tag(section)
                    }
                }
            }
            .listStyle(.sidebar)
            .navigationTitle("SecuPerso")
        } detail: {
            contentView
                .animation(.easeInOut(duration: 0.2), value: selectedSection)
                .navigationTitle(selectedSection.title)
                .toolbar {
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            Task { await viewModel.refreshAll() }
                        } label: {
                            Label("Refresh", systemImage: "arrow.clockwise")
                        }
                        .disabled(viewModel.isRefreshing)
                    }
                    ToolbarItem {
                        if let lastRefreshAt = viewModel.lastRefreshAt {
                            Text("Last check: \(lastRefreshAt, style: .time)")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .confirmationDialog(
                    viewModel.pendingConfirmationAction?.title ?? "Confirm action",
                    isPresented: Binding(
                        get: { viewModel.pendingConfirmationAction != nil },
                        set: { isPresented in
                            if !isPresented {
                                viewModel.cancelPendingAction()
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
        }
        .sheet(item: $viewModel.oauthSheetProvider) { provider in
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
                        viewModel.dismissError()
                    }
                }
            )
        ) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(viewModel.presentedError?.message ?? "Unknown error")
        }
        .onAppear {
            viewModel.start()
            exposureViewModel.start()
        }
    }

    @ViewBuilder
    private var contentView: some View {
        switch selectedSection {
        case .overview:
            OverviewScreen(viewModel: viewModel) { destination in
                selectedSection = destination
            }
        case .exposure:
            ExposureScreen(viewModel: viewModel, exposureViewModel: exposureViewModel)
        case .activity:
            ActivityScreen(viewModel: viewModel)
        case .settings:
            SettingsScreen(viewModel: viewModel, exposureViewModel: exposureViewModel)
        }
    }
}
