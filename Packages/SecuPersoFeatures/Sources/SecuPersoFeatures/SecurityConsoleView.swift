import SwiftUI

public struct SecurityConsoleView: View {
    @ObservedObject private var viewModel: SecurityConsoleViewModel
    @State private var selectedSection: AppSection = .overview

    public init(viewModel: SecurityConsoleViewModel) {
        self.viewModel = viewModel
    }

    public var body: some View {
        NavigationSplitView {
            List(AppSection.allCases, selection: $selectedSection) { section in
                Label(section.title, systemImage: section.symbol)
                    .tag(section)
            }
            .listStyle(.sidebar)
            .navigationTitle("SecuPerso")
        } detail: {
            contentView
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
        }
    }

    @ViewBuilder
    private var contentView: some View {
        switch selectedSection {
        case .overview:
            OverviewScreen(viewModel: viewModel)
        case .emailExposure:
            EmailExposureScreen(viewModel: viewModel)
        case .loginActivity:
            LoginActivityScreen(viewModel: viewModel)
        case .settings:
            SettingsScreen(viewModel: viewModel)
        }
    }
}
