import SwiftUI
import SecuPersoDomain
import SecuPersoUI

struct EmailExposureScreen: View {
    @ObservedObject var viewModel: SecurityConsoleViewModel
    @State private var exposureFilter: ExposureFilter = .all
    @State private var selectedExposureID: ExposureRecord.ID?

    var body: some View {
        HStack(spacing: DesignTokens.spacingM) {
            VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                Picker("Filter", selection: $exposureFilter) {
                    ForEach(ExposureFilter.allCases) { filter in
                        Text(filter.title).tag(filter)
                    }
                }
                .pickerStyle(.segmented)

                Table(filteredExposures, selection: $selectedExposureID) {
                    TableColumn("Email", value: \.email)
                    TableColumn("Source", value: \.source)
                    TableColumn("Severity") { record in
                        Text(record.severity.rawValue.capitalized)
                            .foregroundStyle(record.severity == .critical ? .red : record.severity == .high ? .orange : .primary)
                    }
                    TableColumn("Status") { record in
                        Text(record.status.rawValue.capitalized)
                            .foregroundStyle(record.status == .resolved ? .green : .primary)
                    }
                    TableColumn("Date") { record in
                        Text(record.foundAt, style: .date)
                    }
                }
            }
            .frame(minWidth: 600, maxWidth: .infinity)

            VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
                Text("Remediation")
                    .font(.headline)
                if let selected = selectedExposure {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(selected.email)
                            .font(.title3.weight(.semibold))
                        Text("Source: \(selected.source)")
                            .foregroundStyle(.secondary)
                        Text("Severity: \(selected.severity.rawValue.capitalized)")
                        Text("Status: \(selected.status.rawValue.capitalized)")
                        Divider()
                        Text(selected.remediation)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                } else {
                    Text("Select an exposure to view remediation steps.")
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            .frame(width: 300)
            .padding(DesignTokens.spacingM)
            .background(RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius).fill(DesignTokens.elevatedCardBackground))
        }
        .padding(DesignTokens.spacingL)
    }

    private var filteredExposures: [ExposureRecord] {
        switch exposureFilter {
        case .all:
            return viewModel.exposures
        case .open:
            return viewModel.exposures.filter { $0.status == .open }
        case .resolved:
            return viewModel.exposures.filter { $0.status == .resolved }
        case .highSeverity:
            return viewModel.exposures.filter { $0.severity == .high || $0.severity == .critical }
        }
    }

    private var selectedExposure: ExposureRecord? {
        guard let selectedExposureID else { return nil }
        return viewModel.exposures.first(where: { $0.id == selectedExposureID })
    }
}
