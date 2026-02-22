import SwiftUI

public struct MetricCardView: View {
    private let title: String
    private let value: String
    private let subtitle: String

    public init(title: String, value: String, subtitle: String) {
        self.title = title
        self.value = value
        self.subtitle = subtitle
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingXS) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.title2.weight(.semibold))
            Text(subtitle)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(DesignTokens.spacingM)
        .background(RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius).fill(DesignTokens.elevatedCardBackground))
    }
}
