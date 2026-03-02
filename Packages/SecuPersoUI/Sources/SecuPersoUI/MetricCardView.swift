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
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(DesignTokens.caption)
                .foregroundStyle(DesignTokens.textSecondary)
            Text(value)
                .font(.title2.weight(.semibold))
                .foregroundStyle(DesignTokens.textPrimary)
            Text(subtitle)
                .font(DesignTokens.caption)
                .foregroundStyle(DesignTokens.textSecondary)
                .lineLimit(2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .frame(minHeight: 108, alignment: .topLeading)
        .padding(.horizontal, DesignTokens.spacingM)
        .padding(.vertical, DesignTokens.spacingS)
        .background(
            RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius, style: .continuous)
                .fill(DesignTokens.surfaceSecondary)
        )
        .overlay(
            RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius, style: .continuous)
                .stroke(DesignTokens.borderSubtle, lineWidth: DesignTokens.borderWidth)
        )
    }
}
