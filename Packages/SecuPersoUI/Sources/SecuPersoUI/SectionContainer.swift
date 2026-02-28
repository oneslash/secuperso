import SwiftUI

public struct SectionContainer<Content: View>: View {
    private let title: String?
    private let subtitle: String?
    private let content: Content

    public init(
        title: String? = nil,
        subtitle: String? = nil,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.subtitle = subtitle
        self.content = content()
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingS) {
            if let title {
                Text(title)
                    .font(.headline)
            }

            if let subtitle {
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(DesignTokens.mutedForeground)
            }

            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(DesignTokens.spacingM)
        .background(
            RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius)
                .fill(DesignTokens.elevatedCardBackground)
        )
        .overlay(
            RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius)
                .stroke(DesignTokens.subtleBorder, lineWidth: DesignTokens.borderWidth)
        )
    }
}
