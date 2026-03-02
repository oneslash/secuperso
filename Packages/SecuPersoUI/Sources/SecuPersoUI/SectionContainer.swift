import SwiftUI

public enum SectionContainerStyle: Sendable {
    case elevated
    case flat
    case inset
}

public struct SectionContainer<Content: View>: View {
    private let title: String?
    private let subtitle: String?
    private let style: SectionContainerStyle
    private let content: Content

    public init(
        title: String? = nil,
        subtitle: String? = nil,
        style: SectionContainerStyle = .elevated,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.subtitle = subtitle
        self.style = style
        self.content = content()
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: DesignTokens.spacingM) {
            if let title {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(DesignTokens.sectionTitle)
                        .foregroundStyle(DesignTokens.textPrimary)

                    if let subtitle {
                        Text(subtitle)
                            .font(DesignTokens.body)
                            .foregroundStyle(DesignTokens.textSecondary)
                    }
                }
            }

            if title == nil, let subtitle {
                Text(subtitle)
                    .font(DesignTokens.body)
                    .foregroundStyle(DesignTokens.textSecondary)
            }

            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(DesignTokens.spacingM)
        .background(
            RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius, style: .continuous)
                .fill(backgroundFill)
        )
        .overlay(
            RoundedRectangle(cornerRadius: DesignTokens.cardCornerRadius, style: .continuous)
                .stroke(borderColor, lineWidth: DesignTokens.borderWidth)
        )
        .shadow(
            color: shadowColor,
            radius: shadowRadius,
            x: 0,
            y: shadowYOffset
        )
    }

    private var backgroundFill: Color {
        switch style {
        case .elevated:
            return DesignTokens.surfacePrimary
        case .flat:
            return DesignTokens.surfacePrimary
        case .inset:
            return DesignTokens.surfaceSecondary
        }
    }

    private var borderColor: Color {
        switch style {
        case .elevated:
            return DesignTokens.borderSubtle
        case .flat:
            return DesignTokens.borderSubtle.opacity(0.7)
        case .inset:
            return DesignTokens.borderSubtle.opacity(0.65)
        }
    }

    private var shadowColor: Color {
        switch style {
        case .elevated:
            return DesignTokens.cardShadowColor
        case .flat, .inset:
            return .clear
        }
    }

    private var shadowRadius: CGFloat {
        style == .elevated ? DesignTokens.cardShadowRadius : 0
    }

    private var shadowYOffset: CGFloat {
        style == .elevated ? DesignTokens.cardShadowYOffset : 0
    }
}
