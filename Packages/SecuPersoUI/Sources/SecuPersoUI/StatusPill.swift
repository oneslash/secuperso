import SwiftUI

public enum StatusPillTone: Sendable {
    case neutral
    case positive
    case caution
    case critical
}

public struct StatusPill: View {
    private let text: String
    private let tone: StatusPillTone

    public init(_ text: String, tone: StatusPillTone) {
        self.text = text
        self.tone = tone
    }

    public var body: some View {
        Text(text)
            .font(DesignTokens.caption.weight(.semibold))
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .foregroundStyle(foregroundColor)
            .background(backgroundColor)
            .clipShape(Capsule())
            .overlay(
                Capsule()
                    .stroke(borderColor, lineWidth: DesignTokens.borderWidth)
            )
    }

    private var foregroundColor: Color {
        switch tone {
        case .neutral:
            return DesignTokens.textPrimary
        case .positive:
            return DesignTokens.brandTeal
        case .caution:
            return DesignTokens.riskAmber
        case .critical:
            return .white
        }
    }

    private var backgroundColor: Color {
        switch tone {
        case .neutral:
            return DesignTokens.surfaceTertiary
        case .positive:
            return DesignTokens.brandTeal.opacity(0.16)
        case .caution:
            return DesignTokens.riskAmber.opacity(0.2)
        case .critical:
            return DesignTokens.riskRed
        }
    }

    private var borderColor: Color {
        switch tone {
        case .neutral:
            return DesignTokens.borderSubtle
        case .positive:
            return DesignTokens.brandTeal.opacity(0.28)
        case .caution:
            return DesignTokens.riskAmber.opacity(0.28)
        case .critical:
            return DesignTokens.riskRed.opacity(0.82)
        }
    }
}
