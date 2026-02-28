import SwiftUI

public enum DesignTokens {
    public static let spacingXXS: CGFloat = 4
    public static let spacingXS: CGFloat = 8
    public static let spacingS: CGFloat = 12
    public static let spacingM: CGFloat = 18
    public static let spacingL: CGFloat = 24
    public static let spacingXL: CGFloat = 32

    public static let cardCornerRadius: CGFloat = 14
    public static let borderWidth: CGFloat = 1

    public static var appBackground: Color {
        Color(nsColor: .windowBackgroundColor)
    }

    public static var elevatedCardBackground: some ShapeStyle {
        Color(nsColor: .controlBackgroundColor).opacity(0.9)
    }

    public static var secondaryCardBackground: some ShapeStyle {
        Color(nsColor: .textBackgroundColor).opacity(0.4)
    }

    public static var subtleBorder: Color {
        Color.primary.opacity(0.1)
    }

    public static var mutedForeground: Color {
        Color.primary.opacity(0.65)
    }
}
