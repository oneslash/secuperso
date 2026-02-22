import SwiftUI

public enum DesignTokens {
    public static let spacingXS: CGFloat = 6
    public static let spacingS: CGFloat = 10
    public static let spacingM: CGFloat = 16
    public static let spacingL: CGFloat = 22
    public static let cardCornerRadius: CGFloat = 12

    public static var elevatedCardBackground: some ShapeStyle {
        Color(nsColor: .controlBackgroundColor)
    }
}
