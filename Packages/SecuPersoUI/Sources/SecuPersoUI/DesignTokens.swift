import AppKit
import SwiftUI

public enum DesignTokens {
    public static let spacingXXS: CGFloat = 4
    public static let spacingXS: CGFloat = 6
    public static let spacingS: CGFloat = 10
    public static let spacingM: CGFloat = 16
    public static let spacingL: CGFloat = 22
    public static let spacingXL: CGFloat = 30

    public static let cardCornerRadius: CGFloat = 16
    public static let pillCornerRadius: CGFloat = 999
    public static let borderWidth: CGFloat = 1
    public static let cardShadowRadius: CGFloat = 8
    public static let cardShadowYOffset: CGFloat = 2

    public static var canvas: Color {
        dynamicColor(
            light: NSColor(calibratedRed: 0.965, green: 0.972, blue: 0.984, alpha: 1),
            dark: NSColor(calibratedRed: 0.11, green: 0.12, blue: 0.14, alpha: 1)
        )
    }

    public static var surfacePrimary: Color {
        dynamicColor(
            light: NSColor(calibratedWhite: 1.0, alpha: 0.96),
            dark: NSColor(calibratedRed: 0.17, green: 0.18, blue: 0.2, alpha: 1)
        )
    }

    public static var surfaceSecondary: Color {
        dynamicColor(
            light: NSColor(calibratedWhite: 1.0, alpha: 0.9),
            dark: NSColor(calibratedRed: 0.15, green: 0.16, blue: 0.18, alpha: 1)
        )
    }

    public static var surfaceTertiary: Color {
        dynamicColor(
            light: NSColor(calibratedWhite: 1.0, alpha: 0.86),
            dark: NSColor(calibratedRed: 0.19, green: 0.2, blue: 0.22, alpha: 1)
        )
    }

    public static var borderSubtle: Color {
        textPrimary.opacity(0.07)
    }

    public static var borderStrong: Color {
        textPrimary.opacity(0.14)
    }

    public static var cardShadowColor: Color {
        Color.black.opacity(0.05)
    }

    public static var canvasWarm: Color {
        canvas
    }

    public static var surfaceRaised: Color {
        surfacePrimary
    }

    public static var surfaceSubtle: Color {
        surfaceTertiary
    }

    public static var brandTeal: Color {
        .accentColor
    }

    public static var riskAmber: Color {
        Color(nsColor: .systemOrange)
    }

    public static var riskRed: Color {
        Color(nsColor: .systemRed)
    }

    public static var textPrimary: Color {
        .primary
    }

    public static var textSecondary: Color {
        .secondary
    }

    public static var headlineLarge: Font {
        .title2.weight(.semibold)
    }

    public static var headlineMedium: Font {
        .headline
    }

    public static var bodyStrong: Font {
        .body.weight(.semibold)
    }

    public static var heroDisplay: Font {
        .title2.weight(.semibold)
    }

    public static var heroScore: Font {
        .system(.largeTitle, design: .rounded).weight(.bold)
    }

    public static var sectionTitle: Font {
        headlineMedium
    }

    public static var body: Font {
        .body
    }

    public static var caption: Font {
        .caption
    }

    public static var appBackground: Color {
        canvas
    }

    public static var elevatedCardBackground: some ShapeStyle {
        surfacePrimary
    }

    public static var secondaryCardBackground: some ShapeStyle {
        surfaceSecondary
    }

    public static var subtleBorder: Color {
        borderSubtle
    }

    public static var mutedForeground: Color {
        textSecondary
    }

    private static func dynamicColor(light: NSColor, dark: NSColor) -> Color {
        Color(
            nsColor: NSColor(name: nil) { appearance in
                let match = appearance.bestMatch(from: [.darkAqua, .aqua])
                return match == .darkAqua ? dark : light
            }
        )
    }
}
