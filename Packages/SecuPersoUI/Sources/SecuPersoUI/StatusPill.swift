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
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .foregroundStyle(foregroundColor)
            .background(backgroundColor)
            .clipShape(Capsule())
    }

    private var foregroundColor: Color {
        switch tone {
        case .neutral, .caution:
            return .primary
        case .positive, .critical:
            return .white
        }
    }

    private var backgroundColor: Color {
        switch tone {
        case .neutral:
            return Color.secondary.opacity(0.22)
        case .positive:
            return .green
        case .caution:
            return .yellow.opacity(0.5)
        case .critical:
            return .red
        }
    }
}
