import SwiftUI
import SecuPersoDomain

public struct RiskBadgeView: View {
    private let level: RiskLevel

    public init(level: RiskLevel) {
        self.level = level
    }

    public var body: some View {
        Text(level.rawValue.uppercased())
            .font(.caption.weight(.bold))
            .foregroundStyle(.white)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(backgroundColor)
            .clipShape(Capsule())
    }

    private var backgroundColor: Color {
        switch level {
        case .low:
            return .green
        case .medium:
            return .orange
        case .high:
            return .red
        }
    }
}
