#if canImport(SwiftUI) && canImport(AppKit)
import SwiftUI

enum AppTheme {
    static let background = Color(hex: "#09090b")
    static let mutedBackground = Color(hex: "#1c1c22")
    static let text = Color(hex: "#fafafa")
    static let mutedText = Color(hex: "#a1a1aa")
    static let primary = Color(hex: "#704dff")
    static let secondary = Color(hex: "#1c1c22")
    static let accent = Color(hex: "#704dff")
    static let destructive = Color(hex: "#7f1d1d")
    static let card = Color(hex: "#0e0e11")
    static let input = Color(hex: "#25252d")
    static let border = Color(hex: "#25252d")
}

struct CardSurface: ViewModifier {
    func body(content: Content) -> some View {
        content
            .padding(14)
            .background(
                RoundedRectangle(cornerRadius: 16)
                    .fill(.ultraThinMaterial)
                    .overlay(
                        ZStack {
                            RoundedRectangle(cornerRadius: 16)
                                .fill(AppTheme.card.opacity(0.58))
                            RoundedRectangle(cornerRadius: 16)
                                .stroke(
                                    LinearGradient(
                                        colors: [
                                            AppTheme.primary.opacity(0.44),
                                            Color.white.opacity(0.10)
                                        ],
                                        startPoint: .topLeading,
                                        endPoint: .bottomTrailing
                                    ),
                                    lineWidth: 1
                                )
                        }
                    )
            )
            .shadow(color: AppTheme.primary.opacity(0.22), radius: 14, x: 0, y: 8)
            .shadow(color: .black.opacity(0.38), radius: 18, x: 0, y: 14)
    }
}

struct ActionButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .medium))
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .foregroundStyle(AppTheme.text)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(AppTheme.primary.opacity(0.15))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(AppTheme.primary.opacity(0.35), lineWidth: 1)
            )
            .opacity(configuration.isPressed ? 0.85 : 1.0)
    }
}

struct ForensicSummaryCardStyle: ViewModifier {
    func body(content: Content) -> some View {
        content
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(AppTheme.card)
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(AppTheme.primary.opacity(0.25), lineWidth: 1)
                    )
            )
            .shadow(color: AppTheme.primary.opacity(0.16), radius: 10, x: 0, y: 6)
    }
}

extension View {
    func cardSurface() -> some View { modifier(CardSurface()) }
    func forensicSummaryCardStyle() -> some View { modifier(ForensicSummaryCardStyle()) }
}

extension Color {
    init(hex: String) {
        let hexSanitized = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hexSanitized).scanHexInt64(&int)
        let r = Double((int >> 16) & 0xFF) / 255.0
        let g = Double((int >> 8) & 0xFF) / 255.0
        let b = Double(int & 0xFF) / 255.0
        self.init(red: r, green: g, blue: b)
    }
}

#endif
