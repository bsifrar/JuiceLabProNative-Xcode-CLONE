#if canImport(SwiftUI) && canImport(AppKit)
import SwiftUI

struct CardSurface: ViewModifier {
    func body(content: Content) -> some View {
        content
            .padding(14)
            .background(
                RoundedRectangle(cornerRadius: 16)
                    .fill(
                        LinearGradient(
                            colors: [
                                Color(red: 0.08, green: 0.09, blue: 0.17).opacity(0.96),
                                Color(red: 0.04, green: 0.05, blue: 0.11).opacity(0.94)
                            ],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(
                                LinearGradient(
                                    colors: [
                                        Color(red: 0.42, green: 0.34, blue: 1.00).opacity(0.55),
                                        Color.white.opacity(0.08)
                                    ],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                ),
                                lineWidth: 1
                            )
                    )
            )
            .shadow(color: Color(red: 0.35, green: 0.28, blue: 1.0).opacity(0.20), radius: 14, x: 0, y: 8)
            .shadow(color: .black.opacity(0.38), radius: 18, x: 0, y: 14)
    }
}

extension View {
    func cardSurface() -> some View { modifier(CardSurface()) }
}

#endif
