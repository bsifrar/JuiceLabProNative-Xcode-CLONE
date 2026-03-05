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
                                Color(nsColor: .windowBackgroundColor).opacity(0.9),
                                Color(nsColor: .underPageBackgroundColor).opacity(0.82)
                            ],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(Color.white.opacity(0.12), lineWidth: 1)
                    )
            )
            .shadow(color: .black.opacity(0.22), radius: 12, x: 0, y: 8)
    }
}

extension View {
    func cardSurface() -> some View { modifier(CardSurface()) }
}

#endif
