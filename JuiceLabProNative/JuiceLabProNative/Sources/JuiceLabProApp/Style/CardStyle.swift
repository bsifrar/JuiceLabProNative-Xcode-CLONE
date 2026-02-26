#if canImport(SwiftUI) && canImport(AppKit)
import SwiftUI

struct CardSurface: ViewModifier {
    func body(content: Content) -> some View {
        content
            .padding(14)
            .background(
                RoundedRectangle(cornerRadius: 16)
                    .fill(Color(nsColor: .windowBackgroundColor).opacity(0.6))
                    .overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(Color.white.opacity(0.08), lineWidth: 1)
                    )
            )
            .shadow(color: .black.opacity(0.16), radius: 8, x: 0, y: 4)
    }
}

extension View {
    func cardSurface() -> some View { modifier(CardSurface()) }
}

#endif
