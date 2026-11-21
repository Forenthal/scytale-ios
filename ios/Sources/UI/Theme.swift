import SwiftUI

enum Theme {
    static let green = Color(red: 64 / 255, green: 220 / 255, blue: 120 / 255)
    static let background = Color(red: 10 / 255, green: 12 / 255, blue: 14 / 255)
    static let panel = Color(red: 20 / 255, green: 24 / 255, blue: 28 / 255)
    static let line = Color(red: 48 / 255, green: 56 / 255, blue: 62 / 255)
    static let text = Color(red: 225 / 255, green: 232 / 255, blue: 228 / 255)
    static let dim = Color(red: 130 / 255, green: 142 / 255, blue: 138 / 255)
    static let warn = Color(red: 240 / 255, green: 190 / 255, blue: 80 / 255)
    static let error = Color(red: 240 / 255, green: 90 / 255, blue: 90 / 255)

    static let mono = Font.system(.body, design: .monospaced)
    static let small = Font.system(.footnote, design: .monospaced)
    static let title = Font.system(.title2, design: .monospaced).weight(.bold)
}

struct PrimaryButton: View {
    let title: String
    var enabled = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(Theme.mono.weight(.semibold))
                .frame(maxWidth: .infinity, minHeight: 48)
                .foregroundStyle(enabled ? Color.black : Theme.dim)
                .background(RoundedRectangle(cornerRadius: 10).fill(enabled ? Theme.green : Theme.panel))
        }
        .disabled(!enabled)
    }
}

/// One terse status line with an icon: ✓ done, ⚠ warning, ⛔ error, › information.
struct Note: View {
    enum Kind { case info, warn, error, ok }
    let text: String
    var kind: Kind = .info
    var icon: String?

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: icon ?? Self.defaultIcon(kind))
                .font(.system(size: 12, weight: .bold))
                .foregroundStyle(Self.color(kind))
                .frame(width: 14)
            Text(text)
                .font(Theme.small)
                .foregroundStyle(kind == .info ? Theme.dim : Self.color(kind))
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    static func defaultIcon(_ k: Kind) -> String {
        switch k {
        case .info: return "chevron.right"
        case .ok: return "checkmark.circle.fill"
        case .warn: return "exclamationmark.triangle.fill"
        case .error: return "xmark.octagon.fill"
        }
    }

    static func color(_ k: Kind) -> Color {
        switch k {
        case .info: return Theme.dim
        case .warn: return Theme.warn
        case .error: return Theme.error
        case .ok: return Theme.green
        }
    }
}
