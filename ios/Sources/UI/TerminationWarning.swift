import SwiftUI

/// Shown under the admin password field once 5 wrong passwords have been entered.
struct TerminationWarning: View {
    let level: Int32

    var body: some View {
        if level > 0 {
            Text(level >= 2 ? "VAULT TERMINATION IN 5 FAILED ATTEMPTS" : "VAULT TERMINATION IN 10 FAILED ATTEMPTS")
                .font(Theme.mono.weight(.heavy))
                .foregroundStyle(Theme.error)
                .frame(maxWidth: .infinity, alignment: .leading)
                .accessibilityLabel("Warning: the vault will be destroyed after \(level >= 2 ? 5 : 10) more failed password attempts")
        }
    }
}
