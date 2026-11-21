import SwiftUI
import UIKit

/// A keyboard-input view with no text storage: every keystroke goes straight into the Rust core's
/// fixed buffer for `field`, so the password never exists as a Swift/UIKit string. It also bypasses
/// Password AutoFill (nothing is offered to, or saved in, iCloud Keychain), has no paste menu, and
/// uses the secure keyboard (no prediction, no learning, no third-party keyboards).
final class KeyInputView: UIView, UIKeyInput {
    var onInsert: (String) -> Void = { _ in }
    var onDelete: () -> Void = {}
    var onReturn: () -> Void = {}
    var hasTextProvider: () -> Bool = { false }

    // UITextInputTraits
    var keyboardType: UIKeyboardType = .asciiCapable
    var returnKeyType: UIReturnKeyType = .next
    var isSecureTextEntry: Bool = true
    var autocorrectionType: UITextAutocorrectionType = .no
    var autocapitalizationType: UITextAutocapitalizationType = .none
    var spellCheckingType: UITextSpellCheckingType = .no
    var smartQuotesType: UITextSmartQuotesType = .no
    var smartDashesType: UITextSmartDashesType = .no
    var smartInsertDeleteType: UITextSmartInsertDeleteType = .no
    var keyboardAppearance: UIKeyboardAppearance = .dark
    var enablesReturnKeyAutomatically: Bool = false

    override var canBecomeFirstResponder: Bool { true }
    var hasText: Bool { hasTextProvider() }

    func insertText(_ text: String) {
        if text == "\n" {
            onReturn()
        } else {
            onInsert(text)
        }
    }

    func deleteBackward() { onDelete() }

    // No cut/copy/paste/select menu at all.
    override func canPerformAction(_ action: Selector, withSender sender: Any?) -> Bool { false }

    override func touchesEnded(_ touches: Set<UITouch>, with event: UIEvent?) {
        super.touchesEnded(touches, with: event)
        if isUserInteractionEnabled { becomeFirstResponder() }
    }
}

struct SecureKeyField: UIViewRepresentable {
    let field: InputField
    @ObservedObject var model: AppModel
    var keyboard: UIKeyboardType = .asciiCapable
    var returnKey: UIReturnKeyType = .next
    @Binding var focused: InputField?
    var onReturn: () -> Void = {}

    func makeUIView(context: Context) -> KeyInputView {
        let v = KeyInputView()
        v.backgroundColor = .clear
        return v
    }

    func updateUIView(_ v: KeyInputView, context: Context) {
        let f = field
        let model = model
        v.keyboardType = keyboard
        v.returnKeyType = returnKey
        v.onInsert = { text in model.type(f, text) }
        v.onDelete = { model.backspace(f) }
        v.onReturn = onReturn
        v.hasTextProvider = { model.counts[f, default: 0] > 0 }
        v.isUserInteractionEnabled = model.busy == nil
        let want = focused == field && model.busy == nil
        DispatchQueue.main.async {
            if want, !v.isFirstResponder, v.window != nil {
                v.becomeFirstResponder()
            } else if !want, v.isFirstResponder {
                v.resignFirstResponder()
            }
        }
    }
}

/// The visible box: dots for the typed length, over the invisible input view.
struct SecretBox: View {
    let label: String
    let field: InputField
    @ObservedObject var model: AppModel
    var keyboard: UIKeyboardType = .asciiCapable
    var returnKey: UIReturnKeyType = .next
    var showCount: Int? = nil
    var allowPaste = false
    /// Red field: the vault is approaching termination.
    var alarm = false
    @Binding var focused: InputField?
    var onReturn: () -> Void = {}

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(Theme.small).foregroundStyle(Theme.dim)
            HStack(spacing: 8) {
                box
                if allowPaste {
                    // System paste control: an explicit user action, so iOS shows no paste prompt
                    // and Scytale never reads the clipboard on its own.
                    PasteButton(payloadType: String.self) { strings in
                        Task { @MainActor in
                            model.paste(field, strings.first)
                            focused = field
                        }
                    }
                    .labelStyle(.iconOnly)
                    .buttonBorderShape(.roundedRectangle(radius: 8))
                    .tint(Theme.green)
                    .disabled(model.busy != nil)
                }
            }
            if let note = model.pasteNote, note.field == field {
                Note(text: note.text, kind: note.ok ? .ok : .error)
            }
        }
    }

    private var box: some View {
        let n = model.counts[field, default: 0]
        return ZStack(alignment: .leading) {
                RoundedRectangle(cornerRadius: 8)
                    .stroke(alarm ? Theme.error : (focused == field ? Theme.green : Theme.line), lineWidth: alarm ? 2.5 : 1.5)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Theme.panel))
                HStack(spacing: 0) {
                    Text(String(repeating: "•", count: min(n, 40)))
                        .font(Theme.mono)
                        .foregroundStyle(alarm ? Theme.error : Theme.text)
                        .lineLimit(1)
                    if focused == field {
                        Rectangle().fill(Theme.green).frame(width: 2, height: 20)
                    }
                    Spacer()
                    if let total = showCount {
                        Text("\(n)/\(total)").font(Theme.small).foregroundStyle(Theme.dim)
                    }
                }
                .padding(.horizontal, 12)
                .allowsHitTesting(false)
                SecureKeyField(field: field, model: model, keyboard: keyboard, returnKey: returnKey,
                               focused: $focused, onReturn: onReturn)
                    .simultaneousGesture(TapGesture().onEnded { focused = field })
            }
            .frame(height: 46)
    }
}
