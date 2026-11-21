import SwiftUI

/// First-time setup, and recovery with the recovery key. Same steps as the Windows app, plus
/// creating the Face ID key:
///   (recovery key) → password → authenticator → Face ID key → recovery key shown once.
struct SetupFlow: View {
    @ObservedObject var model: AppModel
    let recover: Bool

    enum Step { case intro, recoveryEntry, password, authenticator, faceID, showRecovery }

    @State private var step: Step
    @State private var focused: InputField?
    @State private var error: String?
    @State private var qr: (width: Int, modules: [UInt8])?
    @State private var secret: String?
    @State private var recoveryKey: String?
    @State private var savedText = ""
    @State private var copied = false
    @State private var keyCopied = false

    init(model: AppModel, recover: Bool) {
        self.model = model
        self.recover = recover
        _step = State(initialValue: recover ? .recoveryEntry : .intro)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text(recover ? "RECOVER VAULT" : "NEW VAULT")
                    .font(Theme.title).foregroundStyle(Theme.green)
                if let note = model.startNote, step == .intro || step == .recoveryEntry {
                    Note(text: note, kind: model.startNoteIsWarning ? .warn : .ok)
                }
                if step != .intro && step != .recoveryEntry { tracker }
                switch step {
                case .intro: intro
                case .recoveryEntry: recoveryEntry
                case .password: password
                case .authenticator: authenticator
                case .faceID: faceID
                case .showRecovery: showRecovery
                }
                if let error { Note(text: error, kind: .error) }
                if let busy = model.busy {
                    HStack(spacing: 10) { ProgressView().tint(Theme.green); Note(text: busy) }
                }
            }
            .padding(20)
        }
        .scrollDismissesKeyboard(.never)
        .onDisappear { forgetDisplayedSecrets() }
    }

    /// 1 password · 2 authenticator · 3 device key · 4 recovery key, with check marks.
    private var tracker: some View {
        let order: [Step] = [.password, .authenticator, .faceID, .showRecovery]
        let labels = ["PASSWORD", "AUTH", "DEVICE KEY", "RECOVERY"]
        let current = order.firstIndex(of: step) ?? 0
        return HStack(spacing: 6) {
            ForEach(0..<order.count, id: \.self) { i in
                HStack(spacing: 4) {
                    Image(systemName: i < current ? "checkmark.circle.fill" : (i == current ? "circle.inset.filled" : "circle"))
                        .font(.system(size: 11, weight: .bold))
                    Text(labels[i]).font(.system(size: 9, weight: .semibold, design: .monospaced))
                }
                .foregroundStyle(i <= current ? Theme.green : Theme.dim)
                if i < order.count - 1 { Rectangle().fill(Theme.line).frame(height: 1) }
            }
        }
    }

    // MARK: steps

    private var intro: some View {
        VStack(alignment: .leading, spacing: 10) {
            Note(text: "Encrypted on this iPhone only. No sync, no backup.")
            Note(text: "4 steps: password · authenticator · Face ID device key · recovery key")
            Note(text: "Face ID enrolment change disables the device key. Recovery key required.", kind: .warn)
            PrimaryButton(title: "Begin") { step = .password; focused = .password }
                .padding(.top, 6)
        }
    }

    private var recoveryEntry: some View {
        VStack(alignment: .leading, spacing: 14) {
            Note(text: "Enter recovery key. Case and spaces ignored.")
            Note(text: "Password, authenticator, device key and recovery key will all be replaced.", kind: .warn)
            SecretBox(label: "Recovery key", field: .recovery, model: model, returnKey: .go, showCount: 52,
                      focused: $focused) { checkRecovery() }
            PrimaryButton(title: "Verify recovery key", enabled: model.counts[.recovery, default: 0] >= 52) { checkRecovery() }
            Button("Back to login") { model.setupAbandon() }
                .font(Theme.small).foregroundStyle(Theme.dim)
        }
    }

    private var password: some View {
        VStack(alignment: .leading, spacing: 14) {
            Note(text: "Min 14 characters, varied. Not recoverable.")
            SecretBox(label: "Admin password", field: .password, model: model, allowPaste: true, focused: $focused) { focused = .confirm }
            SecretBox(label: "Repeat password", field: .confirm, model: model, returnKey: .done, allowPaste: true, focused: $focused) {
                submitPassword()
            }
            PrimaryButton(title: "Continue",
                          enabled: model.counts[.password, default: 0] > 0 && model.counts[.confirm, default: 0] > 0) {
                submitPassword()
            }
        }
    }

    private var authenticator: some View {
        VStack(alignment: .leading, spacing: 14) {
            Note(text: "On-device authenticator only. No cloud sync (not Apple Passwords, not synced Google Authenticator).", kind: .warn)
            if let qr {
                QRCodeView(width: qr.width, modules: qr.modules)
                    .frame(maxWidth: 260)
                    .frame(maxWidth: .infinity)
                Note(text: "Scan from another device, or enter key manually · Scytale iPhone · TOTP · 6 digits", icon: "key.horizontal.fill")
            }
            if let secret {
                Text(secret)
                    .font(Theme.mono.weight(.semibold))
                    .foregroundStyle(Theme.text)
                    .textSelection(.disabled)
                    .frame(maxWidth: .infinity, alignment: .center)
                Button {
                    model.copyAuthenticatorKey(secret)
                    keyCopied = true
                } label: {
                    Label(keyCopied ? "Copied" : "Copy key", systemImage: keyCopied ? "checkmark" : "doc.on.doc")
                        .font(Theme.mono.weight(.semibold))
                        .frame(maxWidth: .infinity, minHeight: 44)
                        .foregroundStyle(Theme.green)
                        .background(RoundedRectangle(cornerRadius: 10).stroke(Theme.green, lineWidth: 1.5))
                }
                if keyCopied {
                    Note(text: "Local clipboard only · clears in 2 min · return within 5 min", kind: .ok)
                }
            }
            SecretBox(label: "6-digit code", field: .code, model: model,
                      keyboard: .numberPad, showCount: 6, allowPaste: true, focused: $focused)
            PrimaryButton(title: "Verify code", enabled: model.counts[.code, default: 0] == 6) { submitCode() }
        }
    }

    private var faceID: some View {
        VStack(alignment: .leading, spacing: 10) {
            Note(text: "Creates a key in the Secure Enclave. Bound to this iPhone, not backed up.")
            Note(text: "Released only on a Face ID match. Verified once now.")
            PrimaryButton(title: recover ? "Create new device key" : "Create device key", enabled: model.busy == nil) {
                error = nil
                model.setupCreateKey(recover: recover) { message in
                    if let message {
                        error = message
                    } else {
                        recoveryKey = model.setupRecoveryKey()
                        step = .showRecovery
                    }
                }
            }
            .padding(.top, 6)
        }
    }

    private var showRecovery: some View {
        VStack(alignment: .leading, spacing: 14) {
            Note(text: recover ? "Vault re-keyed. New recovery key:" : "Vault created. Recovery key:", kind: .ok)
            if let recoveryKey {
                Text(recoveryKey)
                    .font(.system(.title3, design: .monospaced).weight(.bold))
                    .foregroundStyle(Theme.green)
                    .textSelection(.disabled)
                    .padding(14)
                    .frame(maxWidth: .infinity)
                    .background(RoundedRectangle(cornerRadius: 10).stroke(Theme.green, lineWidth: 1.5))
                Button {
                    model.copyRecoveryKey(recoveryKey)
                    copied = true
                } label: {
                    Label(copied ? "Copied" : "Copy recovery key", systemImage: copied ? "checkmark" : "doc.on.doc")
                        .font(Theme.mono.weight(.semibold))
                        .frame(maxWidth: .infinity, minHeight: 44)
                        .foregroundStyle(Theme.green)
                        .background(RoundedRectangle(cornerRadius: 10).stroke(Theme.green, lineWidth: 1.5))
                }
                if copied {
                    Note(text: "Local clipboard only · clears in 2 min · Scytale locks on app switch", kind: .ok)
                }
            }
            Note(text: "Store: E2E-encrypted password manager or paper.", kind: .ok, icon: "checkmark.shield.fill")
            Note(text: "Never: screenshot, photo, Notes, Messages, email, cloud documents.", kind: .error, icon: "nosign")
            Note(text: "Shown once. Only recovery path. Screen held awake.")
            Text("Type SAVED to continue").font(Theme.small).foregroundStyle(Theme.dim)
            TextField("", text: $savedText)
                .font(Theme.mono)
                .textInputAutocapitalization(.characters)
                .autocorrectionDisabled()
                .padding(12)
                .background(RoundedRectangle(cornerRadius: 8).fill(Theme.panel))
            PrimaryButton(title: "Done", enabled: savedText.trimmingCharacters(in: .whitespaces).uppercased() == "SAVED") {
                forgetDisplayedSecrets()
                model.setupDone()
            }
        }
        // Keep the phone from auto-locking while the key is on screen (an auto-lock wipes it).
        .onAppear { UIApplication.shared.isIdleTimerDisabled = true }
        .onDisappear { UIApplication.shared.isIdleTimerDisabled = false }
    }

    // MARK: actions

    private func checkRecovery() {
        if model.recoverCheck() {
            error = nil
            step = .password
            focused = .password
        } else {
            error = "Recovery key rejected."
        }
    }

    private func submitPassword() {
        switch model.setupBegin(recover: recover) {
        case 0:
            error = nil
            qr = model.setupQR()
            secret = model.setupSecret()
            step = .authenticator
            focused = .code
        case 1:
            error = "Rejected: min 14 characters, varied."
            focused = .password
        case 2:
            error = "Rejected: entries do not match."
            focused = .password
        default:
            error = "Setup state invalid. Relaunch Scytale."
        }
    }

    private func submitCode() {
        if model.setupCode() {
            error = nil
            forgetDisplayedSecrets()
            focused = nil
            step = .faceID
        } else {
            error = "Code rejected. Verify account entry and automatic time."
        }
    }

    /// Releases what was on screen. SwiftUI keeps its own copies of displayed values, so these are
    /// freed, not wiped (a documented limit, like the glyph caches in the Windows build).
    private func forgetDisplayedSecrets() {
        qr = nil
        secret = nil
        if step != .showRecovery { recoveryKey = nil }
    }
}

/// Draws the QR modules directly (no image file, no CoreImage).
struct QRCodeView: View {
    let width: Int
    let modules: [UInt8]

    var body: some View {
        Canvas { ctx, size in
            let quiet = 4
            let total = width + 2 * quiet
            let cell = size.width / CGFloat(total)
            ctx.fill(Path(CGRect(origin: .zero, size: size)), with: .color(.white))
            for y in 0..<width {
                for x in 0..<width where modules[y * width + x] == 1 {
                    let r = CGRect(x: CGFloat(x + quiet) * cell, y: CGFloat(y + quiet) * cell,
                                   width: cell + 0.5, height: cell + 0.5)
                    ctx.fill(Path(r), with: .color(.black))
                }
            }
        }
        .aspectRatio(1, contentMode: .fit)
    }
}
