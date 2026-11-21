import SwiftUI
import UIKit

// MARK: - Message editor

/// A text view that cannot leak what is typed: no copy / cut / share / look-up / translate,
/// no dragging text out, no autocorrect or prediction learning, no Writing Tools
/// (Apple Intelligence), no data detectors. Pasting in is allowed.
final class SealedUITextView: UITextView {
    override func canPerformAction(_ action: Selector, withSender sender: Any?) -> Bool {
        switch action {
        case #selector(paste(_:)), #selector(select(_:)), #selector(selectAll(_:)), #selector(delete(_:)):
            return super.canPerformAction(action, withSender: sender)
        default:
            return false
        }
    }

    override func buildMenu(with builder: UIMenuBuilder) {
        super.buildMenu(with: builder)
        for m in [UIMenu.Identifier.share, .lookup, .learn, .replace, .find, .format, .speech] {
            builder.remove(menu: m)
        }
    }
}

struct SealedTextEditor: UIViewRepresentable {
    @Binding var text: String
    let onEdit: () -> Void

    func makeUIView(context: Context) -> SealedUITextView {
        let v = SealedUITextView()
        v.delegate = context.coordinator
        v.backgroundColor = UIColor(Theme.panel)
        v.textColor = UIColor(Theme.text)
        v.font = UIFont.monospacedSystemFont(ofSize: 15, weight: .regular)
        v.autocorrectionType = .no
        v.spellCheckingType = .no
        v.autocapitalizationType = .sentences
        v.smartQuotesType = .no
        v.smartDashesType = .no
        v.smartInsertDeleteType = .no
        v.inlinePredictionType = .no
        v.dataDetectorTypes = []
        v.keyboardAppearance = .dark
        v.allowsEditingTextAttributes = false
        v.isFindInteractionEnabled = false
        v.textDragInteraction?.isEnabled = false
        if #available(iOS 18.0, *) {
            v.writingToolsBehavior = .none
        }
        v.textContainerInset = UIEdgeInsets(top: 12, left: 8, bottom: 12, right: 8)
        v.layer.cornerRadius = 8
        return v
    }

    func updateUIView(_ v: SealedUITextView, context: Context) {
        if v.text != text { v.text = text }
    }

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    final class Coordinator: NSObject, UITextViewDelegate {
        var parent: SealedTextEditor
        init(_ p: SealedTextEditor) { parent = p }
        func textViewDidChange(_ v: UITextView) {
            parent.text = v.text
            parent.onEdit()
        }
    }
}

struct MessageComposer: View {
    @ObservedObject var model: AppModel
    @State private var text = ""

    private var bytes: Int { text.utf8.count }

    var body: some View {
        Panel(title: "NEW MESSAGE", close: { discard() }) {
            Note(text: "Single read · Face ID to open · destroyed on open", icon: "flame.fill")
            SealedTextEditor(text: $text) { model.touch() }
                .frame(minHeight: 220)
            HStack {
                Text("\(bytes) / 16384 bytes").font(Theme.small)
                    .foregroundStyle(bytes > 16384 ? Theme.error : Theme.dim)
                Spacer()
            }
            PrimaryButton(title: "Seal message", enabled: bytes > 0 && bytes <= 16384 && model.busy == nil) {
                if model.sealMessage(text) {
                    text = ""
                    model.overlay = nil
                }
            }
            Button("Discard") { discard() }.font(Theme.small).foregroundStyle(Theme.dim)
        }
    }

    private func discard() {
        text = ""
        model.overlay = nil
        model.touch()
    }
}

// MARK: - Message reader

struct MessageReader: View {
    @ObservedObject var model: AppModel
    let message: MessageContent

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { ctx in
            let left = max(0, message.lifetime - ctx.date.timeIntervalSince(message.opened))
            Panel(title: "MESSAGE", close: { model.closeMessage(expired: false) }) {
                Note(text: "Destroyed at source · screen clears in \(Int(left) / 60):\(String(format: "%02d", Int(left) % 60))", kind: .warn, icon: "timer")
                ScrollView {
                    Text(message.text)
                        .font(Theme.mono)
                        .foregroundStyle(Theme.text)
                        .textSelection(.disabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                }
                .frame(maxHeight: .infinity)
                .background(RoundedRectangle(cornerRadius: 8).fill(Theme.panel))
                PrimaryButton(title: "Close and destroy") { model.closeMessage(expired: false) }
            }
            .onChange(of: left <= 0) { _, expired in
                if expired { model.closeMessage(expired: true) }
            }
        }
    }
}

// MARK: - Login log

struct LoginLogView: View {
    @ObservedObject var model: AppModel
    @State private var allEvents = false
    @State private var log: (entries: [VaultCore.AuditEntry], chain: Int32, chainAt: UInt64) = ([], -1, 0)

    static let loginEvents: Set<String> = [
        "LOGIN_OK", "LOGIN_FAIL", "LOCKOUT", "LOGOUT", "TIMEOUT", "BACKGROUND", "DEVICE_LOCK", "CAPTURE",
        "ABORTED", "REAUTH_FAIL", "SETUP", "RECOVERY", "RECOV_FAIL", "STATE_RESET", "PW_CHANGE", "SCREENSHOT", "CONFIG_CHANGE",
    ]

    var body: some View {
        Panel(title: "LOGIN LOG", close: { model.overlay = nil; model.touch() }) {
            switch log.chain {
            case 0: Note(text: "Integrity verified · HMAC chain intact", kind: .ok, icon: "checkmark.seal.fill")
            case 1: Note(text: "INTEGRITY FAILURE · tampered at entry \(log.chainAt)", kind: .error)
            case 2: Note(text: "INTEGRITY FAILURE · log truncated", kind: .error)
            default: Note(text: "Log unreadable.", kind: .error)
            }
            Picker("", selection: $allEvents) {
                Text("Logins").tag(false)
                Text("All events").tag(true)
            }
            .pickerStyle(.segmented)
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(shown) { e in
                        HStack(alignment: .top, spacing: 10) {
                            Circle().fill(Self.color(e)).frame(width: 8, height: 8).padding(.top, 6)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(Self.describe(e)).font(Theme.small).foregroundStyle(Theme.text)
                                Text("#\(e.id)  ·  \(AppModel.format(e.ts))")
                                    .font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.dim)
                            }
                        }
                        .padding(.vertical, 8)
                        Divider().overlay(Theme.line)
                    }
                }
            }
            .frame(maxHeight: .infinity)
        }
        .onAppear { log = model.auditEntries() }
    }

    private var shown: [VaultCore.AuditEntry] {
        log.entries.reversed().filter { allEvents || Self.loginEvents.contains($0.event) }
    }

    static func color(_ e: VaultCore.AuditEntry) -> Color {
        switch e.event {
        case "LOGIN_OK", "SETUP", "RECOVERY", "PW_CHANGE": return Theme.green
        case "LOGIN_FAIL", "REAUTH_FAIL", "RECOV_FAIL", "LOCKOUT", "STATE_RESET", "SCREENSHOT", "CAPTURE", "ABORTED", "FILE_DEC_FAIL", "COURIER_REJECT":
            return Theme.error
        default: return Theme.dim
        }
    }

    static func duration(_ s: UInt64) -> String {
        String(format: "%02d:%02d:%02d", s / 3600, s % 3600 / 60, s % 60)
    }

    static func describe(_ e: VaultCore.AuditEntry) -> String {
        switch e.event {
        case "LOGIN_OK": return "Login succeeded"
        case "LOGIN_FAIL":
            switch e.extra {
            case 1: return "Login failed: wrong password"
            case 3: return "Login failed: wrong authenticator code"
            case 4: return "Login failed: Face ID did not match"
            case 2: return "Login refused: vault index failed its integrity check"
            default: return "Login failed"
            }
        case "LOCKOUT": return "Locked out for \(e.extra) s"
        case "REAUTH_FAIL": return e.extra == 1 ? "Password check failed: wrong password" : "Face ID did not match (opening an item)"
        case "LOGOUT": return "Locked (session \(duration(e.extra)))"
        case "TIMEOUT": return "Auto-locked after inactivity (session \(duration(e.extra)))"
        case "BACKGROUND": return "Locked: left the app (session \(duration(e.extra)))"
        case "DEVICE_LOCK": return "Locked: iPhone locked (session \(duration(e.extra)))"
        case "CAPTURE": return "Locked: screen recording or mirroring (session \(duration(e.extra)))"
        case "ABORTED": return "Session ended unexpectedly (app closed or crashed)"
        case "SETUP": return "Vault created"
        case "RECOVERY": return "Recovered with the recovery key"
        case "RECOV_FAIL": return "Wrong recovery key entered"
        case "STATE_RESET": return "Lockout state failed its integrity check (locked 15 min)"
        case "PW_CHANGE": return "Admin password changed"
        case "SCREENSHOT": return "Screenshot taken while unlocked"
        case "FILE_ENC": return "File encrypted"
        case "PHOTO_ENC": return "Photo encrypted"
        case "FILE_DEC": return "File decrypted"
        case "FILE_REENC": return e.extra == 1 ? "File re-encrypted (automatic: vault locked)" : "File re-encrypted"
        case "FILE_DEC_FAIL": return "Decryption refused: integrity failure"
        case "FILE_PURGE": return "File destroyed"
        case "MSG_ENC": return "Message sealed"
        case "MSG_DEC": return "Message read (destroyed)"
        case "MSG_KILL": return "Message closed"
        case "MSG_EXPIRE": return "Message expired"
        case "MSG_PURGE": return "Message destroyed unread"
        case "COURIER_BUNDLE": return "Courier: key bundle exported"
        case "COURIER_PAIR": return "Courier: key bundle imported"
        case "COURIER_VERIFY": return "Courier: pairing verified (safety number)"
        case "COURIER_UNPAIR": return "Courier: unpaired"
        case "COURIER_SEND": return e.extra == 1 ? "Courier: message sealed (destroy on receipt)" : "Courier: message sealed"
        case "COURIER_RECV": return e.extra == 1 ? "Courier: message received (destroyed on receipt)" : "Courier: message received (kept)"
        case "COURIER_REJECT": return "Courier: rejected (\(AppModel.courierMessage(Int32(e.extra))))"
        case "CONFIG_CHANGE": return "Configuration changed"
        default: return e.event
        }
    }
}

// MARK: - Configuration

/// Scytale's configuration. Opening it requires Face ID; the values live in the core's
/// tamper-protected state. "Hardened defaults" on = the shipped behaviour, options ignored.
struct ConfigurationView: View {
    @ObservedObject var model: AppModel
    @State private var unlocked = false
    @State private var draft = AppConfig.hardened
    @State private var saved = AppConfig.hardened
    @State private var note: (String, Note.Kind)?

    var body: some View {
        Panel(title: "CONFIGURATION", close: close) {
            if !unlocked {
                Note(text: "Changes to security settings require Face ID.")
                PrimaryButton(title: "Unlock with Face ID", enabled: model.busy == nil) { unlock() }
                if let note { Note(text: note.0, kind: note.1) }
                fixedSection
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        Toggle(isOn: Binding(get: { !draft.custom }, set: { draft.custom = !$0 })) {
                            label("Hardened defaults", "On: Scytale behaves as shipped and the options below are ignored.")
                        }
                        Group {
                            section("SESSION")
                            Toggle(isOn: $draft.lockOnLeave) {
                                label("Lock when leaving the app", "Off: the vault stays open while away, until the session timeout.")
                            }
                            picker("Session timeout", AppConfig.timeouts, $draft.timeoutMin) { "\($0) min" }
                            section("LOGIN")
                            Toggle(isOn: $draft.requireTotp) {
                                label("Always require 2FA code", "Off: password + Face ID only.")
                            }
                            Toggle(isOn: $draft.notify) {
                                label("Login notifications", "A notification for every login success and failure.")
                            }
                            section("ACCESS")
                            Toggle(isOn: $draft.faceIDEachOpen) {
                                label("Face ID for every open", "Off: Face ID once per session, then items open directly.")
                            }
                            Toggle(isOn: $draft.screenshotLocks) {
                                label("Screenshot ends the session", "Off: the screenshot is blocked and logged; the session stays open.")
                            }
                            picker("Message display time", AppConfig.messageTimes, $draft.messageMin) { "\($0) min" }
                            section("IMPORT")
                            Picker("", selection: $draft.originals) {
                                Text("Ask").tag(0)
                                Text("Delete").tag(1)
                                Text("Keep").tag(2)
                            }
                            .pickerStyle(.segmented)
                            label("Originals after import", "Delete: always delete originals after a verified import. Keep: never ask.")
                        }
                        .disabled(!draft.custom)
                        .opacity(draft.custom ? 1 : 0.45)

                        if draft.custom && (!draft.lockOnLeave || !draft.requireTotp || !draft.faceIDEachOpen || !draft.screenshotLocks) {
                            Note(text: "Weaker than hardened defaults: \(weakened)", kind: .warn)
                        }
                        PrimaryButton(title: "Apply", enabled: draft != saved && model.busy == nil) { apply() }
                        if let note { Note(text: note.0, kind: note.1) }
                        fixedSection
                    }
                }
            }
        }
        .tint(Theme.green)
        .onDisappear { model.configEnd() }
    }

    /// Protections that no setting can turn off.
    private var fixedSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            section("ALWAYS ON")
            Note(text: "iPhone lock: vault locks", icon: "lock.fill")
            Note(text: "Screen recording or mirroring: vault locks", icon: "lock.fill")
            Note(text: "15 failed passwords: vault terminated", icon: "lock.fill")
            Note(text: "Lockouts after 3 failed attempts, doubling to 1 h", icon: "lock.fill")
        }
    }

    private var weakened: String {
        var w: [String] = []
        if !draft.lockOnLeave { w.append("vault stays open when leaving the app") }
        if !draft.requireTotp { w.append("no 2FA code") }
        if !draft.faceIDEachOpen { w.append("Face ID once per session") }
        if !draft.screenshotLocks { w.append("screenshots do not end the session") }
        return w.joined(separator: " · ")
    }

    private func section(_ t: String) -> some View {
        Text(t).font(Theme.small.weight(.bold)).foregroundStyle(Theme.dim).padding(.top, 6)
    }

    private func label(_ title: String, _ detail: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(Theme.small.weight(.semibold)).foregroundStyle(Theme.text)
            Text(detail).font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.dim)
        }
    }

    private func picker(_ title: String, _ values: [Int], _ value: Binding<Int>, _ text: @escaping (Int) -> String) -> some View {
        HStack {
            Text(title).font(Theme.small.weight(.semibold)).foregroundStyle(Theme.text)
            Spacer()
            Picker("", selection: value) {
                ForEach(values, id: \.self) { Text(text($0)).tag($0) }
            }
            .pickerStyle(.menu)
        }
    }

    private func unlock() {
        note = nil
        model.configUnlock { ok, message in
            if ok {
                saved = model.configStored()
                draft = saved
                unlocked = true
            } else {
                note = (message ?? "Not unlocked.", .error)
            }
        }
    }

    private func apply() {
        if model.configApply(draft) {
            saved = draft
            note = ("Applied.", .ok)
        } else {
            note = ("Not applied.", .error)
        }
    }

    private func close() {
        model.configEnd()
        model.overlay = nil
        model.touch()
    }
}

// MARK: - Shared panel chrome

struct Panel<Content: View>: View {
    let title: String
    let close: () -> Void
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text(title).font(Theme.title).foregroundStyle(Theme.green)
                Spacer()
                Button(action: close) { Image(systemName: "xmark").font(.title3.weight(.semibold)) }
                    .foregroundStyle(Theme.green)
            }
            content()
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background(Theme.background)
    }
}

// MARK: - Encrypted item

/// The item at rest: details, Decrypt (Face ID), Destroy. Decrypting opens the viewer, whose only
/// exit is Re-encrypt.
struct EncryptedItemView: View {
    @ObservedObject var model: AppModel
    let item: VaultItem
    @State private var confirmDestroy = false

    var body: some View {
        Panel(title: "ENCRYPTED", close: { model.selected = nil; model.vaultNote = nil; model.touch() }) {
            HStack(spacing: 12) {
                Image(systemName: "lock.fill").font(.title2).foregroundStyle(Theme.green)
                VStack(alignment: .leading, spacing: 4) {
                    Text(item.name)
                        .font(Theme.mono.weight(.semibold))
                        .foregroundStyle(Theme.text)
                        .lineLimit(2)
                        .truncationMode(.middle)
                    Text("\(HomeView.size(item.size)) · \(AppModel.format(item.created))")
                        .font(Theme.small).foregroundStyle(Theme.dim)
                }
            }
            .padding(.vertical, 8)
            PrimaryButton(title: "Decrypt", enabled: model.busy == nil) { model.open(item) }
            if let note = model.vaultNote { Note(text: note.0, kind: note.1) }
            if let busy = model.busy {
                HStack(spacing: 10) { ProgressView().tint(Theme.green); Note(text: busy) }
            }
            Spacer().frame(height: 12)
            if confirmDestroy {
                Note(text: "Destroy permanently? Key erased. Irreversible.", kind: .error)
                HStack {
                    Button("Cancel") { confirmDestroy = false }.foregroundStyle(Theme.dim)
                    Spacer()
                    Button("Destroy") { model.purge(item) }.foregroundStyle(Theme.error).bold()
                }
                .font(Theme.mono)
            } else {
                Button("Destroy…") { confirmDestroy = true; model.touch() }
                    .font(Theme.small).foregroundStyle(Theme.error)
            }
        }
        .onAppear { model.vaultNote = nil }
    }
}
