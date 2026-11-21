import Foundation
import ScytaleCore
import Security
import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// App state and every action that touches the vault. Long operations (Argon2id, Face ID) run on
/// the core's own queue; the interface is disabled while `busy` is set.
@MainActor
final class AppModel: ObservableObject {
    enum Screen: Equatable {
        case boot
        case setup(recover: Bool)
        case login
        case home
        case fatal(String)
    }

    @Published var screen: Screen = .boot
    @Published var busy: String?
    @Published var counts: [InputField: Int] = [:]
    @Published var startNote: String?
    @Published var startNoteIsWarning = false
    @Published var captured = false
    @Published var shieldProtected = true
    @Published var summaryLines: [(String, Note.Kind)] = []
    @Published var items: [VaultItem] = []
    @Published var tagDefs: [VaultTag] = []
    @Published var itemTags: [Data: [UInt16]] = [:]
    @Published var tagFilter: UInt16?
    /// The file whose tag panel is open (press and hold).
    @Published var tagging: VaultItem?
    @Published var vaultNote: (String, Note.Kind)?
    @Published var originals: Originals?
    @Published var viewer: ViewerContent?
    /// The item whose encrypted screen is open (Decrypt / Destroy).
    @Published var selected: VaultItem?
    @Published var openMessage: MessageContent?
    @Published var showCamera = false
    @Published var overlay: HomeOverlay?

    /// Full-screen panels drawn inside the screen shield (never sheets).
    enum HomeOverlay: Equatable { case compose, courier, loginLog, configuration }

    private(set) var core: VaultCore?
    var auditKeyMissing = false
    private var lastActivity = Date()
    /// Auto-lock after this many minutes without a touch (1–5; the setting cannot exceed 5).
    /// The configuration in force (from the core's tamper-protected state).
    @Published var config = AppConfig.hardened
    var idleLimit: TimeInterval { TimeInterval(config.timeoutMin * 60) }

    func reloadConfig() {
        config = core?.run { $0.config() } ?? .hardened
    }

    /// 0 none; 1 "termination in 10"; 2 "termination in 5".
    @Published var terminationLevel: Int32 = 0

    // MARK: boot

    /// Result of the device integrity checks at launch (shown in Diagnostics).
    private(set) var integrity = Integrity.Report()

    func boot() {
        clearTemporaryDirectory()
        integrity = Integrity.check()
        guard integrity.ok else {
            screen = .fatal("Integrity check failed: \(integrity.problems.joined(separator: "; ")). Execution refused. Vault untouched.")
            return
        }
        let dir: URL
        do {
            dir = try VaultLocation.directory()
        } catch {
            screen = .fatal("Vault folder unavailable.")
            return
        }
        guard let core = VaultCore(directory: dir) else {
            screen = .fatal("Encryption core failed to start.")
            return
        }
        self.core = core
        var result: (note: Int32, ts: UInt64)?
        do {
            try KeychainSecret.auditKey.load { key in
                result = core.run { $0.start(auditKey: key) }
            }
        } catch {
            // The Keychain refused (for example the phone is locked). Do not treat that as a missing
            // key: that would push toward recovery and archive the audit log.
            screen = .fatal("Keychain unavailable. Unlock iPhone and relaunch.")
            return
        }
        let start = result ?? core.run { $0.start(auditKey: nil) }
        auditKeyMissing = start.note == 7
        if start.note == 0 {
            // No vault: remove anything left by an earlier install (Keychain items survive deletion).
            DeviceKey.vault.delete()
            KeychainSecret.deleteAll()
            screen = .setup(recover: false)
        } else {
            describeStart(start.note, start.ts)
            screen = .login
        }
        refreshCounts()
    }

    private func describeStart(_ note: Int32, _ ts: UInt64) {
        let when = ts > 0 ? " · \(Self.format(ts))" : ""
        startNoteIsWarning = false
        switch note {
        case 2: startNote = "Last session closed: inactivity\(when). Memory wiped."
        case 3: startNote = "Last session closed: app left\(when). Memory wiped."
        case 4: startNote = "Last session closed: device locked\(when). Memory wiped."
        case 5: startNote = "Last session terminated abnormally\(when)."
        case 8: startNote = "Last session closed: screen capture\(when)."
        case 6:
            startNote = "Lockout state integrity failure. Locked 15 min."
            startNoteIsWarning = true
        case 7:
            startNote = "Audit key missing. Login unavailable. Use recovery key."
            startNoteIsWarning = true
        default: startNote = nil
        }
    }

    static func format(_ ts: UInt64) -> String {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f.string(from: Date(timeIntervalSince1970: TimeInterval(ts)))
    }

    // MARK: input

    func type(_ field: InputField, _ text: String) {
        touch()
        guard busy == nil, let core else { return }
        core.run { _ = $0.push(field, text) }
        refreshCounts()
    }

    func backspace(_ field: InputField) {
        touch()
        guard busy == nil, let core else { return }
        core.run { $0.backspace(field) }
        refreshCounts()
    }

    /// Message shown under the field a paste went into (nil = none).
    @Published var pasteNote: (field: InputField, text: String, ok: Bool)?
    private var pastedChangeCount: Int?

    /// Replace a field's content with pasted text (from the system Paste button). Rejects, never
    /// truncates: a silently shortened password would differ from the one in the password manager.
    func paste(_ field: InputField, _ text: String?) {
        touch()
        guard busy == nil, let core else { return }
        guard let raw = text else { return }
        // Authenticator apps often copy codes as "123 456".
        let trimmed = field == .code
            ? String(raw.filter { !$0.isWhitespace })
            : raw.trimmingCharacters(in: .newlines)
        guard !trimmed.isEmpty else {
            pasteNote = (field, "Clipboard empty.", false)
            return
        }
        let accepted = core.run { c -> Bool in
            c.clear(field)
            let ok = c.push(field, trimmed)
            if !ok { c.clear(field) }
            return ok
        }
        pastedChangeCount = UIPasteboard.general.changeCount
        refreshCounts()
        if accepted {
            pasteNote = (field, field == .code ? "Code pasted." : "Pasted · \(counts[field, default: 0]) chars.", true)
            if field == .confirm || field == .code { clearClipboardIfOurs() }
        } else {
            pasteNote = (field, field == .code
                         ? "Rejected: clipboard holds no 6-digit code."
                         : "Rejected: control characters or > 256 bytes. Field cleared.", false)
        }
    }

    /// Copies the recovery key for a password manager: this iPhone's clipboard only (never
    /// Universal Clipboard) and erased by iOS after 2 minutes.
    func copyRecoveryKey(_ text: String) {
        copyLocalExpiring(text)
    }

    /// The authenticator setup key, without the grouping spaces so any authenticator accepts it.
    func copyAuthenticatorKey(_ text: String) {
        copyLocalExpiring(text.filter { !$0.isWhitespace })
    }

    /// This iPhone's clipboard only (never Universal Clipboard), erased by iOS after 2 minutes.
    private func copyLocalExpiring(_ text: String) {
        touch()
        UIPasteboard.general.setItems(
            [[UTType.plainText.identifier: text]],
            options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(120)]
        )
    }

    /// Empties the clipboard if it still holds what was pasted into Scytale (anything copied since
    /// is left alone). Universal Clipboard can carry it to other devices, and other apps can ask for it.
    func clearClipboardIfOurs() {
        guard let n = pastedChangeCount else { return }
        if UIPasteboard.general.changeCount == n {
            UIPasteboard.general.items = []
        }
        pastedChangeCount = nil
    }

    func clear(_ fields: InputField...) {
        guard let core else { return }
        core.run { c in fields.forEach { c.clear($0) } }
        refreshCounts()
    }

    func refreshCounts() {
        guard let core else { return }
        var c: [InputField: Int] = [:]
        core.run { vc in
            for f in [InputField.password, .confirm, .code, .recovery] { c[f] = vc.count(f) }
        }
        counts = c
        terminationLevel = core.run { $0.terminationLevel }
        config = core.run { $0.config() }
    }

    // MARK: activity, locking, capture

    func touch() { lastActivity = Date() }

    /// The vault is open (or the recovery key is on screen right after setup).
    var sessionOpen: Bool { screen == .home || isSetupAfterCommit }

    /// Something typed or generated before a session exists: login fields, or setup / recovery
    /// in progress (new authenticator secret, pepper, and during recovery the master key).
    var preSessionState: Bool {
        setupInProgress || counts.values.contains { $0 > 0 }
    }

    /// 5 minutes without a touch wipes everything, on every screen (as on Windows).
    func checkIdle() {
        guard busy == nil, sessionOpen || preSessionState else { return }
        if Date().timeIntervalSince(lastActivity) >= idleLimit {
            lock(.timeout)
        }
    }

    /// Leaving the app locks an open vault at once. Pre-session state survives a short trip
    /// (needed to read an authenticator on this same iPhone) and is wiped on return after 5 minutes.
    func didEnterBackground() {
        if sessionOpen && config.lockOnLeave {
            lock(.background)
        } else {
            backgroundedAt = Date()
        }
    }

    func didBecomeActive() {
        defer { backgroundedAt = nil }
        // Away longer than the session timeout: wipe (an open vault too, when lock-on-leave is off).
        if let t = backgroundedAt, Date().timeIntervalSince(t) >= idleLimit, sessionOpen || preSessionState {
            lock(.timeout)
            startNote = "Away > \(config.timeoutMin) min. Input wiped."
            return
        }
        touch()
    }

    private var backgroundedAt: Date?

    /// Set by the setup flow while the recovery key is on screen (the vault is already open).
    var isSetupAfterCommit = false

    /// Setup or recovery has generated secrets that are not committed yet.
    var setupInProgress = false

    /// Changes whenever pre-session state is wiped, so the setup screens restart visibly instead
    /// of showing a QR code or step whose secret no longer exists.
    @Published private(set) var setupEpoch = 0

    /// Bumped by every lock. A long operation started before a lock must not report success after it.
    private(set) var lockGeneration = 0

    func lock(_ reason: LockReason) {
        guard let core else { return }
        lockGeneration += 1
        clearClipboardIfOurs()
        pasteNote = nil
        // A decrypted file on screen is wiped by this lock: record it before the session ends.
        let wasDecrypted = viewer != nil
        // Runs after any long operation in progress has finished, never concurrently.
        core.queue.async {
            if wasDecrypted { core.auditReencrypted(automatic: true) }
            core.lock(reason)
        }
        isSetupAfterCommit = false
        setupInProgress = false
        setupEpoch += 1
        summaryLines = []
        viewer = nil          // decrypted bytes are wiped when the view releases them
        selected = nil
        tagging = nil
        tagFilter = nil
        tagDefs = []
        itemTags = [:]
        openMessage = nil
        overlay = nil
        showCamera = false
        items = []
        originals = nil
        vaultNote = nil
        if case .fatal = screen { return }
        if case .boot = screen { return }
        let hasVault = FileManager.default.fileExists(atPath: core.directory.appendingPathComponent("vault.hdr").path)
        screen = hasVault ? .login : .setup(recover: false)
        switch reason {
        case .timeout: startNote = "Locked: inactivity (\(config.timeoutMin) min). Memory wiped."
        case .background: startNote = "Locked: app left. Memory wiped."
        case .deviceLock: startNote = "Locked: device locked. Memory wiped."
        case .capture: startNote = "Locked: screen capture detected. Memory wiped."
        case .logout: startNote = "Locked. Memory wiped."
        }
        startNoteIsWarning = reason == .capture
        DispatchQueue.main.async { self.refreshCounts() }
    }

    func captureChanged(_ isCaptured: Bool) {
        captured = isCaptured
        if isCaptured && (sessionOpen || preSessionState) {
            lock(.capture)
        }
    }

    /// Any screenshot ends the session (and wipes any input), returning to the login screen.
    /// The shield keeps vault content out of the image; if the shield is unavailable on this iOS
    /// version the notice says "detected" rather than "blocked".
    func screenshotTaken() {
        guard let core else { return }
        if case .fatal = screen { return }
        core.queue.async { core.auditScreenshot() }
        if !config.screenshotLocks && sessionOpen {
            // Configured "record only": logged, session kept.
            vaultNote = (shieldProtected ? "Screenshot blocked. Recorded in the log." : "Screenshot detected. Recorded in the log.", .warn)
            return
        }
        lock(.logout)
        show(shieldProtected ? "Screenshot blocked. Session terminated." : "Screenshot detected. Session terminated.",
             warn: true)
    }

    // MARK: login

    func unlock() {
        guard let core, busy == nil else { return }
        clearClipboardIfOurs()
        pasteNote = nil
        let ready = counts[.password, default: 0] > 0 && (!config.requireTotp || counts[.code, default: 0] == 6)
        guard ready else {
            show("Password and 6-digit code required.", warn: true)
            return
        }
        let remaining = core.run { $0.lockedRemaining }
        if remaining > 0 {
            clear(.password, .code)
            show("Locked. Retry in \(remaining) s.", warn: true)
            return
        }
        guard let wrapped = core.run({ $0.wrappedPepper() }) else {
            show("Vault header unreadable.", warn: true)
            return
        }
        busy = "Verifying…"
        let generation = lockGeneration
        core.queue.async {
            var outcome: (code: Int32, aux: UInt64)?
            var failure: DeviceKey.Failure?
            do {
                try DeviceKey.vault.unwrap(wrapped, reason: "Unlock Scytale") { pepper in
                    outcome = core.login(pepper: pepper)
                }
            } catch let f as DeviceKey.Failure {
                if f == .notRecognised {
                    outcome = core.login(pepper: nil)  // counts as a failed attempt
                } else {
                    failure = f
                }
            } catch {
                failure = .failed(-1)
            }
            if outcome?.code == 7 {
                // Vault terminated: the core has destroyed the files; destroy the hardware key
                // and Keychain items before anything else can run.
                DeviceKey.vault.delete()
                KeychainSecret.deleteAll()
            }
            let summary = core.summary()
            DispatchQueue.main.async {
                self.busy = nil
                if outcome?.code == 7 {
                    LoginNotifier.shared.post(.terminated)
                    self.resetAfterDestruction("VAULT TERMINATED. 15 failed password attempts. Device key, items and audit log destroyed.", warn: true)
                    return
                }
                // A lock happened meanwhile (it ran on the core queue after this login, so the
                // session is already closed): do not show the vault.
                guard generation == self.lockGeneration else {
                    self.refreshCounts()
                    return
                }
                self.finishLogin(outcome, failure, summary)
            }
        }
    }

    private func finishLogin(_ outcome: (code: Int32, aux: UInt64)?, _ failure: DeviceKey.Failure?, _ s: ScySummary) {
        refreshCounts()
        if let failure {
            show(Self.message(for: failure), warn: true)
            return
        }
        guard let outcome else { return }
        switch outcome.code {
        case 0, 1, 2:
            if config.notify { LoginNotifier.shared.post(outcome.code == 0 ? .succeeded : .failed) }
        default:
            break
        }
        switch outcome.code {
        case 0:
            LoginNotifier.shared.requestPermissionIfNeeded()
            enterHome(s)
        case 1: show("Authentication failed. \(outcome.aux) attempt(s) before lockout.", warn: true)
        case 2: show("Authentication failed. Locked \(outcome.aux) s.", warn: true)
        case 3: show("Locked. Retry in \(outcome.aux) s.", warn: true)
        case 4: show("Password and 6-digit code required.", warn: true)
        case 5: show("Audit key missing. Use recovery key.", warn: true)
        case 6: show("Index integrity failure. Vault not opened.", warn: true)
        default: show("Authentication failed.", warn: true)
        }
    }

    func enterHome(_ s: ScySummary) {
        var lines: [(String, Note.Kind)] = []
        if s.last_login > 0 {
            lines.append(("Last login · \(Self.format(s.last_login)) · \(s.fails_since) failed since",
                          s.fails_since > 0 ? .warn : .info))
        }
        if s.chain == 1 { lines.append(("AUDIT LOG TAMPERED · entry \(s.chain_at)", .error)) }
        if s.chain == 2 { lines.append(("AUDIT LOG TRUNCATED", .error)) }
        if s.dropped > 0 { lines.append(("\(s.dropped) orphaned index entr\(s.dropped == 1 ? "y" : "ies") removed", .warn)) }
        if s.shredded > 0 { lines.append(("\(s.shredded) interrupted write(s) erased", .warn)) }
        summaryLines = lines
        startNote = nil
        vaultNote = nil
        touch()
        reloadItems()
        screen = .home
    }

    func show(_ text: String, warn: Bool) {
        startNote = text
        startNoteIsWarning = warn
    }

    static func message(for f: DeviceKey.Failure) -> String {
        switch f {
        case .cancelled: return "Face ID cancelled. No attempt used."
        case .notRecognised: return "Face ID: no match."
        case .invalidated:
            return "Device key disabled (Face ID enrolment changed) or missing. Use recovery key."
        case .lockedOut:
            return "Face ID locked by iOS. Lock and unlock iPhone with passcode, then retry."
        case .biometryOff:
            return "Face ID off for Scytale. Settings › Face ID & Passcode › Other Apps."
        case .noPasscode: return "Device passcode required."
        case .unavailable: return "Secure Enclave unavailable."
        case .failed(let code): return "Secure Enclave error \(code)."
        }
    }

    // MARK: panic wipe

    func panicWipe() {
        guard let core, busy == nil else { return }
        busy = "Destroying vault…"
        core.queue.async {
            // Hardware key first: the stored pepper becomes undecryptable on this and every device.
            DeviceKey.vault.delete()
            KeychainSecret.deleteAll()
            let failed = core.panicWipe()
            DispatchQueue.main.async {
                self.busy = nil
                self.resetAfterDestruction(failed == 0
                    ? "Vault destroyed. Device key, items and audit log erased."
                    : "Vault destroyed. \(failed) file(s) not overwritten; their keys are erased.",
                    warn: failed != 0)
            }
        }
    }

    /// After a panic wipe or a termination: drop every reference and start again at setup.
    func resetAfterDestruction(_ message: String, warn: Bool) {
        lockGeneration += 1
        core = nil
        summaryLines = []
        viewer = nil
        selected = nil
        openMessage = nil
        showCamera = false
        overlay = nil
        items = []
        originals = nil
        vaultNote = nil
        isSetupAfterCommit = false
        setupInProgress = false
        setupEpoch += 1
        boot()
        show(message, warn: warn)
    }
}
