import Foundation
import ScytaleCore
import Security

extension AppModel {
    func recoverCheck() -> Bool {
        guard let core else { return false }
        let ok = core.run { $0.recoverCheck() }
        if ok { setupInProgress = true }
        refreshCounts()
        return ok
    }

    /// 0 ok, 1 weak, 2 mismatch, 3 wrong state.
    func setupBegin(recover: Bool) -> Int32 {
        guard let core else { return 3 }
        clearClipboardIfOurs()
        pasteNote = nil
        let r = core.run { $0.setupBegin(recover: recover) }
        if r == 0 { setupInProgress = true }
        refreshCounts()
        return r
    }

    func setupQR() -> (width: Int, modules: [UInt8])? { core?.run { $0.setupQR() } }
    func setupSecret() -> String? { core?.run { $0.setupSecret() } }

    func setupCode() -> Bool {
        guard let core else { return false }
        let ok = core.run { $0.setupCode() }
        refreshCounts()
        return ok
    }

    /// Creates the Secure Enclave key, wraps the new pepper, proves the Face ID round trip, then
    /// commits the vault. Calls `done` with nil on success or a message.
    func setupCreateKey(recover: Bool, done: @escaping (String?) -> Void) {
        guard let core, busy == nil else { return }
        busy = recover ? "Re-keying vault…" : "Creating vault…"
        let generation = lockGeneration
        let needAuditKey = !recover || auditKeyMissing
        core.queue.async {
            var message: String?
            do {
                try DeviceKey.vault.create()
                guard let wrapped = try core.withSetupPepper({ try DeviceKey.vault.wrap($0) }) else {
                    throw DeviceKey.Failure.failed(-2)
                }
                var verified = false
                try DeviceKey.vault.unwrap(wrapped, reason: "Confirm Face ID for Scytale's key") {
                    verified = core.setupPepperVerify($0)
                }
                guard verified else { throw DeviceKey.Failure.failed(-3) }

                var auditKey = [UInt8](repeating: 0, count: 32)
                defer { wipe(&auditKey) }
                if needAuditKey {
                    guard SecRandomCopyBytes(kSecRandomDefault, 32, &auditKey) == errSecSuccess else {
                        throw DeviceKey.Failure.failed(-4)
                    }
                    try auditKey.withUnsafeBytes { try KeychainSecret.auditKey.store($0) }
                }
                let rc = needAuditKey
                    ? auditKey.withUnsafeBytes { core.setupCommit(wrapped: wrapped, auditKey: $0) }
                    : core.setupCommit(wrapped: wrapped, auditKey: nil)
                if rc != 0 {
                    if needAuditKey { KeychainSecret.auditKey.delete() }
                    if !recover { DeviceKey.vault.delete() }
                    message = "Could not \(recover ? "re-key" : "create") the vault (error \(rc))."
                }
            } catch let f as DeviceKey.Failure {
                if !recover { DeviceKey.vault.delete() }
                message = Self.message(for: f)
            } catch let e as KeychainError {
                if !recover { DeviceKey.vault.delete() }
                message = "Keychain error \(e.status)."
            } catch {
                if !recover { DeviceKey.vault.delete() }
                message = "Unexpected error."
            }
            DispatchQueue.main.async {
                self.busy = nil
                self.refreshCounts()
                guard generation == self.lockGeneration else { return }
                if message == nil {
                    self.auditKeyMissing = false
                    self.setupInProgress = false
                    self.isSetupAfterCommit = true
                    self.touch()
                }
                done(message)
            }
        }
    }

    func setupRecoveryKey() -> String? { core?.run { $0.setupRecoveryKey() } }

    /// The recovery key has been saved: forget it and open the vault screen.
    func setupDone() {
        guard let core else { return }
        let s = core.run { c -> ScySummary in
            c.setupFinish()
            return c.summary()
        }
        isSetupAfterCommit = false
        enterHome(s)
    }

    /// Leave setup / recovery before anything was committed.
    func setupAbandon() {
        guard let core else { return }
        core.run { $0.setupFinish() }
        setupInProgress = false
        refreshCounts()
        screen = core.run({ $0.phase }) == 0 ? .setup(recover: false) : .login
    }
}
