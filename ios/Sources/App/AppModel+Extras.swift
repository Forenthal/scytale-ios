import Foundation
import ScytaleCore

/// A message that was opened once. Its ciphertext is already destroyed; it is wiped from the
/// screen after 5 minutes or when closed.
struct MessageContent: Identifiable {
    let id = UUID()
    let text: String
    let opened = Date()
    /// Seconds on screen (configuration: message display time).
    var lifetime: TimeInterval = 300
}

extension AppModel {
    // MARK: messages

    func sealMessage(_ text: String) -> Bool {
        guard let core, busy == nil else { return false }
        let ok = core.run { $0.sealMessage(text) }
        reloadItems()
        vaultNote = ok ? ("Message sealed · single read", .ok)
                       : ("Seal failed: empty or > 16 KiB.", .error)
        touch()
        return ok
    }

    func closeMessage(expired: Bool) {
        guard openMessage != nil else { return }
        openMessage = nil
        if let core {
            core.queue.async { expired ? core.auditMessageExpired() : core.auditMessageClosed() }
        }
        vaultNote = (expired ? "Message expired · destroyed" : "Message destroyed", .ok)
        touch()
    }

    // MARK: configuration

    /// Face ID (always, whatever the configuration), then unlock the configuration screen.
    func configUnlock(done: @escaping (Bool, String?) -> Void) {
        guard let core, busy == nil, let wrapped = core.run({ $0.wrappedPepper() }) else { return }
        busy = "Verifying…"
        let generation = lockGeneration
        core.queue.async {
            var r: (code: Int32, aux: UInt64)?
            var failure: DeviceKey.Failure?
            do {
                try DeviceKey.vault.unwrap(wrapped, reason: "Change Scytale's configuration") { p in
                    r = core.reauth(pepper: p)
                }
            } catch let f as DeviceKey.Failure {
                if f == .notRecognised { r = core.reauth(pepper: nil) } else { failure = f }
            } catch {
                failure = .failed(-1)
            }
            let ok = r?.code == 0 && core.configBegin()
            DispatchQueue.main.async {
                self.busy = nil
                guard generation == self.lockGeneration else { return }
                self.touch()
                if let failure { done(false, Self.message(for: failure)); return }
                if r?.code == 2 {
                    self.lock(.logout)
                    self.show("Locked: repeated Face ID failures.", warn: true)
                    return
                }
                done(ok, ok ? nil : "Face ID: no match.")
            }
        }
    }

    func configStored() -> AppConfig { core?.run { $0.config(stored: true) } ?? .hardened }

    func configApply(_ c: AppConfig) -> Bool {
        touch()
        let ok = core?.run { $0.configSet(c) } ?? false
        reloadConfig()
        return ok
    }

    func configEnd() { core?.run { $0.configEnd() } }

    // MARK: login log

    func auditEntries() -> (entries: [VaultCore.AuditEntry], chain: Int32, chainAt: UInt64) {
        core?.run { $0.auditEntries() } ?? ([], -1, 0)
    }

    // MARK: diagnostics

    /// Times Argon2id with the parameters new and re-keyed vaults use. Blocks: call off main.
    nonisolated static func kdfBenchmark() -> (ms: UInt64, m: UInt32, t: UInt32, p: UInt32) {
        var m: UInt32 = 0, t: UInt32 = 0, p: UInt32 = 0
        scytale_kdf_default(&m, &t, &p)
        return (scytale_kdf_benchmark(m, t, p), m, t, p)
    }
}
