import Foundation
import UIKit
import UniformTypeIdentifiers

extension AppModel {
    static func courierMessage(_ code: Int32) -> String {
        switch code {
        case 1: return "Not a Scytale courier message."
        case 2: return "Signature invalid: forged or altered. Rejected."
        case 3: return "Not from the paired device, or not addressed to this one. Rejected."
        case 4: return "Pairing not verified. Compare safety numbers first."
        case 5: return "No device paired."
        case 6: return "Already opened. Its one-time key is destroyed; no copy can ever be read."
        case 7: return "Decryption failed: altered or corrupt. Rejected."
        case 8: return "No one-time keys left. Import a new key bundle from the other device."
        case 9: return "Message empty or over 16 KiB."
        case 10: return "Another device is already paired. Unpair first."
        case 11: return "That is this device's own key bundle."
        case 12: return "Photos and other images cannot be sent."
        case 13: return "File empty or over 12 MiB."
        case 101: return "Vault locked."
        case 102: return "Courier state could not be read."
        case 103: return "Could not save."
        case -4, 104: return "Re-authentication required."
        case 105: return "Only files can be sent."
        case 106: return "File failed its integrity check. Not sent."
        default: return "Courier error \(code)."
        }
    }

    func courierStatus() -> CourierStatus? { core?.run { $0.courierStatus() } }

    /// Writes this device's signed key bundle to a temporary file for sharing (public keys only).
    func courierExportBundleFile() -> URL? {
        guard let data = core?.run({ $0.courierExportBundle() }) else { return nil }
        touch()
        return Self.writeOutgoing(data, name: "Scytale key bundle \(Self.fileStamp()).scykey")
    }

    func courierImportBundle(_ data: Data) -> (ok: Bool, message: String) {
        guard let core else { return (false, "Vault locked.") }
        touch()
        let r = core.run { $0.courierImportBundle(data) }
        if r.code == 0 { return (true, "Key bundle accepted.") }
        return (false, r.code == 1 ? "Not a Scytale key bundle." : Self.courierMessage(r.code))
    }

    func courierSafety() -> String? { core?.run { $0.courierSafety() } }
    func courierVerify() -> Bool { touch(); return core?.run { $0.courierVerify() } ?? false }
    func courierUnpair() -> Bool { touch(); return core?.run { $0.courierUnpair() } ?? false }

    enum SealedOutput { case file(URL), text(String), failed(String) }

    /// Copy an encrypted text block (ciphertext only): this iPhone's clipboard, cleared after 10 min.
    func copyCiphertext(_ text: String) {
        touch()
        UIPasteboard.general.setItems(
            [[UTType.plainText.identifier: text]],
            options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(600)]
        )
    }

    /// Seal a message for the paired device: a .scy file (temporary, for Save to Files or the share
    /// sheet) or the raw encrypted text block for an email body.
    func courierSend(_ text: String, burn: Bool, asFile: Bool) -> SealedOutput {
        guard let core else { return .failed("Vault locked.") }
        touch()
        let r = core.run { $0.courierSend(text, burn: burn, armored: !asFile) }
        guard r.code == 0, let out = r.out else { return .failed(Self.courierMessage(r.code)) }
        if asFile {
            guard let url = Self.writeOutgoing(out, name: "Scytale message \(Self.fileStamp()).scy") else {
                return .failed("Could not write the file.")
            }
            return .file(url)
        }
        return .text(String(decoding: out, as: UTF8.self))
    }

    /// Face ID (unless configured once per session), then `work` on the core queue. `done` gets
    /// the work's result, or a message if re-authentication failed. Repeated Face ID failures
    /// lock the vault and `done` is not called.
    private func courierReauth<T>(_ reason: String, work: @escaping (VaultCore) -> T,
                                  done: @escaping (T?, String?) -> Void) {
        guard let core, busy == nil, let wrapped = core.run({ $0.wrappedPepper() }) else { return }
        busy = "Verifying…"
        let generation = lockGeneration
        let needFaceID = core.run { $0.reauthRequired }
        core.queue.async {
            var reauth: (code: Int32, aux: UInt64)?
            var failure: DeviceKey.Failure?
            if !needFaceID {
                reauth = (0, 0)  // configured: Face ID once per session, already given
            } else {
                do {
                    try DeviceKey.vault.unwrap(wrapped, reason: reason) { p in
                        reauth = core.reauth(pepper: p)
                    }
                } catch let f as DeviceKey.Failure {
                    if f == .notRecognised { reauth = core.reauth(pepper: nil) } else { failure = f }
                } catch {
                    failure = .failed(-1)
                }
            }
            var result: T?
            if failure == nil, reauth?.code == 0 { result = work(core) }
            DispatchQueue.main.async {
                self.busy = nil
                guard generation == self.lockGeneration else { return }
                self.touch()
                if let failure { done(nil, Self.message(for: failure)); return }
                switch reauth?.code {
                case 0: done(result, result == nil ? "Re-authentication failed." : nil)
                case 1: done(nil, "Face ID: no match. \(reauth?.aux ?? 0) attempt(s) before lockout.")
                case 2:
                    self.lock(.logout)
                    self.show("Locked: repeated Face ID failures.", warn: true)
                default: done(nil, "Re-authentication failed.")
                }
            }
        }
    }

    /// Face ID, then open a courier file or pasted text. Burn messages are shown once and never
    /// stored; others are also kept in the vault as a text file. A received file is encrypted
    /// into the vault by the core and never shown or handed to Swift.
    func courierReceive(_ data: Data, done: @escaping (String?) -> Void) {
        courierReauth("Open a courier message", work: { $0.courierReceive(data) }) { got, failure in
            if let failure { done(failure); return }
            guard let got, got.code == 0 else {
                done(Self.courierMessage(got?.code ?? -1))
                return
            }
            self.reloadItems()
            switch got.kind {
            case .file:
                self.vaultNote = ("File received · encrypted into the vault", .ok)
            case .burnMessage, .keptMessage:
                guard let text = got.text else { done(Self.courierMessage(-1)); return }
                self.openMessage = MessageContent(text: String(decoding: text, as: UTF8.self), lifetime: TimeInterval(self.config.messageMin * 60))
                self.vaultNote = got.kind == .burnMessage
                    ? ("Received · destroy-on-receipt · not stored", .ok)
                    : ("Received · saved in vault as a text file", .ok)
            }
            done(nil)
        }
    }

    /// Whether a vault item can be sent to the paired device: a file, not a photo or other
    /// image, within the courier's size limit. (The core checks again, by content too.)
    func courierCanSend(_ item: VaultItem) -> Bool {
        !item.isMessage && item.size > 0 && item.size <= Self.courierFileCap && !VaultCore.isImageName(item.name)
    }

    static let courierFileCap: UInt64 = 12 * 1024 * 1024

    /// Face ID, then seal a vault file for the paired device as a .scy file (ciphertext only, in
    /// the temporary outgoing folder for Save to Files or the share sheet).
    func courierSendFile(_ item: VaultItem, done: @escaping (SealedOutput) -> Void) {
        courierReauth("Send a file to the paired device", work: { $0.courierSendFile(item.id) }) { r, failure in
            if let failure { done(.failed(failure)); return }
            guard let r, r.code == 0, let out = r.out else {
                done(.failed(Self.courierMessage(r?.code ?? -1)))
                return
            }
            guard let url = Self.writeOutgoing(out, name: "Scytale file \(Self.fileStamp()).scy") else {
                done(.failed("Could not write the file."))
                return
            }
            done(.file(url))
        }
    }

    /// Outgoing courier files (public keys or ciphertext only) live in the temporary folder,
    /// which is cleared at every launch.
    static func writeOutgoing(_ data: Data, name: String) -> URL? {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("outgoing", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent(name)
        do {
            try data.write(to: url, options: [.atomic, .completeFileProtection])
            return url
        } catch {
            return nil
        }
    }
}
