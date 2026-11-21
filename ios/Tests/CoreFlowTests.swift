import CryptoKit
import XCTest
@testable import Scytale

/// Drives the real Rust core through the same Swift bridge the app uses. The simulator has no
/// Secure Enclave, so the pepper wrap is a stand-in; the on-device diagnostics cover the enclave.
final class CoreFlowTests: XCTestCase {
    private let pw = "correct horse battery staple"

    func testSetupLoginLockAndWipeThroughBridge() throws {
        let base = FileManager.default.temporaryDirectory.appendingPathComponent("scytale-ffi-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: base) }
        let core = try XCTUnwrap(VaultCore(directory: base.appendingPathComponent("vault")))

        XCTAssertEqual(core.run { $0.start(auditKey: nil) }.note, 0, "fresh install needs setup")
        XCTAssertEqual(core.run { $0.phase }, 0)

        core.run { c in
            c.push(.password, "short"); c.push(.confirm, "short")
        }
        XCTAssertEqual(core.run { $0.setupBegin(recover: false) }, 1, "weak password rejected")
        XCTAssertEqual(core.run { $0.count(.password) }, 0, "rejected password wiped")

        core.run { c in
            c.push(.password, pw); c.push(.confirm, pw)
        }
        XCTAssertEqual(core.run { $0.count(.password) }, pw.count)
        XCTAssertEqual(core.run { $0.setupBegin(recover: false) }, 0)

        let qr = try XCTUnwrap(core.run { $0.setupQR() })
        XCTAssertEqual(qr.modules.count, qr.width * qr.width)
        let secretText = try XCTUnwrap(core.run { $0.setupSecret() })
        let totpKey = try XCTUnwrap(Self.base32(secretText.replacingOccurrences(of: " ", with: "")))
        XCTAssertEqual(totpKey.count, 20)

        var pepper = [UInt8]()
        core.run { c in _ = c.withSetupPepper { pepper = Array($0) } }
        XCTAssertEqual(pepper.count, 32)
        XCTAssertFalse(core.run { c in [UInt8](repeating: 0, count: 32).withUnsafeBytes { c.setupPepperVerify($0) } })
        XCTAssertTrue(core.run { c in pepper.withUnsafeBytes { c.setupPepperVerify($0) } })

        let now = UInt64(Date().timeIntervalSince1970)
        core.run { $0.push(.code, Self.totp(totpKey, now)) }
        XCTAssertTrue(core.run { $0.setupCode() })

        let audit = [UInt8](repeating: 7, count: 32)
        let wrapped = Data("stand-in for the Secure Enclave wrap".utf8)
        XCTAssertEqual(core.run { c in audit.withUnsafeBytes { c.setupCommit(wrapped: wrapped, auditKey: $0) } }, 0)
        XCTAssertEqual(core.run { $0.phase }, 2, "vault open after setup")
        let rk = try XCTUnwrap(core.run { $0.setupRecoveryKey() })
        XCTAssertEqual(rk.replacingOccurrences(of: " ", with: "").count, 52)

        core.run { $0.setupFinish(); $0.lock(.logout) }
        XCTAssertEqual(core.run { $0.phase }, 1)
        XCTAssertNil(core.run { $0.setupRecoveryKey() }, "recovery key gone after setup")
        XCTAssertEqual(core.run { $0.wrappedPepper() }, wrapped)

        // wrong Face ID pepper: a counted failure
        core.run { c in c.push(.password, pw); c.push(.code, Self.totp(totpKey, now + 30)) }
        let bad = core.run { c in [UInt8](repeating: 1, count: 32).withUnsafeBytes { c.login(pepper: $0) } }
        XCTAssertEqual(bad.code, 1)
        XCTAssertEqual(bad.aux, 2, "two attempts left")
        XCTAssertEqual(core.run { $0.count(.password) }, 0, "password wiped after an attempt")

        // correct password + code + pepper
        core.run { c in c.push(.password, pw); c.push(.code, Self.totp(totpKey, now + 30)) }
        let ok = core.run { c in pepper.withUnsafeBytes { c.login(pepper: $0) } }
        XCTAssertEqual(ok.code, 0)
        let s = core.run { $0.summary() }
        XCTAssertEqual(s.chain, 0, "audit chain intact")
        XCTAssertEqual(s.fails_since, 1)

        // import (camera bytes + a file), re-authenticate, view, purge
        let photo = Data((0..<200_000).map { UInt8(truncatingIfNeeded: $0 &* 7) })
        XCTAssertEqual(core.run { $0.importBytes(name: "Camera test.heic", data: photo, photo: true) }, 0)
        let file = base.appendingPathComponent("note.txt")
        try Data("hello vault".utf8).write(to: file)
        XCTAssertEqual(core.run { $0.importFile(path: file.path) }, 0)
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path), "original left for the user to delete")
        let items = core.run { $0.items() }
        XCTAssertEqual(items.map(\.name).sorted(), ["Camera test.heic", "note.txt"])
        let cam = try XCTUnwrap(items.first { $0.name == "Camera test.heic" })
        XCTAssertEqual(cam.size, UInt64(photo.count))

        // tags through the bridge: create, reuse by name, apply, read back
        let tagID = try XCTUnwrap(core.run { $0.tagCreate("1password", color: 3) })
        XCTAssertEqual(core.run { $0.tagCreate("1Password", color: 5) }, tagID, "saved tag reused")
        XCTAssertTrue(core.run { $0.tagSet(item: cam.id, tag: tagID, on: true) })
        let tags = core.run { $0.tags() }
        XCTAssertEqual(tags.defs, [VaultTag(id: tagID, name: "1password", color: 5)])
        XCTAssertEqual(tags.assigned[cam.id], [tagID])

        XCTAssertEqual(core.run { $0.openView(cam.id) }.code, 1, "viewing needs re-authentication")
        XCTAssertEqual(core.run { c in pepper.withUnsafeBytes { c.reauth(pepper: $0) } }.code, 0)
        let opened = core.run { $0.openView(cam.id) }
        XCTAssertEqual(opened.code, 0)
        XCTAssertEqual(opened.data, photo)
        core.run { $0.auditReencrypted(automatic: false) }
        XCTAssertEqual(core.run { $0.openView(cam.id) }.code, 1, "one re-authentication = one decrypt")
        XCTAssertEqual(core.run { $0.reauth(pepper: nil) }.code, 1, "Face ID mismatch counts")

        XCTAssertTrue(core.run { $0.purge(cam.id) })
        XCTAssertEqual(core.run { $0.items() }.count, 1)

        // burn-after-reading message through the bridge
        XCTAssertTrue(core.run { $0.sealMessage("meet at 9, code 4417") })
        let msg = try XCTUnwrap(core.run { $0.items() }.first { $0.isMessage })
        XCTAssertEqual(core.run { $0.openMessage(msg.id) }.code, 1, "needs re-authentication")
        XCTAssertEqual(core.run { c in pepper.withUnsafeBytes { c.reauth(pepper: $0) } }.code, 0)
        let read = core.run { $0.openMessage(msg.id) }
        XCTAssertEqual(read.code, 0)
        XCTAssertEqual(read.data.map { String(decoding: $0, as: UTF8.self) }, "meet at 9, code 4417")
        XCTAssertFalse(core.run { $0.items() }.contains { $0.isMessage }, "destroyed when read")

        // the login log is readable, intact and records the failed factor
        let log = core.run { $0.auditEntries() }
        XCTAssertEqual(log.chain, 0)
        XCTAssertTrue(log.entries.contains { $0.event == "LOGIN_FAIL" && $0.extra == 1 }, "wrong pepper logged as password factor")
        XCTAssertTrue(log.entries.contains { $0.event == "MSG_DEC" })
        for event in ["PHOTO_ENC", "FILE_ENC", "FILE_DEC", "MSG_ENC"] {
            XCTAssertTrue(log.entries.contains { $0.event == event }, "\(event) logged")
        }
        XCTAssertTrue(log.entries.contains { $0.event == "FILE_REENC" && $0.extra == 0 }, "re-encrypt logged")
        XCTAssertEqual(core.run { $0.terminationLevel }, 0, "counter reset by the successful login")

        // courier bridge: bundle export and status (a second vault is covered by the Rust tests)
        let bundle = try XCTUnwrap(core.run { $0.courierExportBundle() })
        XCTAssertTrue(String(decoding: bundle, as: UTF8.self).hasPrefix("-----BEGIN SCYTALE KEY BUNDLE-----"))
        XCTAssertEqual(core.run { $0.courierStatus() }, CourierStatus(paired: false, verified: false, peerKeys: 0, ownKeys: 100))
        XCTAssertEqual(core.run { $0.courierImportBundle(bundle) }.code, 11, "own bundle refused")
        XCTAssertEqual(core.run { $0.courierSend("x", burn: true, armored: true) }.code, 5, "not paired")

        // configuration through the bridge: hardened by default, Face ID needed to change it
        XCTAssertEqual(core.run { $0.config() }, .hardened)
        var relaxed = AppConfig.hardened
        relaxed.custom = true
        relaxed.timeoutMin = 30
        relaxed.requireTotp = false
        XCTAssertFalse(core.run { $0.configSet(relaxed) }, "locked without Face ID")
        XCTAssertEqual(core.run { c in pepper.withUnsafeBytes { c.reauth(pepper: $0) } }.code, 0)
        XCTAssertTrue(core.run { $0.configBegin() })
        XCTAssertTrue(core.run { $0.configSet(relaxed) })
        XCTAssertEqual(core.run { $0.config() }, relaxed)
        core.run { $0.configEnd() }

        core.run { $0.lock(.background) }
        XCTAssertTrue(core.run { $0.items() }.isEmpty, "nothing listed once locked")
        XCTAssertEqual(core.run { $0.phase }, 1)
        XCTAssertEqual(core.run { $0.panicWipe() }, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: base.appendingPathComponent("vault").path))
    }

    // RFC 6238 TOTP (SHA-1, 6 digits, 30 s), independent of the Rust implementation.
    static func totp(_ key: [UInt8], _ t: UInt64) -> String {
        var counter = (t / 30).bigEndian
        let msg = Data(bytes: &counter, count: 8)
        let mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: msg, using: SymmetricKey(data: key)))
        let o = Int(mac[19] & 0x0f)
        let bin = (UInt32(mac[o] & 0x7f) << 24) | (UInt32(mac[o + 1]) << 16) | (UInt32(mac[o + 2]) << 8) | UInt32(mac[o + 3])
        return String(format: "%06u", bin % 1_000_000)
    }

    static func base32(_ s: String) -> [UInt8]? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var bits = 0, value = 0
        var out = [UInt8]()
        for ch in s.uppercased() {
            guard let i = alphabet.firstIndex(of: ch) else { return nil }
            value = (value << 5) | i
            bits += 5
            if bits >= 8 {
                out.append(UInt8((value >> (bits - 8)) & 0xff))
                bits -= 8
            }
        }
        return out
    }
}
