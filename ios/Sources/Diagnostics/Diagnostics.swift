import Foundation
import ScytaleCore

/// On-device checks for everything the cloud simulator cannot test: Secure Enclave, Face ID,
/// Data Protection and the Keychain's device-only settings. Each check cleans up after itself.
enum Diagnostics {
    struct Result: Identifiable {
        let id = UUID()
        let name: String
        let passed: Bool
        let detail: String
    }

    static func coreSelfTest() -> Result {
        let r = scytale_selftest()
        return Result(name: "Encryption core self-test", passed: r == 0,
                      detail: r == 0 ? "AES-256-GCM, HKDF, TOTP vectors and tamper checks pass" : "failed check \(r)")
    }

    static func vaultFolder() -> Result {
        do {
            let dir = try VaultLocation.directory()
            let excluded = VaultLocation.isExcludedFromBackup(dir)
            let attrs = try FileManager.default.attributesOfItem(atPath: dir.path)
            let prot = attrs[.protectionKey] as? FileProtectionType
            let ok = excluded && (prot == .complete || isSimulator)
            return Result(name: "Vault folder", passed: ok,
                          detail: "excluded from backup: \(excluded ? "yes" : "NO"), protection: \(prot?.rawValue ?? "none")")
        } catch {
            return Result(name: "Vault folder", passed: false, detail: "error: \(error)")
        }
    }

    static func fileProtection() -> Result {
        guard let dir = try? VaultLocation.directory() else {
            return Result(name: "File protection", passed: false, detail: "no vault folder")
        }
        let path = Array(dir.path.utf8)
        let cls = path.withUnsafeBufferPointer { scytale_protection_probe($0.baseAddress, $0.count) }
        let ok = cls == 1 || (isSimulator && cls == -1)
        let what: String
        switch cls {
        case 1: what = "Complete (class A): unreadable while the phone is locked"
        case -1: what = "simulator: no Data Protection"
        case -2: what = "could NOT be applied"
        case -3: what = "I/O error"
        default: what = "wrong class \(cls)"
        }
        return Result(name: "File protection", passed: ok, detail: what)
    }

    static func keychain() -> Result {
        let item = KeychainSecret(account: "diagnostics-probe")
        defer { item.delete() }
        var probe = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, probe.count, &probe) == errSecSuccess else {
            return Result(name: "Keychain", passed: false, detail: "random generator failed")
        }
        do {
            try probe.withUnsafeBytes { try item.store($0) }
            var same = false
            try item.load { same = $0.elementsEqual(probe) }
            let attrs = item.attributes() ?? [:]
            let accessible = attrs[kSecAttrAccessible as String] as? String
            let deviceOnly = accessible == (kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
            let synced = (attrs[kSecAttrSynchronizable as String] as? NSNumber)?.boolValue ?? false
            let ok = same && deviceOnly && !synced
            return Result(name: "Keychain", passed: ok,
                          detail: "round trip: \(same ? "ok" : "MISMATCH"), this device only: \(deviceOnly ? "yes" : "NO"), iCloud sync: \(synced ? "ON" : "off")")
        } catch let e as KeychainError {
            return Result(name: "Keychain", passed: false, detail: "OSStatus \(e.status)")
        } catch {
            return Result(name: "Keychain", passed: false, detail: "error: \(error)")
        }
    }

    /// Creates a throwaway Secure Enclave key, wraps random bytes, unwraps them with Face ID,
    /// compares, deletes the key. Blocks while Face ID runs: call off the main thread.
    static func secureEnclave() -> Result {
        let key = DeviceKey.diagnostics
        defer { key.delete() }
        var probe = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, probe.count, &probe) == errSecSuccess else {
            return Result(name: "Secure Enclave + Face ID", passed: false, detail: "random generator failed")
        }
        do {
            try key.create()
            let wrapped = try probe.withUnsafeBytes { try key.wrap($0) }
            let leaked = wrapped.range(of: Data(probe)) != nil
            var same = false
            try key.unwrap(wrapped, reason: "Scytale diagnostics: test the Secure Enclave key") {
                same = $0.elementsEqual(probe)
            }
            let ok = same && !leaked
            return Result(name: "Secure Enclave + Face ID", passed: ok,
                          detail: "wrapped \(wrapped.count) bytes, Face ID unwrap: \(same ? "ok" : "MISMATCH")")
        } catch let f as DeviceKey.Failure {
            return Result(name: "Secure Enclave + Face ID", passed: false, detail: "\(f)")
        } catch {
            return Result(name: "Secure Enclave + Face ID", passed: false, detail: "error: \(error)")
        }
    }

    /// The app must have no iCloud container at all. Blocks briefly: call off the main thread.
    static func noICloud() -> Result {
        let container = FileManager.default.url(forUbiquityContainerIdentifier: nil)
        return Result(name: "No iCloud access", passed: container == nil,
                      detail: container == nil ? "app has no iCloud container" : "iCloud container PRESENT")
    }

    static func deviceIntegrity() -> Result {
        let r = Integrity.check()
        let detail = r.ok
            ? (isSimulator ? "simulator: checks skipped" : "no debugger, jailbreak, injected code or re-signing detected (team \(Integrity.signingTeam() ?? "?"))")
            : r.problems.joined(separator: "; ")
        return Result(name: "Device integrity", passed: r.ok, detail: detail)
    }

    /// How long one password guess costs on this iPhone. Blocks for that long.
    static func kdfTiming() -> Result {
        let b = AppModel.kdfBenchmark()
        return Result(name: "Key derivation cost", passed: b.ms > 0,
                      detail: "Argon2id \(b.m / 1024) MiB, t=\(b.t), p=\(b.p): \(b.ms) ms per password attempt")
    }

    /// The codebase's provenance marker (see LICENSE.md and README.md): identifies genuine
    /// Forenthal builds and lets copies of the code be found.
    static func provenance() -> Result {
        var buf = [UInt8](repeating: 0, count: 128)
        let n = buf.withUnsafeMutableBufferPointer { scytale_provenance($0.baseAddress, $0.count) }
        let text = n > 0 ? String(decoding: buf[0..<Int(n)], as: UTF8.self) : "unavailable"
        return Result(name: "Build provenance", passed: n > 0, detail: "Forenthal · \(text)")
    }

    static var isSimulator: Bool {
        #if targetEnvironment(simulator)
        true
        #else
        false
        #endif
    }
}
