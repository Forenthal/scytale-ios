import Foundation
import ScytaleCore

enum InputField: Int32 {
    case password = 0, confirm = 1, code = 2, recovery = 3
}

/// Overwrites a byte array in place (best effort; Swift may have made copies earlier).
func wipe(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBytes { buf in
        if let base = buf.baseAddress { memset_s(base, buf.count, 0, buf.count) }
    }
}

/// Thin wrapper over the Rust core. Every method must run on `queue` (use `run`), so the core is
/// never used from two threads. Secrets cross this boundary only as short-lived raw buffers.
final class VaultCore {
    let queue = DispatchQueue(label: "com.forenthal.scytale.core", qos: .userInitiated)
    let directory: URL
    private let ptr: OpaquePointer
    /// For extensions in other files (courier); same pointer, same queue rules.
    var rawCore: OpaquePointer { ptr }

    init?(directory: URL) {
        var path = Array(directory.path.utf8)
        guard let p = path.withUnsafeBufferPointer({ scy_core_new($0.baseAddress, $0.count) }) else { return nil }
        wipe(&path)
        self.ptr = p
        self.directory = directory
    }

    deinit {
        scy_core_free(ptr)
    }

    /// Run on the core queue and wait. Never call while a long operation is running.
    func run<T>(_ body: (VaultCore) throws -> T) rethrows -> T {
        try queue.sync { try body(self) }
    }

    // MARK: start

    func start(auditKey: UnsafeRawBufferPointer?) -> (note: Int32, ts: UInt64) {
        var ts: UInt64 = 0
        let note = scy_core_start(ptr, auditKey?.bindMemory(to: UInt8.self).baseAddress, auditKey?.count ?? 0, &ts)
        return (note, ts)
    }

    var phase: Int32 { scy_phase(ptr) }

    // MARK: input

    @discardableResult
    func push(_ field: InputField, _ text: String) -> Bool {
        var text = text
        return text.withUTF8 { scy_input_push(ptr, field.rawValue, $0.baseAddress, $0.count) == 1 }
    }

    func backspace(_ field: InputField) { scy_input_backspace(ptr, field.rawValue) }
    func clear(_ field: InputField) { scy_input_clear(ptr, field.rawValue) }
    func count(_ field: InputField) -> Int { Int(max(0, scy_input_count(ptr, field.rawValue))) }

    // MARK: setup / recovery

    func setupBegin(recover: Bool) -> Int32 { scy_setup_begin(ptr, recover ? 1 : 0) }

    func setupQR() -> (width: Int, modules: [UInt8])? {
        var buf = [UInt8](repeating: 0, count: 177 * 177)
        let w = buf.withUnsafeMutableBufferPointer { scy_setup_qr(ptr, $0.baseAddress, $0.count) }
        guard w > 0 else { wipe(&buf); return nil }
        let mods = Array(buf[0..<Int(w * w)])
        wipe(&buf)
        return (Int(w), mods)
    }

    func setupSecret() -> String? { text(scy_setup_secret) }
    func setupRecoveryKey() -> String? { text(scy_setup_recovery_key) }

    private func text(_ f: (OpaquePointer?, UnsafeMutablePointer<UInt8>?, Int) -> Int32) -> String? {
        var buf = [UInt8](repeating: 0, count: 256)
        defer { wipe(&buf) }
        let n = buf.withUnsafeMutableBufferPointer { f(ptr, $0.baseAddress, $0.count) }
        guard n > 0 else { return nil }
        return String(decoding: buf[0..<Int(n)], as: UTF8.self)
    }

    /// Hands the new device pepper to `body`, then wipes it.
    func withSetupPepper<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T? {
        var buf = [UInt8](repeating: 0, count: 32)
        defer { wipe(&buf) }
        let n = buf.withUnsafeMutableBufferPointer { scy_setup_pepper(ptr, $0.baseAddress, $0.count) }
        guard n == 32 else { return nil }
        return try buf.withUnsafeBytes { try body($0) }
    }

    func setupPepperVerify(_ p: UnsafeRawBufferPointer) -> Bool {
        scy_setup_pepper_verify(ptr, p.bindMemory(to: UInt8.self).baseAddress, p.count) == 1
    }

    func setupCode() -> Bool { scy_setup_code(ptr) == 1 }

    func setupCommit(wrapped: Data, auditKey: UnsafeRawBufferPointer?) -> Int32 {
        wrapped.withUnsafeBytes { w in
            scy_setup_commit(ptr, w.bindMemory(to: UInt8.self).baseAddress, w.count,
                             auditKey?.bindMemory(to: UInt8.self).baseAddress, auditKey?.count ?? 0)
        }
    }

    func setupFinish() { scy_setup_finish(ptr) }
    func recoverCheck() -> Bool { scy_recover_check(ptr) == 1 }

    // MARK: login

    func wrappedPepper() -> Data? {
        var buf = [UInt8](repeating: 0, count: 4096)
        let n = buf.withUnsafeMutableBufferPointer { scy_wrapped_pepper(ptr, $0.baseAddress, $0.count) }
        guard n > 0 else { return nil }
        return Data(buf[0..<Int(n)])
    }

    var lockedRemaining: UInt64 { scy_locked_remaining(ptr) }

    func login(pepper: UnsafeRawBufferPointer?) -> (code: Int32, aux: UInt64) {
        var aux: UInt64 = 0
        let code = scy_login(ptr, pepper?.bindMemory(to: UInt8.self).baseAddress, pepper?.count ?? 0, &aux)
        return (code, aux)
    }

    func summary() -> ScySummary {
        var s = ScySummary()
        scy_session_summary(ptr, &s)
        return s
    }

    // MARK: vault contents

    func items() -> [VaultItem] {
        let n = scy_item_count(ptr)
        guard n > 0 else { return [] }
        var name = [UInt8](repeating: 0, count: 2048)
        defer { wipe(&name) }
        var out: [VaultItem] = []
        out.reserveCapacity(Int(n))
        for i in 0..<n {
            var id = [UInt8](repeating: 0, count: 16)
            var kind: Int32 = 0
            var created: UInt64 = 0
            var size: UInt64 = 0
            let len = name.withUnsafeMutableBufferPointer {
                scy_item_get(ptr, i, &id, &kind, &created, &size, $0.baseAddress, $0.count)
            }
            guard len >= 0 else { continue }
            out.append(VaultItem(id: Data(id), kind: kind, created: created, size: size,
                                 name: String(decoding: name[0..<Int(len)], as: UTF8.self)))
        }
        return out
    }

    /// 0 ok, 1 locked, 2 failed.
    func importFile(path: String) -> Int32 {
        var p = Array(path.utf8)
        var id = [UInt8](repeating: 0, count: 16)
        defer { wipe(&p) }
        return p.withUnsafeBufferPointer { scy_import_file(ptr, $0.baseAddress, $0.count, &id) }
    }

    /// 0 ok, 1 locked, 2 failed.
    func importBytes(name: String, data: Data, photo: Bool) -> Int32 {
        var n = Array(name.utf8)
        var id = [UInt8](repeating: 0, count: 16)
        defer { wipe(&n) }
        return n.withUnsafeBufferPointer { nb in
            data.withUnsafeBytes { db in
                scy_import_bytes(ptr, nb.baseAddress, nb.count,
                                 db.bindMemory(to: UInt8.self).baseAddress, db.count, photo ? 1 : 0, &id)
            }
        }
    }

    /// 0 ok; 1 failed (aux = attempts left); 2 locked out (session ended); 3 no session.
    func reauth(pepper: UnsafeRawBufferPointer?) -> (code: Int32, aux: UInt64) {
        var aux: UInt64 = 0
        let code = scy_reauth(ptr, pepper?.bindMemory(to: UInt8.self).baseAddress, pepper?.count ?? 0, &aux)
        return (code, aux)
    }

    /// Decrypts an item into Scytale-owned locked memory (see SecureMemory); the core's own copy
    /// is wiped before this returns. 0 ok, else the view error code.
    func openView(_ id: Data) -> (code: Int32, data: Data?) {
        var len = 0
        let rc = id.withUnsafeBytes { scy_view_open(ptr, $0.bindMemory(to: UInt8.self).baseAddress, &len) }
        guard rc == 0 else { return (rc, nil) }
        defer { scy_view_close(ptr) }
        let data = SecureMemory.data(count: len) { p in
            scy_view_copy(ptr, p.assumingMemoryBound(to: UInt8.self), len) == Int32(len)
        }
        return data == nil ? (4, nil) : (0, data)
    }

    func purge(_ id: Data) -> Bool {
        id.withUnsafeBytes { scy_purge(ptr, $0.bindMemory(to: UInt8.self).baseAddress) == 1 }
    }

    var terminationLevel: Int32 { scy_termination_level(ptr) }

    // MARK: messages

    func sealMessage(_ text: String) -> Bool {
        var t = Array(text.utf8)
        defer { wipe(&t) }
        return t.withUnsafeBufferPointer { scy_msg_seal(ptr, $0.baseAddress, $0.count) == 1 }
    }

    /// Opens a message once (after `reauth`). The core destroys it on disk first.
    func openMessage(_ id: Data) -> (code: Int32, data: Data?) {
        var len = 0
        let rc = id.withUnsafeBytes { scy_msg_open(ptr, $0.bindMemory(to: UInt8.self).baseAddress, &len) }
        guard rc == 0 else { return (rc, nil) }
        defer { scy_view_close(ptr) }
        let data = SecureMemory.data(count: len) { p in
            scy_view_copy(ptr, p.assumingMemoryBound(to: UInt8.self), len) == Int32(len)
        }
        return data == nil ? (4, nil) : (0, data)
    }

    // MARK: audit / login log

    struct AuditEntry: Identifiable {
        let id: UInt64      // sequence number
        let ts: UInt64
        let event: String
        let extra: UInt64
    }

    func auditEntries() -> (entries: [AuditEntry], chain: Int32, chainAt: UInt64) {
        let n = scy_audit_load(ptr)
        var out: [AuditEntry] = []
        var ev = [UInt8](repeating: 0, count: 64)
        for i in 0..<max(n, 0) {
            var seq: UInt64 = 0, ts: UInt64 = 0, extra: UInt64 = 0
            let l = ev.withUnsafeMutableBufferPointer { scy_audit_entry(ptr, i, &seq, &ts, &extra, $0.baseAddress, $0.count) }
            guard l > 0 else { continue }
            out.append(AuditEntry(id: seq, ts: ts, event: String(decoding: ev[0..<Int(l)], as: UTF8.self), extra: extra))
        }
        var at: UInt64 = 0
        let chain = scy_audit_chain(ptr, &at)
        return (out, chain, at)
    }

    // MARK: end

    func lock(_ reason: LockReason) { scy_lock(ptr, reason.rawValue) }
    func auditScreenshot() { _ = scy_audit_event(ptr, 1) }
    func auditMessageExpired() { _ = scy_audit_event(ptr, 2) }
    func auditMessageClosed() { _ = scy_audit_event(ptr, 3) }
    func auditReencrypted(automatic: Bool) { _ = scy_audit_event(ptr, automatic ? 5 : 4) }
    func panicWipe() -> Int32 { scy_panic_wipe(ptr) }
}

struct VaultItem: Identifiable, Hashable {
    let id: Data
    let kind: Int32          // 1 file, 2 message
    let created: UInt64
    let size: UInt64
    let name: String

    var isMessage: Bool { kind == 2 }
}

enum LockReason: Int32 {
    case logout = 0, timeout = 1, background = 2, deviceLock = 3, capture = 4
}
