import Foundation
import ScytaleCore

struct CourierStatus: Equatable {
    var paired: Bool
    var verified: Bool
    var peerKeys: Int     // one-time keys left for sending to the other device
    var ownKeys: Int      // own one-time keys issued and not yet used
}

/// Courier bridge. Run on the core queue (via `run`). Bundles and envelopes are public data;
/// received text arrives in Scytale-owned locked memory (SecureMemory).
extension VaultCore {
    func courierStatus() -> CourierStatus? {
        var p: Int32 = 0, v: Int32 = 0
        var a: UInt32 = 0, b: UInt32 = 0
        guard scy_courier_status(rawCore, &p, &v, &a, &b) == 0 else { return nil }
        return CourierStatus(paired: p == 1, verified: v == 1, peerKeys: Int(a), ownKeys: Int(b))
    }

    private func courierOut(_ n: Int32) -> Data? {
        guard n > 0 else { return nil }
        var buf = [UInt8](repeating: 0, count: Int(n))
        let got = buf.withUnsafeMutableBufferPointer { scy_courier_out_copy(rawCore, $0.baseAddress, $0.count) }
        return got == n ? Data(buf) : nil
    }

    func courierExportBundle() -> Data? {
        courierOut(scy_courier_export_bundle(rawCore))
    }

    /// 0 and the safety number, or a courier error code.
    func courierImportBundle(_ d: Data) -> (code: Int32, safety: String?) {
        var out = [UInt8](repeating: 0, count: 128)
        let rc = d.withUnsafeBytes { b in
            out.withUnsafeMutableBufferPointer {
                scy_courier_import_bundle(rawCore, b.bindMemory(to: UInt8.self).baseAddress, b.count, $0.baseAddress, $0.count)
            }
        }
        guard rc == 0 else { return (rc, nil) }
        return (0, String(decoding: out.prefix { $0 != 0 }, as: UTF8.self))
    }

    func courierSafety() -> String? {
        var out = [UInt8](repeating: 0, count: 128)
        let n = out.withUnsafeMutableBufferPointer { scy_courier_safety(rawCore, $0.baseAddress, $0.count) }
        return n > 0 ? String(decoding: out[0..<Int(n)], as: UTF8.self) : nil
    }

    func courierVerify() -> Bool { scy_courier_verify(rawCore) == 1 }
    func courierUnpair() -> Bool { scy_courier_unpair(rawCore) == 1 }

    /// Returns the sealed envelope (armored text or raw file bytes), or a courier error code.
    func courierSend(_ text: String, burn: Bool, armored: Bool) -> (code: Int32, out: Data?) {
        var t = Array(text.utf8)
        defer { wipe(&t) }
        let n = t.withUnsafeBufferPointer { scy_courier_send(rawCore, $0.baseAddress, $0.count, burn ? 1 : 0, armored ? 1 : 0) }
        guard n > 0 else { return (-n, nil) }
        return (0, courierOut(n))
    }

    /// After `reauth`. Returns the code, the sender's destroy flag and the text (locked memory).
    func courierReceive(_ d: Data) -> (code: Int32, burn: Bool, text: Data?) {
        var burn: Int32 = 0
        var len = 0
        let rc = d.withUnsafeBytes { b in
            scy_courier_receive(rawCore, b.bindMemory(to: UInt8.self).baseAddress, b.count, &burn, &len)
        }
        guard rc == 0 else { return (rc, false, nil) }
        defer { scy_view_close(rawCore) }
        let text = SecureMemory.data(count: len) { p in
            scy_view_copy(rawCore, p.assumingMemoryBound(to: UInt8.self), len) == Int32(len)
        }
        return (0, burn == 1, text)
    }
}
