import Foundation
import ScytaleCore

struct VaultTag: Identifiable, Equatable, Hashable {
    let id: UInt16
    var name: String
    var color: Int
}

/// Tag bridge. Run on the core queue (via `run`).
extension VaultCore {
    /// Definitions and assignments (item id -> tag ids).
    func tags() -> (defs: [VaultTag], assigned: [Data: [UInt16]]) {
        for cap in [64 * 1024, 4 * 1024 * 1024] {
            var buf = [UInt8](repeating: 0, count: cap)
            let n = buf.withUnsafeMutableBufferPointer { scy_tags_get(rawCore, $0.baseAddress, $0.count) }
            if n > 0 { return Self.parseTags(Array(buf[0..<Int(n)])) }
            if n != -1 { break }  // a real error, not "buffer too small"
        }
        return ([], [:])
    }

    static func parseTags(_ b: [UInt8]) -> (defs: [VaultTag], assigned: [Data: [UInt16]]) {
        var p = 0
        func take(_ n: Int) -> ArraySlice<UInt8>? {
            guard p + n <= b.count else { return nil }
            defer { p += n }
            return b[p..<p + n]
        }
        func u16() -> UInt16? { take(2).map { UInt16($0[$0.startIndex]) | UInt16($0[$0.startIndex + 1]) << 8 } }
        func u32() -> UInt32? { take(4).map { s in s.enumerated().reduce(UInt32(0)) { $0 | UInt32($1.element) << (8 * UInt32($1.offset)) } } }
        guard take(5).map(Array.init) == Array("SCYT".utf8) + [1], u16() != nil, let n = u16() else { return ([], [:]) }
        var defs: [VaultTag] = []
        for _ in 0..<n {
            guard let id = u16(), let color = take(1)?.first, let len = take(1)?.first,
                  let name = take(Int(len)) else { return ([], [:]) }
            defs.append(VaultTag(id: id, name: String(decoding: name, as: UTF8.self), color: Int(color)))
        }
        var assigned: [Data: [UInt16]] = [:]
        guard let m = u32() else { return (defs, [:]) }
        for _ in 0..<m {
            guard let item = take(16), let k = take(1)?.first else { break }
            var ids: [UInt16] = []
            for _ in 0..<k { if let id = u16() { ids.append(id) } }
            assigned[Data(item)] = ids
        }
        return (defs, assigned)
    }

    /// Returns the tag id, or nil.
    func tagCreate(_ name: String, color: Int) -> UInt16? {
        var n = Array(name.utf8)
        let r = n.withUnsafeMutableBufferPointer { scy_tag_create(rawCore, $0.baseAddress, $0.count, UInt8(color)) }
        return r > 0 ? UInt16(r) : nil
    }

    func tagUpdate(_ id: UInt16, name: String, color: Int) -> Bool {
        var n = Array(name.utf8)
        return n.withUnsafeMutableBufferPointer { scy_tag_update(rawCore, id, $0.baseAddress, $0.count, UInt8(color)) } == 0
    }

    func tagDelete(_ id: UInt16) -> Bool { scy_tag_delete(rawCore, id) == 0 }

    func tagSet(item: Data, tag: UInt16, on: Bool) -> Bool {
        item.withUnsafeBytes { scy_tag_set(rawCore, $0.bindMemory(to: UInt8.self).baseAddress, tag, on ? 1 : 0) } == 0
    }
}
