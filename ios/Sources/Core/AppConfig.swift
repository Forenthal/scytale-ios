import Foundation
import ScytaleCore

/// Mirror of the core's Config (config.rs). The core stores it inside the HMAC-protected state,
/// so it cannot be changed by editing files; changing it requires Face ID.
struct AppConfig: Equatable {
    var custom = false
    var lockOnLeave = true
    var timeoutMin: Int = 5
    var requireTotp = true
    var faceIDEachOpen = true
    var notify = true
    var screenshotLocks = true
    var messageMin: Int = 5
    /// 0 ask, 1 always delete originals, 2 always keep originals.
    var originals: Int = 0

    static let hardened = AppConfig()
    static let timeouts = [1, 2, 5, 10, 15, 30, 60]
    static let messageTimes = [1, 5, 10]

    var bytes: [UInt8] {
        var f: UInt8 = 0
        if custom { f |= 1 }
        if !lockOnLeave { f |= 1 << 1 }
        if !requireTotp { f |= 1 << 2 }
        if !faceIDEachOpen { f |= 1 << 3 }
        if !notify { f |= 1 << 4 }
        if !screenshotLocks { f |= 1 << 5 }
        return [f, UInt8(timeoutMin), UInt8(messageMin), UInt8(originals), 0, 0, 0, 0]
    }

    init() {}

    init(bytes b: [UInt8]) {
        guard b.count == 8 else { self = .hardened; return }
        let f = b[0]
        custom = f & 1 != 0
        lockOnLeave = f & (1 << 1) == 0
        requireTotp = f & (1 << 2) == 0
        faceIDEachOpen = f & (1 << 3) == 0
        notify = f & (1 << 4) == 0
        screenshotLocks = f & (1 << 5) == 0
        timeoutMin = Self.timeouts.contains(Int(b[1])) ? Int(b[1]) : 5
        messageMin = Self.messageTimes.contains(Int(b[2])) ? Int(b[2]) : 5
        originals = b[3] <= 2 ? Int(b[3]) : 0
    }
}

extension VaultCore {
    /// The configuration in force, or (stored: true) the saved choices.
    func config(stored: Bool = false) -> AppConfig {
        var b = [UInt8](repeating: 0, count: 8)
        let n = b.withUnsafeMutableBufferPointer { scy_config_get(rawCore, stored ? 1 : 0, $0.baseAddress) }
        return n == 8 ? AppConfig(bytes: b) : .hardened
    }

    func configBegin() -> Bool { scy_config_begin(rawCore) == 1 }
    func configEnd() { scy_config_end(rawCore) }

    func configSet(_ c: AppConfig) -> Bool {
        c.bytes.withUnsafeBufferPointer { scy_config_set(rawCore, $0.baseAddress) == 1 }
    }

    var reauthRequired: Bool { scy_reauth_required(rawCore) == 1 }
}
