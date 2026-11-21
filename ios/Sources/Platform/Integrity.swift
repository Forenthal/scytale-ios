import Darwin
import Foundation
import MachO
import Security

/// Refuses to run where Scytale's memory could be read while it is unlocked: an attached debugger,
/// a jailbroken phone, injected hooking libraries, or a copy of the app re-signed by someone else.
///
/// These checks raise the bar; a skilled attacker who controls the device can defeat them. Only
/// strong signals are used, to avoid locking the owner out on a normal iPhone. The simulator (used
/// for automated tests) is exempt.
enum Integrity {
    static let teamID = "RWX6R62WK4"

    struct Report {
        var problems: [String] = []
        var ok: Bool { problems.isEmpty }
    }

    /// Ask the kernel to kill the process if a debugger ever attaches (PT_DENY_ATTACH).
    static func denyDebuggerAttach() {
        #if !targetEnvironment(simulator) && !DEBUG
        typealias Ptrace = @convention(c) (CInt, pid_t, UnsafeMutableRawPointer?, CInt) -> CInt
        guard let handle = dlopen(nil, RTLD_NOW), let sym = dlsym(handle, "ptrace") else { return }
        let ptrace = unsafeBitCast(sym, to: Ptrace.self)
        _ = ptrace(31, 0, nil, 0)
        #endif
    }

    static func check() -> Report {
        var r = Report()
        #if targetEnvironment(simulator)
        return r
        #else
        if debuggerAttached() { r.problems.append("a debugger is attached") }
        if let p = jailbreakArtifact() { r.problems.append("jailbreak detected (\(p))") }
        if sandboxEscaped() { r.problems.append("jailbreak detected (sandbox is open)") }
        if let lib = injectedLibrary() { r.problems.append("injected code detected (\(lib))") }
        if getenv("DYLD_INSERT_LIBRARIES") != nil { r.problems.append("library injection is configured") }
        if let team = signingTeam(), team != teamID { r.problems.append("this copy of Scytale was re-signed by someone else") }
        return r
        #endif
    }

    static func debuggerAttached() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        guard sysctl(&mib, u_int(mib.count), &info, &size, nil, 0) == 0 else { return false }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    private static func jailbreakArtifact() -> String? {
        let paths = [
            "/var/jb", "/private/var/jb", "/var/binpack",
            "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib", "/usr/lib/libsubstitute.dylib",
            "/usr/lib/TweakInject", "/etc/apt", "/private/var/lib/apt", "/usr/sbin/sshd",
            "/bin/bash", "/usr/libexec/cydia",
        ]
        return paths.first { FileManager.default.fileExists(atPath: $0) }
    }

    /// A normal app cannot write outside its own sandbox.
    private static func sandboxEscaped() -> Bool {
        let path = "/private/scytale-sandbox-probe-\(getpid())"
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
        guard fd >= 0 else { return false }
        close(fd)
        unlink(path)
        return true
    }

    private static func injectedLibrary() -> String? {
        let markers = ["frida", "fridagadget", "substrate", "substitute", "libhooker", "cycript",
                       "sslkillswitch", "tweakinject", "ellekit", "cynject", "libblackjack", "shadow.dylib"]
        for i in 0..<_dyld_image_count() {
            guard let c = _dyld_get_image_name(i) else { continue }
            let name = String(cString: c).lowercased()
            if let m = markers.first(where: { name.contains($0) }) { return m }
        }
        return nil
    }

    /// The team prefix of the app's own Keychain access group: Apple's signing determines it, so a
    /// re-signed copy has a different one.
    static func signingTeam() -> String? {
        let probe = KeychainSecret(account: "integrity-probe")
        defer { probe.delete() }
        var one: UInt8 = 1
        guard (try? withUnsafeBytes(of: &one) { try probe.store($0) }) != nil,
              let group = probe.attributes()?[kSecAttrAccessGroup as String] as? String,
              let dot = group.firstIndex(of: ".") else { return nil }
        return String(group[..<dot])
    }
}
