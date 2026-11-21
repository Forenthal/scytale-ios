import Foundation
import Security

/// Small secrets (the audit-log key) kept in the Keychain as: readable only while the phone is
/// unlocked, bound to this device, never synced to iCloud Keychain, never in any backup.
struct KeychainSecret {
    static let service = "com.forenthal.scytale"
    static let auditKey = KeychainSecret(account: "audit-key.v1")

    let account: String

    private var base: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse!,
        ]
    }

    func store(_ bytes: UnsafeRawBufferPointer) throws {
        delete()
        var item = base
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        item[kSecValueData as String] = Data(bytes)
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError(status: status) }
    }

    /// Hands the stored bytes to `use`, then overwrites the returned buffer.
    /// Returns false if there is no such item.
    @discardableResult
    func load(_ use: (UnsafeRawBufferPointer) throws -> Void) throws -> Bool {
        var query = base
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        if status == errSecItemNotFound { return false }
        guard status == errSecSuccess, let data = out as? NSData else { throw KeychainError(status: status) }
        let length = data.length
        let base = UnsafeMutableRawPointer(mutating: data.bytes)
        defer { memset_s(base, length, 0, length) }
        try use(UnsafeRawBufferPointer(start: base, count: length))
        return true
    }

    func delete() {
        SecItemDelete(base as CFDictionary)
    }

    /// The item's stored attributes (no data), for verifying protection settings.
    func attributes() -> [String: Any]? {
        var query = base
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? [String: Any]
    }

    /// Removes every Scytale Keychain item. Keychain items outlive an app deletion on iOS, so this
    /// runs on first launch when no vault exists, and during a panic wipe.
    static func deleteAll() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        SecItemDelete(query as CFDictionary)
    }
}

struct KeychainError: Error, Equatable {
    let status: OSStatus
}
