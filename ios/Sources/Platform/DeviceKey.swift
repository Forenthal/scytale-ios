import Foundation
import LocalAuthentication
import Security

/// A P-256 key generated inside the Secure Enclave. Its private half never leaves the chip, and the
/// chip only uses it after a Face ID match against the *current* enrolment (`biometryCurrentSet`):
/// adding or removing a face permanently disables it. It exists only while the phone has a
/// passcode, is bound to this device, and is never synced to iCloud or included in backups.
///
/// It wraps the 32-byte device pepper that, together with the password, derives the vault key.
/// This replaces Windows DPAPI in the desktop build.
struct DeviceKey {
    enum Failure: Error, Equatable {
        case noPasscode          // the phone has no passcode, so no Secure Enclave key can exist
        case unavailable         // no Secure Enclave (simulator)
        case cancelled           // the person cancelled Face ID
        case notRecognised       // Face ID did not match
        case invalidated         // key missing or disabled (Face ID enrolment changed, or wiped)
        case lockedOut           // iOS locked Face ID after too many misses (needs the passcode)
        case biometryOff         // Face ID is switched off for Scytale in Settings
        case failed(Int)         // any other OSStatus / CFError code
    }

    static let vault = DeviceKey(tag: "com.forenthal.scytale.devicekey.v1")
    /// Throwaway key used only by the on-device diagnostics.
    static let diagnostics = DeviceKey(tag: "com.forenthal.scytale.devicekey.diag")

    private static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    let tag: Data

    init(tag: String) {
        self.tag = Data(tag.utf8)
    }

    // MARK: lifecycle

    /// Replaces any existing key with a new one.
    func create() throws {
        delete()
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &error
        ) else {
            throw Self.map(error?.takeRetainedValue())
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
            ] as [String: Any],
        ]
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
            throw Self.map(error?.takeRetainedValue())
        }
    }

    func delete() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]
        SecItemDelete(query as CFDictionary)
    }

    var exists: Bool {
        (try? privateKey(context: nil)) != nil
    }

    // MARK: wrap / unwrap

    /// Encrypts to the public key. No Face ID needed: anyone may lock, only the enclave can unlock.
    func wrap(_ plaintext: UnsafeRawBufferPointer) throws -> Data {
        guard plaintext.count > 0 else { throw Failure.failed(-1) }
        guard let pub = SecKeyCopyPublicKey(try privateKey(context: nil)) else {
            throw Failure.invalidated
        }
        guard SecKeyIsAlgorithmSupported(pub, .encrypt, Self.algorithm) else {
            throw Failure.unavailable
        }
        let input = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: plaintext.baseAddress!),
                         count: plaintext.count, deallocator: .none)
        var error: Unmanaged<CFError>?
        guard let out = SecKeyCreateEncryptedData(pub, Self.algorithm, input as CFData, &error) else {
            throw Self.map(error?.takeRetainedValue())
        }
        return out as Data
    }

    /// Decrypts inside the Secure Enclave; iOS shows the Face ID prompt. The plaintext is handed to
    /// `use` and the buffer is overwritten immediately afterwards. Blocks: call off the main thread.
    func unwrap(_ blob: Data, reason: String, use: (UnsafeRawBufferPointer) throws -> Void) throws {
        let context = LAContext()
        context.localizedReason = reason
        context.localizedFallbackTitle = ""          // no "Enter Passcode" fallback
        context.touchIDAuthenticationAllowableReuseDuration = 0
        defer { context.invalidate() }
        let key = try privateKey(context: context)
        var error: Unmanaged<CFError>?
        guard let plain = SecKeyCreateDecryptedData(key, Self.algorithm, blob as CFData, &error) else {
            throw Self.map(error?.takeRetainedValue())
        }
        let length = CFDataGetLength(plain)
        // CFData is immutable by API but its storage is ordinary heap memory: wipe it after use.
        let base = UnsafeMutableRawPointer(mutating: CFDataGetBytePtr(plain)!)
        defer { memset_s(base, length, 0, length) }
        try use(UnsafeRawBufferPointer(start: base, count: length))
    }

    // MARK: internals

    private func privateKey(context: LAContext?) throws -> SecKey {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let item else {
            throw status == errSecItemNotFound ? Failure.invalidated : Failure.failed(Int(status))
        }
        // swiftlint:disable:next force_cast
        return (item as! SecKey)
    }

    /// LocalAuthentication and Security share small negative codes (e.g. -4), so the error domain
    /// decides which table applies.
    private static func map(_ error: CFError?) -> Failure {
        guard let error else { return .failed(-1) }
        let code = CFErrorGetCode(error)
        if (CFErrorGetDomain(error) as String) == LAErrorDomain {
            switch LAError.Code(rawValue: code) {
            case .userCancel, .systemCancel, .appCancel, .userFallback:
                return .cancelled
            case .authenticationFailed:
                return .notRecognised
            case .passcodeNotSet:
                return .noPasscode
            case .biometryLockout:
                return .lockedOut
            case .biometryNotAvailable:
                return .biometryOff
            case .biometryNotEnrolled, .invalidContext:
                return .invalidated
            default:
                return .failed(code)
            }
        }
        switch OSStatus(truncatingIfNeeded: code) {
        case errSecUserCanceled:
            return .cancelled
        case errSecAuthFailed:
            return .notRecognised
        case errSecItemNotFound:
            return .invalidated
        case errSecUnimplemented, errSecNotAvailable, errSecParam:
            return .unavailable
        default:
            return .failed(code)
        }
    }
}
