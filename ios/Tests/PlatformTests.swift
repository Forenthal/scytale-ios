import Security
import XCTest
@testable import Scytale

final class PlatformTests: XCTestCase {
    func testVaultFolderIsExcludedFromBackup() throws {
        let dir = try VaultLocation.directory()
        XCTAssertTrue(VaultLocation.isExcludedFromBackup(dir))
        XCTAssertTrue(dir.path.contains("/Library/Application Support/Scytale"),
                      "vault must live outside Documents so it never shows in the Files app")
    }

    func testFileProtectionProbe() {
        let r = Diagnostics.fileProtection()
        XCTAssertTrue(r.passed, r.detail)
    }

    func testKeychainItemIsDeviceOnlyAndNotSynced() throws {
        let r = Diagnostics.keychain()
        if r.detail == "OSStatus \(errSecMissingEntitlement)" {
            throw XCTSkip("simulator build has no keychain entitlement; covered by on-device diagnostics")
        }
        XCTAssertTrue(r.passed, r.detail)
    }

    func testNoICloudContainer() {
        let r = Diagnostics.noICloud()
        XCTAssertTrue(r.passed, r.detail)
    }

    func testSecureEnclaveUnavailableOnSimulatorFailsClosed() throws {
        #if targetEnvironment(simulator)
        let key = DeviceKey(tag: "com.forenthal.scytale.devicekey.unit-test")
        defer { key.delete() }
        // The simulator has no Secure Enclave: creation must fail rather than silently falling back
        // to a software key.
        XCTAssertThrowsError(try key.create())
        XCTAssertFalse(key.exists)
        #else
        throw XCTSkip("device run")
        #endif
    }
}
