import Foundation

/// Where the vault lives: Library/Application Support/Scytale inside the app's sandbox.
/// - Not in Documents, so it never appears in the Files app and cannot be shared out.
/// - Excluded from iCloud Backup and from Mac/PC (Finder/iTunes) backups.
/// - Default Data Protection class "Complete" (each file is also set individually by the core).
enum VaultLocation {
    static func directory() throws -> URL {
        let fm = FileManager.default
        let support = try fm.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                 appropriateFor: nil, create: true)
        var dir = support.appendingPathComponent("Scytale", isDirectory: true)
        let protection: [FileAttributeKey: Any] = [.protectionKey: FileProtectionType.complete]
        try fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: protection)
        try fm.setAttributes(protection, ofItemAtPath: dir.path)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try dir.setResourceValues(values)
        return dir
    }

    static func isExcludedFromBackup(_ url: URL) -> Bool {
        (try? url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup) == true
    }
}
