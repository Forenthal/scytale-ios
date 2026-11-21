import Foundation

/// Decrypted file contents for the viewer. The bytes live in a malloc'd, mlock'ed buffer owned by
/// the returned Data: when the last user (image decoder, PDFKit, text view) releases it, the
/// buffer is overwritten with zeros, unlocked and freed. Nothing is written to storage.
enum SecureMemory {
    static func data(count: Int, fill: (UnsafeMutableRawPointer) -> Bool) -> Data? {
        if count == 0 { return Data() }
        guard let p = malloc(count) else { return nil }
        mlock(p, count)
        guard fill(p) else {
            memset_s(p, count, 0, count)
            munlock(p, count)
            free(p)
            return nil
        }
        return Data(bytesNoCopy: p, count: count, deallocator: .custom { ptr, n in
            memset_s(ptr, n, 0, n)
            munlock(ptr, n)
            free(ptr)
        })
    }
}

/// Removes everything in the app's temporary folder. iOS may stage picked photos there during a
/// transfer; Scytale itself never writes plaintext to storage.
func clearTemporaryDirectory() {
    let fm = FileManager.default
    let tmp = fm.temporaryDirectory
    guard let items = try? fm.contentsOfDirectory(at: tmp, includingPropertiesForKeys: nil) else { return }
    for url in items { try? fm.removeItem(at: url) }
}
