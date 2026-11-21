import Foundation
import Photos
import PhotosUI
import SwiftUI
import UniformTypeIdentifiers

/// Originals that were encrypted into the vault and can now be deleted from where they came from.
enum Originals {
    case files([URL])
    case photos([String])

    var count: Int {
        switch self {
        case .files(let u): return u.count
        case .photos(let p): return p.count
        }
    }
}

/// A decrypted file on screen. `data` is Scytale-owned locked memory, wiped when released.
struct ViewerContent: Identifiable {
    let id = UUID()
    let item: VaultItem
    let data: Data
}

extension AppModel {
    func reloadItems() {
        guard let core else { items = []; return }
        items = core.run { $0.items() }.sorted { $0.created > $1.created }
        reloadTags()
    }

    // MARK: import

    func importFiles(_ urls: [URL]) {
        guard let core, busy == nil, !urls.isEmpty else { return }
        busy = "Encrypting \(urls.count) file(s)…"
        let generation = lockGeneration
        core.queue.async {
            var done: [URL] = []
            var failed = 0
            for url in urls {
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                // Coordinated read: downloads iCloud Drive items first and blocks concurrent writers.
                var rc: Int32 = 2
                var coordErr: NSError?
                NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &coordErr) { readURL in
                    rc = core.importFile(path: readURL.path)
                }
                if rc == 0 { done.append(url) } else { failed += 1 }
            }
            DispatchQueue.main.async {
                self.busy = nil
                guard generation == self.lockGeneration else { return }
                self.reloadItems()
                self.importFinished(ok: done.count, failed: failed, originals: done.isEmpty ? nil : .files(done))
            }
        }
    }

    func importPhotos(_ picks: [PhotosPickerItem]) {
        guard let core, busy == nil, !picks.isEmpty else { return }
        busy = "Encrypting \(picks.count) photo(s)…"
        let generation = lockGeneration
        Task { @MainActor in
            var ok = 0
            var failed = 0
            var ids: [String] = []
            let stamp = Self.fileStamp()
            for (i, pick) in picks.enumerated() {
                guard generation == lockGeneration else { break }
                guard let data = try? await pick.loadTransferable(type: Data.self) else {
                    failed += 1
                    continue
                }
                let ext = pick.supportedContentTypes.first?.preferredFilenameExtension ?? "img"
                let name = picks.count > 1 ? "Photo \(stamp) (\(i + 1)).\(ext)" : "Photo \(stamp).\(ext)"
                let rc = await withCheckedContinuation { cont in
                    core.queue.async { cont.resume(returning: core.importBytes(name: name, data: data, photo: true)) }
                }
                if rc == 0 {
                    ok += 1
                    if let id = pick.itemIdentifier { ids.append(id) }
                } else {
                    failed += 1
                }
            }
            clearTemporaryDirectory()
            busy = nil
            guard generation == lockGeneration else { return }
            reloadItems()
            importFinished(ok: ok, failed: failed, originals: ids.isEmpty ? nil : .photos(ids))
        }
    }

    /// A photo taken with Scytale's own camera: it exists only in memory until it is encrypted.
    func importCapture(_ data: Data, ext: String) {
        guard let core else { return }
        let name = "Camera \(Self.fileStamp()).\(ext)"
        let generation = lockGeneration
        core.queue.async {
            let rc = core.importBytes(name: name, data: data, photo: true)
            DispatchQueue.main.async {
                guard generation == self.lockGeneration else { return }
                self.reloadItems()
                self.vaultNote = rc == 0 ? ("Photo encrypted.", .ok)
                                         : ("Photo encryption failed.", .error)
            }
        }
    }

    private func importFinished(ok: Int, failed: Int, originals: Originals?) {
        touch()
        if failed == 0 {
            vaultNote = ("Encrypted · \(ok) item(s)", .ok)
        } else {
            vaultNote = ("Encrypted · \(ok) · failed · \(failed) (originals untouched)", .warn)
        }
        switch config.originals {
        case 1:  // configured: always delete originals
            self.originals = originals
            if originals != nil { deleteOriginals() }
        case 2:  // configured: always keep originals
            self.originals = nil
        default:
            self.originals = originals
        }
    }

    static func fileStamp() -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH.mm.ss"
        return f.string(from: Date())
    }

    // MARK: delete originals

    func deleteOriginals() {
        guard let originals else { return }
        self.originals = nil
        switch originals {
        case .files(let urls):
            var failed = 0
            for url in urls {
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                var err: NSError?
                var removed = false
                NSFileCoordinator().coordinate(writingItemAt: url, options: .forDeleting, error: &err) { u in
                    removed = (try? FileManager.default.removeItem(at: u)) != nil
                }
                if !removed { failed += 1 }
            }
            vaultNote = failed == 0
                ? ("Originals deleted. iCloud Drive: Recently Deleted retains 30 days.", .ok)
                : ("Deleted · \(urls.count - failed) · failed · \(failed). Delete remainder in Files.", .warn)
        case .photos(let ids):
            Task { @MainActor in
                let status = await PHPhotoLibrary.requestAuthorization(for: .readWrite)
                guard status == .authorized || status == .limited else {
                    vaultNote = ("Photos access denied. Originals kept.", .warn)
                    return
                }
                let assets = PHAsset.fetchAssets(withLocalIdentifiers: ids, options: nil)
                guard assets.count > 0 else {
                    vaultNote = ("Originals outside granted access. Delete in Photos.", .warn)
                    return
                }
                do {
                    try await PHPhotoLibrary.shared().performChanges {
                        PHAssetChangeRequest.deleteAssets(assets)
                    }
                    vaultNote = ("Originals moved to Recently Deleted. Empty it: Photos › Albums › Recently Deleted.", .ok)
                } catch {
                    vaultNote = ("Deletion failed. Delete in Photos.", .warn)
                }
            }
        }
    }

    // MARK: open / close / purge

    func open(_ item: VaultItem) {
        guard let core, busy == nil else { return }
        guard let wrapped = core.run({ $0.wrappedPepper() }) else { return }
        busy = "Verifying…"
        let generation = lockGeneration
        let needFaceID = core.run { $0.reauthRequired }
        core.queue.async {
            var reauth: (code: Int32, aux: UInt64)?
            var failure: DeviceKey.Failure?
            if !needFaceID {
                reauth = (0, 0)  // configured: Face ID once per session, already given
            } else {
                do {
                    try DeviceKey.vault.unwrap(wrapped, reason: item.isMessage ? "Read a message once" : "Open a file in Scytale") { pepper in
                        reauth = core.reauth(pepper: pepper)
                    }
                } catch let f as DeviceKey.Failure {
                    if f == .notRecognised { reauth = core.reauth(pepper: nil) } else { failure = f }
                } catch {
                    failure = .failed(-1)
                }
            }
            var opened: (code: Int32, data: Data?)?
            if reauth?.code == 0 {
                opened = item.isMessage ? core.openMessage(item.id) : core.openView(item.id)
            }
            DispatchQueue.main.async {
                self.busy = nil
                guard generation == self.lockGeneration else { return }
                self.touch()
                if let failure {
                    self.vaultNote = (Self.message(for: failure), .warn)
                    return
                }
                switch reauth?.code {
                case 0:
                    switch opened?.code {
                    case 0:
                        guard let data = opened?.data else { break }
                        if item.isMessage {
                            // Already destroyed on disk; it now exists only on screen.
                            self.openMessage = MessageContent(text: String(decoding: data, as: UTF8.self), lifetime: TimeInterval(self.config.messageMin * 60))
                            self.reloadItems()
                        } else {
                            self.viewer = ViewerContent(item: item, data: data)
                        }
                    case 3: self.vaultNote = ("Exceeds 64 MiB in-memory limit.", .warn)
                    case 4: self.vaultNote = ("Integrity failure: corrupt or modified. Not opened.", .error)
                    default: self.vaultNote = ("Open failed.", .error)
                    }
                case 1: self.vaultNote = ("Face ID: no match. \(reauth?.aux ?? 0) attempt(s) before lockout.", .warn)
                case 2:
                    self.lock(.logout)
                    self.show("Locked: repeated Face ID failures.", warn: true)
                default: break
                }
            }
        }
    }

    /// Re-encrypt: wipes the decrypted copy (the vault file itself never stopped being encrypted)
    /// and returns to the list. The bytes are zeroed once SwiftUI releases the last view of them.
    func reencrypt() {
        guard let content = viewer else { return }
        viewer = nil
        selected = nil
        if let core { core.queue.async { core.auditReencrypted(automatic: false) } }
        vaultNote = ("Re-encrypted · \(content.item.name)", .ok)
        touch()
    }

    func purge(_ item: VaultItem) {
        guard let core, busy == nil else { return }
        if viewer?.item.id == item.id { viewer = nil }
        if selected?.id == item.id { selected = nil }
        let ok = core.run { $0.purge(item.id) }
        reloadItems()
        vaultNote = ok ? ("Destroyed · \(item.isMessage ? "message" : item.name)", .ok)
                       : ("Destroy failed.", .error)
    }
}
