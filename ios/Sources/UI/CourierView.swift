import SwiftUI
import UniformTypeIdentifiers

/// Courier: pair with the other Scytale once, then send and receive sealed messages by email.
struct CourierView: View {
    @ObservedObject var model: AppModel

    enum Importing { case bundle, message }

    @State private var status: CourierStatus?
    @State private var safety: String?
    @State private var bundleFile: URL?
    @State private var note: (String, Note.Kind)?
    /// Which import the picker is for. Kept separate from the presentation flag: iOS clears the
    /// flag before the completion runs, so the choice must not live in it.
    @State private var importKind: Importing = .bundle
    @State private var showImporter = false
    @State private var text = ""
    @State private var burn = true
    @State private var asFile = true
    @State private var sealed: Sealed?
    @State private var sendNote: (String, Note.Kind)?
    @State private var showExporter = false

    /// The last sealed output, shown right under the Seal button until the next seal.
    enum Sealed { case file(URL, Data), text(String) }
    @State private var confirmUnpair = false

    var body: some View {
        Panel(title: "COURIER", close: { model.overlay = nil; model.touch() }) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    statusLine
                    if let note { Note(text: note.0, kind: note.1) }
                    if let busy = model.busy {
                        HStack(spacing: 10) { ProgressView().tint(Theme.green); Note(text: busy) }
                    }
                    if status?.verified == true {
                        sendSection
                        Divider().overlay(Theme.line)
                        receiveSection
                        Divider().overlay(Theme.line)
                    }
                    pairingSection
                }
            }
        }
        .onAppear(perform: refresh)
        .fileExporter(isPresented: $showExporter, document: SealedDocument(data: exportData),
                      contentType: .data, defaultFilename: exportName) { result in
            if case .success(let url) = result {
                sendNote = ("Saved: \(url.lastPathComponent)", .ok)
            } else {
                sendNote = ("Not saved.", .warn)
            }
            model.touch()
        }
        .fileImporter(isPresented: $showImporter,
                      allowedContentTypes: [.item], allowsMultipleSelection: false) { result in
            let kind = importKind
            guard case .success(let urls) = result, let url = urls.first, let data = Self.read(url) else {
                note = ("File could not be read.", .error)
                return
            }
            kind == .bundle ? importBundle(data) : receive(data)
        }
    }

    // MARK: sections

    private var statusLine: some View {
        Group {
            if let s = status {
                if !s.paired {
                    Note(text: "No device paired.")
                } else if !s.verified {
                    Note(text: "Paired · not verified. Compare safety numbers.", kind: .warn)
                } else {
                    Note(text: "Paired · verified · \(s.peerKeys) one-time key(s) left to send · \(s.ownKeys) issued", kind: .ok)
                }
            }
        }
    }

    private var sendSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("SEND").font(Theme.small.weight(.bold)).foregroundStyle(Theme.dim)
            SealedTextEditor(text: $text) { model.touch() }.frame(minHeight: 160)
            HStack {
                Text("Destroy when received").font(Theme.small).foregroundStyle(Theme.text)
                Spacer()
                Picker("", selection: $burn) {
                    Text("Yes").tag(true)
                    Text("No").tag(false)
                }
                .pickerStyle(.segmented)
                .frame(width: 130)
            }
            HStack {
                Text("Output").font(Theme.small).foregroundStyle(Theme.text)
                Spacer()
                Picker("", selection: $asFile) {
                    Text("File").tag(true)
                    Text("Raw text").tag(false)
                }
                .pickerStyle(.segmented)
                .frame(width: 170)
            }
            PrimaryButton(title: "Seal", enabled: !text.isEmpty && text.utf8.count <= 16384 && model.busy == nil) { seal() }
            if let sendNote { Note(text: sendNote.0, kind: sendNote.1) }
            if let sealed { result(sealed) }
        }
    }

    /// What to do with what was just sealed: a real file via Files or the share sheet, or the raw
    /// encrypted text for an email body.
    @ViewBuilder
    private func result(_ s: Sealed) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            switch s {
            case .file(let url, _):
                Note(text: url.lastPathComponent, kind: .ok, icon: "doc.fill")
                HStack(spacing: 10) {
                    actionButton("Save to Files…", "folder") { showExporter = true; model.touch() }
                    ShareLink(item: url, preview: SharePreview("Scytale message")) {
                        actionLabel("Email / share…", "square.and.arrow.up")
                    }
                }
            case .text(let armored):
                ScrollView {
                    Text(armored)
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundStyle(Theme.text)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                }
                .frame(height: 140)
                .background(RoundedRectangle(cornerRadius: 8).fill(Theme.panel))
                HStack(spacing: 10) {
                    actionButton("Copy", "doc.on.doc") {
                        model.copyCiphertext(armored)
                        sendNote = ("Copied · local clipboard · clears in 10 min. Paste into an email body.", .ok)
                    }
                    ShareLink(item: armored, subject: Text("Scytale message")) {
                        actionLabel("Email…", "envelope")
                    }
                }
            }
            Note(text: "Ciphertext only. Only the paired device can open it.")
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).stroke(Theme.green.opacity(0.5), lineWidth: 1))
    }

    private func actionButton(_ title: String, _ icon: String, _ action: @escaping () -> Void) -> some View {
        Button(action: action) { actionLabel(title, icon) }
    }

    private func actionLabel(_ title: String, _ icon: String) -> some View {
        Label(title, systemImage: icon)
            .font(Theme.small.weight(.semibold))
            .frame(maxWidth: .infinity, minHeight: 44)
            .foregroundStyle(Theme.green)
            .background(RoundedRectangle(cornerRadius: 10).stroke(Theme.green, lineWidth: 1.5))
    }

    private var exportData: Data {
        if case .file(_, let d) = sealed { return d }
        return Data()
    }

    private var exportName: String {
        if case .file(let url, _) = sealed { return url.lastPathComponent }
        return "Scytale message.scy"
    }

    private var receiveSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("RECEIVE").font(Theme.small.weight(.bold)).foregroundStyle(Theme.dim)
            HStack(spacing: 10) {
                Button { importKind = .message; showImporter = true; model.touch() } label: {
                    Label("Import file", systemImage: "doc.badge.arrow.up").frame(maxWidth: .infinity, minHeight: 40)
                }
                PasteButton(payloadType: String.self) { strings in
                    Task { @MainActor in
                        guard let s = strings.first else { return }
                        receive(Data(s.utf8))
                    }
                }
                .labelStyle(.titleAndIcon)
                .tint(Theme.green)
            }
            .font(Theme.small)
            .foregroundStyle(Theme.green)
            .disabled(model.busy != nil)
        }
    }

    private var pairingSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("PAIRING").font(Theme.small.weight(.bold)).foregroundStyle(Theme.dim)
            Note(text: "Exchange key bundles by email, then compare the safety number on both screens.")
            HStack(spacing: 10) {
                Button {
                    bundleFile = model.courierExportBundleFile()
                    refresh()
                } label: {
                    Label("Export bundle", systemImage: "key.horizontal").frame(maxWidth: .infinity, minHeight: 40)
                }
                Button { importKind = .bundle; showImporter = true; model.touch() } label: {
                    Label("Import bundle", systemImage: "tray.and.arrow.down").frame(maxWidth: .infinity, minHeight: 40)
                }
            }
            .font(Theme.small)
            .foregroundStyle(Theme.green)
            if let url = bundleFile {
                ShareLink(item: url, preview: SharePreview("Scytale key bundle")) {
                    Label("Share key bundle", systemImage: "square.and.arrow.up")
                        .font(Theme.mono.weight(.semibold))
                        .frame(maxWidth: .infinity, minHeight: 44)
                        .foregroundStyle(Theme.green)
                        .background(RoundedRectangle(cornerRadius: 10).stroke(Theme.green, lineWidth: 1.5))
                }
                Note(text: "Public keys only. Send a fresh bundle whenever the other device runs low on one-time keys.")
            }
            if status?.paired == true, let safety {
                Text("SAFETY NUMBER").font(Theme.small.weight(.bold)).foregroundStyle(Theme.dim)
                Text(safety)
                    .font(.system(.title3, design: .monospaced).weight(.semibold))
                    .foregroundStyle(Theme.text)
                    .textSelection(.disabled)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(12)
                    .background(RoundedRectangle(cornerRadius: 10).fill(Theme.panel))
                if status?.verified == false {
                    Note(text: "Must match the number on the other device exactly. If it differs, do not verify: a key was swapped.", kind: .warn)
                    PrimaryButton(title: "Numbers match: verify") {
                        if model.courierVerify() { note = ("Pairing verified.", .ok) }
                        refresh()
                    }
                }
                if confirmUnpair {
                    HStack {
                        Note(text: "Unpair? Messages in transit become unreadable.", kind: .error)
                        Spacer()
                        Button("Unpair") {
                            if model.courierUnpair() { note = ("Unpaired.", .ok) }
                            confirmUnpair = false
                            refresh()
                        }
                        .font(Theme.small.bold()).foregroundStyle(Theme.error)
                    }
                } else {
                    Button("Unpair…") { confirmUnpair = true }.font(Theme.small).foregroundStyle(Theme.error)
                }
            }
        }
    }

    // MARK: actions

    private func refresh() {
        status = model.courierStatus()
        safety = status?.paired == true ? model.courierSafety() : nil
    }

    private func importBundle(_ data: Data) {
        let r = model.courierImportBundle(data)
        note = (r.message, r.ok ? .ok : .error)
        refresh()
    }

    private func seal() {
        sealed = nil
        sendNote = nil
        switch model.courierSend(text, burn: burn, asFile: asFile) {
        case .file(let url):
            sealed = .file(url, (try? Data(contentsOf: url)) ?? Data())
            text = ""
            sendNote = ("Sealed\(burn ? " · destroy when received" : ""). Save it or email it below.", .ok)
        case .text(let armored):
            sealed = .text(armored)
            text = ""
            sendNote = ("Sealed\(burn ? " · destroy when received" : ""). Copy it or email it below.", .ok)
        case .failed(let message):
            sendNote = (message, .error)
        }
        refresh()
    }

    private func receive(_ data: Data) {
        note = nil
        model.courierReceive(data) { message in
            if let message { note = (message, .error) }
            refresh()
        }
    }

    private static func read(_ url: URL) -> Data? {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        var out: Data?
        var err: NSError?
        NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &err) { u in
            out = try? Data(contentsOf: u, options: [.mappedIfSafe])
        }
        guard let d = out, d.count <= 4 * 1024 * 1024 else { return nil }
        return d
    }
}

/// A sealed courier file for "Save to Files" (ciphertext only).
struct SealedDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    let data: Data

    init(data: Data) { self.data = data }

    init(configuration: ReadConfiguration) throws {
        data = configuration.file.regularFileContents ?? Data()
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}