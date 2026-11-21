import PhotosUI
import SwiftUI

/// The unlocked vault: encrypted items, and three ways in (Scytale's camera, the photo library,
/// the Files app). Opening an item needs Face ID every time.
struct HomeView: View {
    @ObservedObject var model: AppModel
    @State private var confirmWipe = false
    @State private var wipeText = ""
    @State private var showDiagnostics = false
    @State private var importingFiles = false
    @State private var photoPicks: [PhotosPickerItem] = []
    @State private var confirmDelete: Data?

    var body: some View {
        ZStack {
            list
            if model.showCamera {
                CameraView(model: model).transition(.move(edge: .bottom))
            }
            if let o = model.overlay {
                switch o {
                case .compose: MessageComposer(model: model)
                case .courier: CourierView(model: model)
                case .loginLog: LoginLogView(model: model)
                case .configuration: ConfigurationView(model: model)
                }
            }
            if let m = model.openMessage {
                MessageReader(model: model, message: m).id(m.id)
            }
            if let item = model.tagging {
                TagEditorView(model: model, item: item).id(item.id)
            }
            if let item = model.selected, model.viewer == nil {
                EncryptedItemView(model: model, item: item).id(item.id)
            }
            if let content = model.viewer {
                ViewerView(model: model, content: content)
                    .id(content.id)
                    .transition(.opacity)
            }
        }
        .fileImporter(isPresented: $importingFiles, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
            model.touch()
            if case .success(let urls) = result { model.importFiles(urls) }
        }
        .onChange(of: photoPicks) { _, picks in
            guard !picks.isEmpty else { return }
            model.importPhotos(picks)
            photoPicks = []
        }
        .sheet(isPresented: $showDiagnostics) { DiagnosticsView() }
    }

    private var list: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Text("VAULT").font(Theme.title).foregroundStyle(Theme.green)
                    Spacer()
                    Button { model.lock(.logout) } label: {
                        Label("Lock", systemImage: "lock.fill").font(Theme.small.weight(.semibold))
                    }
                    .foregroundStyle(Theme.green)
                }
                .padding(.top, 24)

                ForEach(Array(model.summaryLines.enumerated()), id: \.offset) { _, line in
                    Note(text: line.0, kind: line.1)
                }

                addButtons
                actionButtons

                if let note = model.vaultNote {
                    Note(text: note.0, kind: note.1)
                }
                if let originals = model.originals { originalsPrompt(originals) }
                if let busy = model.busy {
                    HStack(spacing: 10) { ProgressView().tint(Theme.green); Note(text: busy) }
                }

                if model.items.isEmpty {
                    Note(text: "Vault empty.", icon: "tray")
                        .padding(.vertical, 20)
                } else {
                    if !model.tagDefs.isEmpty { TagFilterBar(model: model) }
                    VStack(spacing: 0) {
                        ForEach(model.visibleItems) { item in
                            row(item)
                            Divider().overlay(Theme.line)
                        }
                    }
                    .background(RoundedRectangle(cornerRadius: 10).fill(Theme.panel))
                }

                Note(text: "Auto-lock: \(model.config.timeoutMin) min idle\(model.config.lockOnLeave ? " · app switch" : "") · device lock · screen capture", icon: "timer")
                    .padding(.top, 8)

                Button("Diagnostics") { showDiagnostics = true }
                    .font(Theme.small).foregroundStyle(Theme.dim)

                Divider().overlay(Theme.line).padding(.vertical, 6)
                panicWipe
            }
            .padding(20)
        }
    }

    private var addButtons: some View {
        HStack(spacing: 10) {
            addTile("Camera", "camera.fill") { model.touch(); model.showCamera = true }
            PhotosPicker(selection: $photoPicks, maxSelectionCount: 50, matching: .images,
                         photoLibrary: .shared()) {
                tileLabel("Photos", "photo.on.rectangle")
            }
            .simultaneousGesture(TapGesture().onEnded { model.touch() })
            addTile("Files", "folder.fill") { model.touch(); importingFiles = true }
        }
        .disabled(model.busy != nil)
    }

    private var actionButtons: some View {
        HStack(spacing: 10) {
            smallAction("Message", "square.and.pencil") { model.overlay = .compose }
            smallAction("Courier", "envelope.badge.shield.half.filled") { model.overlay = .courier }
            smallAction("Login log", "list.bullet.rectangle") { model.overlay = .loginLog }
            smallAction("Config", "slider.horizontal.3") { model.overlay = .configuration }
        }
        .disabled(model.busy != nil)
    }

    private func smallAction(_ title: String, _ icon: String, action: @escaping () -> Void) -> some View {
        Button {
            model.touch()
            action()
        } label: {
            VStack(spacing: 4) {
                Image(systemName: icon).font(.body)
                Text(title).font(.system(size: 10, design: .monospaced))
            }
            .foregroundStyle(Theme.text)
            .frame(maxWidth: .infinity, minHeight: 50)
            .background(RoundedRectangle(cornerRadius: 10).fill(Theme.panel))
        }
    }

    private func addTile(_ title: String, _ icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) { tileLabel(title, icon) }
    }

    private func tileLabel(_ title: String, _ icon: String) -> some View {
        VStack(spacing: 6) {
            Image(systemName: icon).font(.title3)
            Text(title).font(Theme.small)
        }
        .foregroundStyle(Theme.green)
        .frame(maxWidth: .infinity, minHeight: 64)
        .background(RoundedRectangle(cornerRadius: 10).stroke(Theme.green.opacity(0.6), lineWidth: 1.2))
    }

    private func originalsPrompt(_ o: Originals) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            switch o {
            case .files:
                Note(text: "Encrypted and verified. Delete \(o.count) original(s) at source?", kind: .warn)
            case .photos:
                Note(text: "Encrypted and verified. Delete \(o.count) original(s) from Photos? (Recently Deleted retains 30 days)", kind: .warn)
            }
            HStack {
                Button("Keep originals") { model.originals = nil; model.touch() }.foregroundStyle(Theme.dim)
                Spacer()
                Button("Delete originals") { model.deleteOriginals(); model.touch() }.foregroundStyle(Theme.error).bold()
            }
            .font(Theme.small)
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).fill(Theme.panel))
    }

    private func row(_ item: VaultItem) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                Image(systemName: Self.icon(item)).foregroundStyle(Theme.green).frame(width: 24)
                VStack(alignment: .leading, spacing: 3) {
                    Text(item.isMessage ? "Message (read once)" : item.name)
                        .font(Theme.small.weight(.semibold))
                        .foregroundStyle(Theme.text)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text("\(Self.size(item.size))  ·  \(AppModel.format(item.created))")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Theme.dim)
                    let tags = model.tags(for: item)
                    if !tags.isEmpty {
                        HStack(spacing: 5) {
                            ForEach(tags.prefix(4)) { TagChip(tag: $0) }
                            if tags.count > 4 {
                                Text("+\(tags.count - 4)").font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.dim)
                            }
                        }
                        .padding(.top, 3)
                    }
                }
                Spacer()
                Button { confirmDelete = confirmDelete == item.id ? nil : item.id; model.touch() } label: {
                    Image(systemName: "ellipsis").padding(8)
                }
                .foregroundStyle(Theme.dim)
            }
            .contentShape(Rectangle())
            .onTapGesture {
                model.touch()
                if item.isMessage { model.open(item) } else { model.selected = item }
            }
            .onLongPressGesture(minimumDuration: 0.45) {
                guard !item.isMessage else { return }
                UIImpactFeedbackGenerator(style: .medium).impactOccurred()
                model.touch()
                model.tagging = item
            }
            if confirmDelete == item.id {
                HStack {
                    Note(text: "Destroy permanently? Irreversible.", kind: .error)
                    Spacer()
                    Button("Destroy") { model.purge(item); confirmDelete = nil }
                        .font(Theme.small.bold()).foregroundStyle(Theme.error)
                }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
    }

    private var panicWipe: some View {
        VStack(alignment: .leading, spacing: 12) {
            if confirmWipe {
                Note(text: "PANIC WIPE · device key, all items, audit log. Irreversible. Recovery key will not help. Type DESTROY.", kind: .error)
                TextField("", text: $wipeText)
                    .font(Theme.mono)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                    .padding(12)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Theme.panel))
                HStack {
                    Button("Cancel") { confirmWipe = false; wipeText = "" }
                        .font(Theme.mono).foregroundStyle(Theme.dim)
                    Spacer()
                    Button("Destroy vault") { model.panicWipe() }
                        .font(Theme.mono.weight(.bold))
                        .foregroundStyle(wipeText == "DESTROY" ? Theme.error : Theme.dim)
                        .disabled(wipeText != "DESTROY")
                }
            } else {
                Button("Panic wipe…") { confirmWipe = true }
                    .font(Theme.small).foregroundStyle(Theme.error)
            }
        }
    }

    static func icon(_ item: VaultItem) -> String {
        if item.isMessage { return "envelope.fill" }
        let ext = (item.name as NSString).pathExtension.lowercased()
        switch ext {
        case "jpg", "jpeg", "png", "heic", "heif", "gif", "webp", "bmp", "tif", "tiff", "img": return "photo"
        case "pdf": return "doc.richtext"
        case "doc", "docx": return "doc.text"
        case "txt", "md", "csv", "log", "json": return "text.alignleft"
        default: return "doc"
        }
    }

    static func size(_ n: UInt64) -> String {
        let units = ["B", "KiB", "MiB", "GiB", "TiB"]
        var v = Double(n)
        var i = 0
        while v >= 1024, i < units.count - 1 { v /= 1024; i += 1 }
        return i == 0 ? "\(n) B" : String(format: "%.1f %@", v, units[i])
    }
}
