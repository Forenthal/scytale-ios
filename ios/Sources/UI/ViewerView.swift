import PDFKit
import SwiftUI
import UIKit

/// In-memory viewer. Drawn inside the screen shield (never as a sheet: iOS presents sheets outside
/// the protected layer). Images, PDFs and text render natively; everything else as hex. Nothing is
/// written to storage, and the bytes are wiped when the viewer closes.
struct ViewerView: View {
    @ObservedObject var model: AppModel
    let content: ViewerContent

    @State private var hex = false
    @State private var rendered: Rendered?

    enum Rendered {
        case image(UIImage)
        case pdf(PDFDocument)
        case lockedPDF
        case text(String)
        case word
        case binary
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(Theme.line)
            Group {
                if hex {
                    HexView(data: content.data)
                } else {
                    switch rendered {
                    case .image(let img):
                        ZoomableImage(image: img)
                    case .pdf(let doc):
                        PDFKitView(document: doc)
                    case .lockedPDF:
                        message("Password-protected PDF unsupported · hex view") { HexView(data: content.data) }
                    case .text(let s):
                        ScrollView {
                            Text(s)
                                .font(Theme.small)
                                .foregroundStyle(Theme.text)
                                .textSelection(.disabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(12)
                        }
                    case .word:
                        message("Word reading view pending · hex view") { HexView(data: content.data) }
                    case .binary, .none:
                        HexView(data: content.data)
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            // The only way out: wipe the decrypted copy.
            PrimaryButton(title: "Re-encrypt") { model.reencrypt() }
                .padding(16)
                .background(Theme.panel)
        }
        .background(Theme.background)
        .onAppear { rendered = Self.render(content.data) }
        .onDisappear { rendered = nil }
    }

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: "lock.open").foregroundStyle(Theme.warn)
            Text(content.item.name)
                .font(Theme.small.weight(.semibold))
                .lineLimit(1)
                .truncationMode(.middle)
                .foregroundStyle(Theme.text)
            Spacer()
            Button(hex ? "View" : "Hex") { hex.toggle(); model.touch() }
                .font(Theme.small).foregroundStyle(Theme.green)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    private func message<V: View>(_ text: String, @ViewBuilder _ then: () -> V) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Note(text: text, kind: .warn).padding(12)
            then()
        }
    }

    // MARK: type detection (by content, not by name)

    static func render(_ d: Data) -> Rendered {
        if d.starts(with: [0x25, 0x50, 0x44, 0x46]) { // %PDF
            guard let doc = PDFDocument(data: d) else { return .binary }
            return doc.isLocked ? .lockedPDF : .pdf(doc)
        }
        if isImage(d), let img = UIImage(data: d)?.preparingForDisplay() ?? UIImage(data: d) {
            return .image(img)
        }
        if d.starts(with: [0x50, 0x4B, 0x03, 0x04]), d.range(of: Data("word/".utf8)) != nil {
            return .word
        }
        if let s = text(d) { return .text(s) }
        return .binary
    }

    private static func isImage(_ d: Data) -> Bool {
        let b = [UInt8](d.prefix(12))
        guard b.count >= 4 else { return false }
        if b.starts(with: [0x89, 0x50, 0x4E, 0x47]) { return true }               // PNG
        if b.starts(with: [0xFF, 0xD8, 0xFF]) { return true }                     // JPEG
        if b.starts(with: [0x47, 0x49, 0x46, 0x38]) { return true }               // GIF
        if b.starts(with: [0x42, 0x4D]) { return true }                           // BMP
        if b.starts(with: [0x49, 0x49, 0x2A, 0x00]) || b.starts(with: [0x4D, 0x4D, 0x00, 0x2A]) { return true } // TIFF
        if b.count >= 12 {
            if b[0...3] == [0x52, 0x49, 0x46, 0x46], b[8...11] == [0x57, 0x45, 0x42, 0x50] { return true } // WebP
            if b[4...7] == [0x66, 0x74, 0x79, 0x70] {                              // ISO BMFF: HEIC/HEIF/AVIF
                let brand = String(decoding: b[8...11], as: UTF8.self)
                return ["heic", "heix", "hevc", "mif1", "msf1", "avif"].contains(brand)
            }
        }
        return false
    }

    /// Text in any common encoding; control characters other than whitespace are stripped.
    private static func text(_ d: Data) -> String? {
        let sample = d.prefix(4096)
        var s: String?
        if d.starts(with: [0xFF, 0xFE]) || d.starts(with: [0xFE, 0xFF]) {
            s = String(data: d, encoding: .utf16)
        } else if !sample.contains(0), let u = String(data: d, encoding: .utf8) {
            s = u
        } else if !sample.contains(0), let l = String(data: d, encoding: .windowsCP1252) {
            s = l
        }
        guard let s else { return nil }
        return String(s.unicodeScalars.filter { !$0.properties.isDefaultIgnorableCodePoint
            && !(CharacterSet.controlCharacters.contains($0) && !CharacterSet.whitespacesAndNewlines.contains($0)) })
    }
}

struct HexView: View {
    let data: Data
    private var lines: Int { (data.count + 15) / 16 }

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 2) {
                ForEach(0..<lines, id: \.self) { i in
                    Text(Self.line(data, i))
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Theme.text)
                }
            }
            .padding(12)
        }
    }

    static func line(_ d: Data, _ i: Int) -> String {
        let start = d.startIndex + i * 16
        let end = min(start + 16, d.endIndex)
        let bytes = d[start..<end]
        let hex = bytes.map { String(format: "%02x", $0) }.joined(separator: " ")
        let ascii = String(bytes.map { (0x20...0x7e).contains($0) ? Character(UnicodeScalar($0)) : "." })
        return String(format: "%08x  ", i * 16) + hex.padding(toLength: 47, withPad: " ", startingAt: 0) + "  " + ascii
    }
}

struct ZoomableImage: View {
    let image: UIImage
    @State private var scale: CGFloat = 1
    @GestureState private var pinch: CGFloat = 1

    var body: some View {
        GeometryReader { geo in
            ScrollView([.horizontal, .vertical]) {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFit()
                    .frame(width: geo.size.width * scale * pinch, height: geo.size.height * scale * pinch)
            }
            .gesture(MagnificationGesture()
                .updating($pinch) { v, s, _ in s = v }
                .onEnded { v in scale = min(max(scale * v, 1), 8) })
            .onTapGesture(count: 2) { scale = scale > 1 ? 1 : 2.5 }
        }
    }
}

/// A PDFView that cannot leak: no copy / share / look-up / translate menu, no dragging text or
/// images out, and links are never followed (a link would hand data to Safari or another app).
final class SealedPDFView: PDFView, PDFViewDelegate {
    override func canPerformAction(_ action: Selector, withSender sender: Any?) -> Bool { false }

    override func buildMenu(with builder: UIMenuBuilder) {
        super.buildMenu(with: builder)
        for m in [UIMenu.Identifier.standardEdit, .lookup, .share, .learn, .replace, .find] {
            builder.remove(menu: m)
        }
    }

    override func didAddSubview(_ subview: UIView) {
        super.didAddSubview(subview)
        Self.stripDrag(subview)
    }

    override func layoutSubviews() {
        super.layoutSubviews()
        Self.stripDrag(self)
    }

    static func stripDrag(_ v: UIView) {
        for i in v.interactions where i is UIDragInteraction || i is UIContextMenuInteraction {
            v.removeInteraction(i)
        }
        v.subviews.forEach(stripDrag)
    }

    func pdfViewWillClick(onLink sender: PDFView, with url: URL) {
        // deliberately nothing: links are not followed
    }
}

struct PDFKitView: UIViewRepresentable {
    let document: PDFDocument

    func makeUIView(context: Context) -> SealedPDFView {
        let v = SealedPDFView()
        v.delegate = v
        v.autoScales = true
        v.displayMode = .singlePageContinuous
        v.backgroundColor = UIColor(Theme.background)
        v.document = document
        return v
    }

    func updateUIView(_ v: SealedPDFView, context: Context) {}

    static func dismantleUIView(_ v: SealedPDFView, coordinator: ()) {
        v.document = nil
    }
}
