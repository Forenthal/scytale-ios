import SwiftUI
import UIKit

/// Eight colours tuned for the dark interface; tags store an index into this list.
enum TagPalette {
    static let colors: [Color] = [
        Color(red: 64 / 255, green: 220 / 255, blue: 120 / 255),   // mint (Scytale green)
        Color(red: 45 / 255, green: 212 / 255, blue: 191 / 255),   // teal
        Color(red: 96 / 255, green: 165 / 255, blue: 250 / 255),   // sky
        Color(red: 167 / 255, green: 139 / 255, blue: 250 / 255),  // violet
        Color(red: 244 / 255, green: 114 / 255, blue: 182 / 255),  // rose
        Color(red: 248 / 255, green: 113 / 255, blue: 113 / 255),  // coral
        Color(red: 251 / 255, green: 191 / 255, blue: 36 / 255),   // amber
        Color(red: 148 / 255, green: 163 / 255, blue: 184 / 255),  // slate
    ]
    static let names = ["Mint", "Teal", "Sky", "Violet", "Rose", "Coral", "Amber", "Slate"]

    static func color(_ i: Int) -> Color { colors[max(0, min(i, colors.count - 1))] }
}

/// Small rounded chip: dot, name, soft tint, hairline border.
struct TagChip: View {
    let tag: VaultTag
    var selected = false

    var body: some View {
        let c = TagPalette.color(tag.color)
        HStack(spacing: 5) {
            Circle().fill(c).frame(width: 6, height: 6)
            Text(tag.name)
                .font(.system(size: 10.5, weight: .semibold, design: .monospaced))
                .lineLimit(1)
        }
        .foregroundStyle(c)
        .padding(.horizontal, 8)
        .padding(.vertical, 3.5)
        .background(Capsule().fill(c.opacity(selected ? 0.30 : 0.13)))
        .overlay(Capsule().stroke(c.opacity(selected ? 0.9 : 0.35), lineWidth: selected ? 1.2 : 0.75))
        .accessibilityLabel("Tag \(tag.name)")
    }
}

/// Row of palette swatches.
struct PalettePicker: View {
    @Binding var selection: Int

    var body: some View {
        HStack(spacing: 10) {
            ForEach(0..<TagPalette.colors.count, id: \.self) { i in
                Circle()
                    .fill(TagPalette.colors[i])
                    .frame(width: 24, height: 24)
                    .overlay(Circle().stroke(Theme.background, lineWidth: selection == i ? 2.5 : 0).padding(2.5))
                    .overlay(Circle().stroke(TagPalette.colors[i], lineWidth: selection == i ? 1.5 : 0).padding(-2))
                    .contentShape(Circle())
                    .onTapGesture { selection = i }
                    .accessibilityLabel(TagPalette.names[i])
                    .accessibilityAddTraits(selection == i ? .isSelected : [])
            }
        }
    }
}

/// Filter bar above the list: All, then each tag.
struct TagFilterBar: View {
    @ObservedObject var model: AppModel

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                Button { model.tagFilter = nil; model.touch() } label: {
                    Text("All")
                        .font(.system(size: 10.5, weight: .semibold, design: .monospaced))
                        .foregroundStyle(model.tagFilter == nil ? Color.black : Theme.dim)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 3.5)
                        .background(Capsule().fill(model.tagFilter == nil ? Theme.green : Theme.panel))
                }
                ForEach(model.tagDefs) { t in
                    Button {
                        model.tagFilter = model.tagFilter == t.id ? nil : t.id
                        model.touch()
                    } label: {
                        TagChip(tag: t, selected: model.tagFilter == t.id)
                    }
                }
            }
            .padding(.vertical, 2)
        }
    }
}

/// Press-and-hold a file: apply, create, recolour, rename or delete tags. Drawn inside the
/// screen shield (never a sheet).
struct TagEditorView: View {
    @ObservedObject var model: AppModel
    let item: VaultItem

    @State private var newName = ""
    @State private var newColor = 0
    @State private var editing: VaultTag?
    @State private var editName = ""
    @State private var editColor = 0
    @State private var error: String?

    var body: some View {
        Panel(title: "TAGS", close: { model.tagging = nil; model.touch() }) {
            Text(item.name)
                .font(Theme.small.weight(.semibold))
                .foregroundStyle(Theme.text)
                .lineLimit(1)
                .truncationMode(.middle)
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    if !model.tagDefs.isEmpty { existing }
                    create
                    if let error { Note(text: error, kind: .error) }
                }
            }
        }
    }

    private var existing: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(model.tagDefs) { t in
                let on = (model.itemTags[item.id] ?? []).contains(t.id)
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 12) {
                        Image(systemName: on ? "checkmark.circle.fill" : "circle")
                            .foregroundStyle(on ? TagPalette.color(t.color) : Theme.line)
                            .font(.system(size: 18))
                        TagChip(tag: t, selected: on)
                        Spacer()
                        Button {
                            if editing?.id == t.id { editing = nil } else {
                                editing = t
                                editName = t.name
                                editColor = t.color
                            }
                        } label: {
                            Image(systemName: "slider.horizontal.3").foregroundStyle(Theme.dim).padding(6)
                        }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { model.tagToggle(t, on: item) }
                    if editing?.id == t.id { editor(t) }
                }
                .padding(.vertical, 9)
                .padding(.horizontal, 12)
                Divider().overlay(Theme.line)
            }
        }
        .background(RoundedRectangle(cornerRadius: 10).fill(Theme.panel))
    }

    private func editor(_ t: VaultTag) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            nameField($editName)
            PalettePicker(selection: $editColor)
            HStack {
                Button("Delete tag") {
                    model.tagDelete(t)
                    editing = nil
                }
                .font(Theme.small).foregroundStyle(Theme.error)
                Spacer()
                Button("Save") {
                    error = model.tagUpdate(t, name: editName, color: editColor) ? nil : "Name empty, too long or already used."
                    if error == nil { editing = nil }
                }
                .font(Theme.small.weight(.bold)).foregroundStyle(Theme.green)
            }
        }
        .padding(.leading, 30)
    }

    private var create: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("NEW TAG").font(Theme.small.weight(.bold)).foregroundStyle(Theme.dim)
            nameField($newName)
            PalettePicker(selection: $newColor)
            if !newName.trimmingCharacters(in: .whitespaces).isEmpty {
                HStack(spacing: 8) {
                    Text("Preview").font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.dim)
                    TagChip(tag: VaultTag(id: 0, name: String(newName.prefix(32)), color: newColor), selected: true)
                }
            }
            PrimaryButton(title: "Add tag", enabled: !newName.trimmingCharacters(in: .whitespaces).isEmpty) {
                if model.tagAdd(newName, color: newColor, to: item) {
                    newName = ""
                    error = nil
                } else {
                    error = "Not added: name empty or over 32 characters, or 64 tags already exist."
                }
            }
            Note(text: "Saved tags are reused: adding an existing name applies it with the chosen colour.")
        }
    }

    private func nameField(_ text: Binding<String>) -> some View {
        TextField("", text: text, prompt: Text("Tag name").foregroundStyle(Theme.dim))
            .font(Theme.mono)
            .foregroundStyle(Theme.text)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .padding(10)
            .background(RoundedRectangle(cornerRadius: 8).fill(Theme.background))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.line, lineWidth: 1))
            .onChange(of: text.wrappedValue) { _, v in if v.count > 32 { text.wrappedValue = String(v.prefix(32)) } }
    }
}
