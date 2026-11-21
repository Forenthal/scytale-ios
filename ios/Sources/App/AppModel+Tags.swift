import Foundation

extension AppModel {
    func reloadTags() {
        guard let core else { tagDefs = []; itemTags = [:]; return }
        let t = core.run { $0.tags() }
        tagDefs = t.defs.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        itemTags = t.assigned
        if let f = tagFilter, !tagDefs.contains(where: { $0.id == f }) { tagFilter = nil }
    }

    func tags(for item: VaultItem) -> [VaultTag] {
        let ids = itemTags[item.id] ?? []
        return ids.compactMap { id in tagDefs.first { $0.id == id } }
    }

    /// Create (or reuse a saved tag with the same name) and apply it to `item`.
    @discardableResult
    func tagAdd(_ name: String, color: Int, to item: VaultItem) -> Bool {
        touch()
        guard let core, let id = core.run({ $0.tagCreate(name, color: color) }) else { return false }
        let ok = core.run { $0.tagSet(item: item.id, tag: id, on: true) }
        reloadTags()
        return ok
    }

    func tagToggle(_ tag: VaultTag, on item: VaultItem) {
        touch()
        let on = !(itemTags[item.id] ?? []).contains(tag.id)
        _ = core?.run { $0.tagSet(item: item.id, tag: tag.id, on: on) }
        reloadTags()
    }

    @discardableResult
    func tagUpdate(_ tag: VaultTag, name: String, color: Int) -> Bool {
        touch()
        let ok = core?.run { $0.tagUpdate(tag.id, name: name, color: color) } ?? false
        reloadTags()
        return ok
    }

    func tagDelete(_ tag: VaultTag) {
        touch()
        _ = core?.run { $0.tagDelete(tag.id) }
        reloadTags()
    }

    /// Items shown in the list (filtered by the selected tag, if any).
    var visibleItems: [VaultItem] {
        guard let f = tagFilter else { return items }
        return items.filter { (itemTags[$0.id] ?? []).contains(f) }
    }
}
