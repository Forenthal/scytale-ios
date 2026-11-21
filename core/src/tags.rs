//! File tags with a colour. Tag names can reveal what a file is ("1password", "taxes"), so the
//! whole set (definitions and which items carry them) is stored sealed in the vault under a key
//! derived from the master key, like the index. Never logged.

pub const MAX_TAGS: usize = 64;
pub const MAX_NAME: usize = 32;
pub const MAX_PER_ITEM: usize = 8;
/// Colours are indices into a fixed palette chosen by the app (0..PALETTE).
pub const PALETTE: u8 = 8;
const MAGIC: &[u8; 5] = b"SCYT\x01";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tag {
    pub id: u16,
    pub name: String,
    pub color: u8,
}

#[derive(Default, Debug)]
pub struct Tags {
    pub defs: Vec<Tag>,
    /// item id -> tag ids
    pub assigned: Vec<([u8; 16], Vec<u16>)>,
    next_id: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagErr {
    BadName = 1,
    BadColor = 2,
    TooMany = 3,
    NoSuchTag = 4,
    ItemFull = 5,
}

/// Trimmed, single line, printable, 1..=32 characters.
fn clean_name(name: &str) -> Result<String, TagErr> {
    let n: String = name.trim().chars().filter(|c| !c.is_control()).collect();
    if n.is_empty() || n.chars().count() > MAX_NAME {
        return Err(TagErr::BadName);
    }
    Ok(n)
}

impl Tags {
    /// Create a tag, or return the existing one with the same name (case-insensitive), updating
    /// its colour: naming "1password" again reuses the saved tag.
    pub fn create(&mut self, name: &str, color: u8) -> Result<u16, TagErr> {
        let name = clean_name(name)?;
        if color >= PALETTE {
            return Err(TagErr::BadColor);
        }
        if let Some(t) = self.defs.iter_mut().find(|t| t.name.to_lowercase() == name.to_lowercase()) {
            t.color = color;
            return Ok(t.id);
        }
        if self.defs.len() >= MAX_TAGS {
            return Err(TagErr::TooMany);
        }
        self.next_id = self.next_id.wrapping_add(1).max(1);
        while self.defs.iter().any(|t| t.id == self.next_id) {
            self.next_id = self.next_id.wrapping_add(1).max(1);
        }
        self.defs.push(Tag { id: self.next_id, name, color });
        Ok(self.next_id)
    }

    pub fn update(&mut self, id: u16, name: &str, color: u8) -> Result<(), TagErr> {
        let name = clean_name(name)?;
        if color >= PALETTE {
            return Err(TagErr::BadColor);
        }
        if self.defs.iter().any(|t| t.id != id && t.name.to_lowercase() == name.to_lowercase()) {
            return Err(TagErr::BadName);
        }
        let t = self.defs.iter_mut().find(|t| t.id == id).ok_or(TagErr::NoSuchTag)?;
        t.name = name;
        t.color = color;
        Ok(())
    }

    /// Delete a tag and remove it from every item.
    pub fn delete(&mut self, id: u16) -> bool {
        let before = self.defs.len();
        self.defs.retain(|t| t.id != id);
        for (_, ids) in self.assigned.iter_mut() {
            ids.retain(|&x| x != id);
        }
        self.assigned.retain(|(_, ids)| !ids.is_empty());
        self.defs.len() != before
    }

    pub fn of(&self, item: &[u8; 16]) -> &[u16] {
        self.assigned.iter().find(|(i, _)| i == item).map_or(&[], |(_, ids)| ids)
    }

    pub fn set(&mut self, item: &[u8; 16], id: u16, on: bool) -> Result<(), TagErr> {
        if !self.defs.iter().any(|t| t.id == id) {
            return Err(TagErr::NoSuchTag);
        }
        let pos = self.assigned.iter().position(|(i, _)| i == item);
        match (pos, on) {
            (Some(p), true) => {
                let ids = &mut self.assigned[p].1;
                if !ids.contains(&id) {
                    if ids.len() >= MAX_PER_ITEM {
                        return Err(TagErr::ItemFull);
                    }
                    ids.push(id);
                }
            }
            (None, true) => self.assigned.push((*item, vec![id])),
            (Some(p), false) => {
                self.assigned[p].1.retain(|&x| x != id);
                if self.assigned[p].1.is_empty() {
                    self.assigned.remove(p);
                }
            }
            (None, false) => {}
        }
        Ok(())
    }

    /// Remove every tag from one item (it was destroyed). Returns whether anything changed.
    pub fn set_many_off(&mut self, item: &[u8; 16]) -> bool {
        let before = self.assigned.len();
        self.assigned.retain(|(i, _)| i != item);
        self.assigned.len() != before
    }

    /// Drop assignments for items that no longer exist. Returns whether anything changed.
    pub fn retain_items(&mut self, live: &[[u8; 16]]) -> bool {
        let before = self.assigned.len();
        self.assigned.retain(|(i, _)| live.contains(i));
        self.assigned.len() != before
    }

    pub fn to_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut v = zeroize::Zeroizing::new(MAGIC.to_vec());
        v.extend_from_slice(&self.next_id.to_le_bytes());
        v.extend_from_slice(&(self.defs.len() as u16).to_le_bytes());
        for t in &self.defs {
            v.extend_from_slice(&t.id.to_le_bytes());
            v.push(t.color);
            v.push(t.name.len() as u8);
            v.extend_from_slice(t.name.as_bytes());
        }
        v.extend_from_slice(&(self.assigned.len() as u32).to_le_bytes());
        for (item, ids) in &self.assigned {
            v.extend_from_slice(item);
            v.push(ids.len() as u8);
            for id in ids {
                v.extend_from_slice(&id.to_le_bytes());
            }
        }
        v
    }

    pub fn from_bytes(b: &[u8]) -> Option<Tags> {
        let mut pos = 0usize;
        let mut take = |n: usize| -> Option<&[u8]> {
            let s = b.get(pos..pos + n)?;
            pos += n;
            Some(s)
        };
        if take(5)? != MAGIC {
            return None;
        }
        let next_id = u16::from_le_bytes(take(2)?.try_into().ok()?);
        let n = u16::from_le_bytes(take(2)?.try_into().ok()?) as usize;
        if n > MAX_TAGS {
            return None;
        }
        let mut defs = Vec::with_capacity(n);
        for _ in 0..n {
            let id = u16::from_le_bytes(take(2)?.try_into().ok()?);
            let color = take(1)?[0];
            let len = take(1)?[0] as usize;
            let name = String::from_utf8(take(len)?.to_vec()).ok()?;
            defs.push(Tag { id, name, color: color.min(PALETTE - 1) });
        }
        let m = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
        let mut assigned = Vec::new();
        for _ in 0..m {
            let item: [u8; 16] = take(16)?.try_into().ok()?;
            let k = take(1)?[0] as usize;
            let mut ids = Vec::with_capacity(k);
            for _ in 0..k {
                ids.push(u16::from_le_bytes(take(2)?.try_into().ok()?));
            }
            assigned.push((item, ids));
        }
        if pos != b.len() {
            return None;
        }
        Some(Tags { defs, assigned, next_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_reuse_names_toggle_and_round_trip() {
        let mut t = Tags::default();
        let a = t.create("1password", 3).unwrap();
        assert_eq!(t.create("  1PASSWORD ", 5).unwrap(), a, "same name = same saved tag");
        assert_eq!(t.defs[0].color, 5);
        assert_eq!(t.create("", 0), Err(TagErr::BadName));
        assert_eq!(t.create(&"x".repeat(33), 0), Err(TagErr::BadName));
        assert_eq!(t.create("ok", PALETTE), Err(TagErr::BadColor));
        let b = t.create("taxes", 1).unwrap();
        let item = [7u8; 16];
        t.set(&item, a, true).unwrap();
        t.set(&item, b, true).unwrap();
        t.set(&item, a, true).unwrap();
        assert_eq!(t.of(&item), &[a, b]);
        assert_eq!(t.update(b, "1password", 2), Err(TagErr::BadName), "no duplicate names");
        t.update(b, "tax 2026", 2).unwrap();
        let r = Tags::from_bytes(&t.to_bytes()).unwrap();
        assert_eq!(r.defs, t.defs);
        assert_eq!(r.of(&item), &[a, b]);
        assert!(t.delete(a));
        assert_eq!(t.of(&item), &[b]);
        t.set(&item, b, false).unwrap();
        assert!(t.assigned.is_empty());
        assert!(t.retain_items(&[]) == false);
        assert!(Tags::from_bytes(&t.to_bytes()[..6]).is_none());
    }
}
