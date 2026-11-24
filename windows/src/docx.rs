//! Word (.docx) reading view, parsed entirely in memory: paragraphs, headings, bold / italic /
//! underline, bulleted and numbered lists, tables, page breaks and embedded images.
//! Exact page layout (fonts, columns, positioning) is not reproduced.
//!
//! A .docx is a ZIP of XML parts. The ZIP reader here is deliberately minimal and fully bounds
//! checked (stored + deflate entries only), with limits against decompression bombs.

use std::{collections::HashMap, rc::Rc};

use quick_xml::{
    escape::resolve_predefined_entity,
    events::{BytesStart, Event},
    Reader, XmlVersion,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{gui::Pixels, viewer::decode_image};

const MAX_ENTRY: usize = 128 << 20;
const MAX_TOTAL: usize = 512 << 20;
const MAX_IMG_SIDE: u32 = 2000;

// ---------------------------------------------------------------- model

pub struct Run {
    pub text: String,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
}

impl Drop for Run {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ParaKind {
    Normal,
    Title,
    Heading(u8),
}

pub enum Block {
    Para { kind: ParaKind, prefix: String, indent: usize, list: bool, runs: Vec<Run> },
    /// rows -> cells -> runs
    Table(Vec<Vec<Vec<Run>>>),
    Image(usize),
    Unsupported(&'static str),
    PageBreak,
}

pub struct Doc {
    pub blocks: Vec<Block>,
    pub images: Vec<Rc<Pixels>>,
}

// ---------------------------------------------------------------- zip

struct Entry {
    method: u16,
    comp: usize,
    uncomp: usize,
    offset: usize,
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(i..i + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

fn zip_index(data: &[u8]) -> Option<HashMap<String, Entry>> {
    // end of central directory: last 22..65557 bytes
    let lo = data.len().saturating_sub(65_557);
    let eocd = (lo..data.len().saturating_sub(21)).rev().find(|&i| u32_at(data, i) == Some(0x0605_4b50))?;
    let count = u16_at(data, eocd + 10)? as usize;
    let mut p = u32_at(data, eocd + 16)? as usize;
    if count > 20_000 {
        return None;
    }
    let mut map = HashMap::new();
    for _ in 0..count {
        if u32_at(data, p)? != 0x0201_4b50 {
            return None;
        }
        let method = u16_at(data, p + 10)?;
        let comp = u32_at(data, p + 20)? as usize;
        let uncomp = u32_at(data, p + 24)? as usize;
        let nlen = u16_at(data, p + 28)? as usize;
        let elen = u16_at(data, p + 30)? as usize;
        let clen = u16_at(data, p + 32)? as usize;
        let offset = u32_at(data, p + 42)? as usize;
        let name = String::from_utf8_lossy(data.get(p + 46..p + 46 + nlen)?).replace('\\', "/");
        map.insert(name, Entry { method, comp, uncomp, offset });
        p = p.checked_add(46 + nlen + elen + clen)?;
    }
    Some(map)
}

struct Zip<'a> {
    data: &'a [u8],
    index: HashMap<String, Entry>,
    total: usize,
}

impl<'a> Zip<'a> {
    fn read(&mut self, name: &str) -> Option<Zeroizing<Vec<u8>>> {
        let e = self.index.get(name)?;
        if e.uncomp > MAX_ENTRY || self.total + e.uncomp > MAX_TOTAL {
            return None;
        }
        let d = self.data;
        if u32_at(d, e.offset)? != 0x0403_4b50 {
            return None;
        }
        let start = e.offset + 30 + u16_at(d, e.offset + 26)? as usize + u16_at(d, e.offset + 28)? as usize;
        let raw = d.get(start..start.checked_add(e.comp)?)?;
        let out = match e.method {
            0 => raw.to_vec(),
            8 => miniz_oxide::inflate::decompress_to_vec_with_limit(raw, e.uncomp.min(MAX_ENTRY)).ok()?,
            _ => return None,
        };
        self.total += out.len();
        Some(Zeroizing::new(out))
    }
}

pub fn is_docx(data: &[u8]) -> bool {
    data.starts_with(b"PK\x03\x04") && zip_index(data).is_some_and(|m| m.contains_key("word/document.xml"))
}

// ---------------------------------------------------------------- xml helpers

fn local(name: &str) -> &[u8] {
    let name = name.as_bytes();
    match name.iter().rposition(|&b| b == b':') {
        Some(i) => &name[i + 1..],
        None => name,
    }
}

fn attr(e: &BytesStart, key: &[u8]) -> Option<String> {
    for a in e.attributes().flatten() {
        if local(a.key.as_ref()) == key {
            return a.normalized_value(XmlVersion::Implicit1_0).ok().map(|v| v.into_owned());
        }
    }
    None
}

fn on(e: &BytesStart) -> bool {
    !matches!(attr(e, b"val").as_deref(), Some("0" | "false" | "off" | "none"))
}

fn for_each_element(xml: &[u8], mut f: impl FnMut(&BytesStart, bool)) {
    let mut r = Reader::from_reader(xml);
    let mut buf = Zeroizing::new(Vec::new());
    loop {
        match r.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => f(&e, true),
            Ok(Event::Empty(e)) => f(&e, false),
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
}

// ---------------------------------------------------------------- styles / numbering / rels

fn parse_styles(xml: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut cur: Option<String> = None;
    for_each_element(xml, |e, _| match local(e.name().as_ref()) {
        b"style" => cur = attr(e, b"styleId"),
        b"name" => {
            if let (Some(id), Some(n)) = (cur.clone(), attr(e, b"val")) {
                map.insert(id, n.to_lowercase());
            }
        }
        _ => {}
    });
    map
}

fn para_kind(style: Option<&str>, styles: &HashMap<String, String>) -> ParaKind {
    let Some(id) = style else { return ParaKind::Normal };
    let name = styles.get(id).cloned().unwrap_or_else(|| id.to_lowercase());
    let compact: String = name.chars().filter(|c| !c.is_whitespace()).collect();
    if compact == "title" {
        ParaKind::Title
    } else if compact == "subtitle" {
        ParaKind::Heading(2)
    } else if let Some(n) = compact.strip_prefix("heading") {
        ParaKind::Heading(n.parse().unwrap_or(1).clamp(1, 9))
    } else {
        ParaKind::Normal
    }
}

#[derive(Default)]
struct Numbering {
    /// abstractNumId -> per level (numFmt, lvlText)
    abs: HashMap<String, Vec<(String, String)>>,
    /// numId -> abstractNumId
    num: HashMap<String, String>,
    counters: HashMap<String, [u32; 9]>,
}

fn parse_numbering(xml: &[u8]) -> Numbering {
    let mut n = Numbering::default();
    let (mut cur_abs, mut cur_lvl, mut cur_num): (Option<String>, usize, Option<String>) = (None, 0, None);
    for_each_element(xml, |e, _| match local(e.name().as_ref()) {
        b"abstractNum" => {
            cur_abs = attr(e, b"abstractNumId");
            cur_num = None;
        }
        b"lvl" => cur_lvl = attr(e, b"ilvl").and_then(|v| v.parse().ok()).unwrap_or(0).min(8),
        b"numFmt" | b"lvlText" => {
            if let (Some(a), Some(v)) = (cur_abs.clone(), attr(e, b"val")) {
                let lv = n.abs.entry(a).or_insert_with(|| vec![(String::new(), String::new()); 9]);
                if local(e.name().as_ref()) == b"numFmt" {
                    lv[cur_lvl].0 = v;
                } else {
                    lv[cur_lvl].1 = v;
                }
            }
        }
        b"num" => {
            cur_num = attr(e, b"numId");
            cur_abs = None;
        }
        b"abstractNumId" => {
            if let (Some(id), Some(v)) = (cur_num.clone(), attr(e, b"val")) {
                n.num.insert(id, v);
            }
        }
        _ => {}
    });
    n
}

fn roman(mut v: u32) -> String {
    const T: [(u32, &str); 13] = [(1000, "m"), (900, "cm"), (500, "d"), (400, "cd"), (100, "c"), (90, "xc"), (50, "l"), (40, "xl"), (10, "x"), (9, "ix"), (5, "v"), (4, "iv"), (1, "i")];
    let mut s = String::new();
    for (n, r) in T {
        while v >= n {
            s.push_str(r);
            v -= n;
        }
    }
    s
}

fn fmt_num(v: u32, fmt: &str) -> String {
    match fmt {
        "lowerLetter" => ((b'a' + ((v.max(1) - 1) % 26) as u8) as char).to_string(),
        "upperLetter" => ((b'A' + ((v.max(1) - 1) % 26) as u8) as char).to_string(),
        "lowerRoman" => roman(v),
        "upperRoman" => roman(v).to_uppercase(),
        _ => v.to_string(),
    }
}

impl Numbering {
    fn prefix(&mut self, num_id: &str, ilvl: usize) -> String {
        let ilvl = ilvl.min(8);
        let levels = self.num.get(num_id).and_then(|a| self.abs.get(a)).cloned();
        let c = self.counters.entry(num_id.to_string()).or_insert([0; 9]);
        c[ilvl] += 1;
        for d in c.iter_mut().skip(ilvl + 1) {
            *d = 0;
        }
        let bullet = if ilvl % 2 == 0 { "\u{2022}" } else { "\u{25e6}" }.to_string();
        let Some(levels) = levels else { return bullet };
        let (fmt, text) = &levels[ilvl];
        if fmt == "bullet" || fmt.is_empty() || fmt == "none" {
            return if fmt == "none" { String::new() } else { bullet };
        }
        let mut out = if text.is_empty() { format!("%{}.", ilvl + 1) } else { text.clone() };
        for k in (1..=9).rev() {
            let pat = format!("%{k}");
            if out.contains(&pat) {
                let f = levels.get(k - 1).map(|l| l.0.as_str()).unwrap_or("decimal");
                out = out.replace(&pat, &fmt_num(c[k - 1].max(1), f));
            }
        }
        out
    }
}

fn parse_rels(xml: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for_each_element(xml, |e, _| {
        if local(e.name().as_ref()) == b"Relationship" && attr(e, b"TargetMode").as_deref() != Some("External") {
            if let (Some(id), Some(t)) = (attr(e, b"Id"), attr(e, b"Target")) {
                map.insert(id, t);
            }
        }
    });
    map
}

fn resolve(target: &str) -> String {
    let path = if let Some(abs) = target.strip_prefix('/') { abs.to_string() } else { format!("word/{target}") };
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            ".." => {
                parts.pop();
            }
            "." | "" => {}
            s => parts.push(s),
        }
    }
    parts.join("/")
}

// ---------------------------------------------------------------- document.xml

#[derive(Default)]
struct ParaState {
    runs: Vec<Run>,
    style: Option<String>,
    ilvl: Option<usize>,
    num: Option<String>,
    images: Vec<String>,
    in_ppr: bool,
    in_r: bool,
    in_rpr: bool,
    in_t: bool,
    b: bool,
    i: bool,
    u: bool,
    text: String,
    page_break: bool,
}

#[derive(Default)]
struct TableState {
    rows: Vec<Vec<Vec<Run>>>,
    row: Vec<Vec<Run>>,
    cell: Vec<Run>,
}

fn plain(t: String) -> Run {
    Run { text: t, bold: false, italic: false, underline: false }
}

pub fn parse(data: &[u8]) -> Result<Doc, String> {
    let index = zip_index(data).ok_or("not a valid .docx (zip structure)")?;
    let mut zip = Zip { data, index, total: 0 };
    let xml = zip.read("word/document.xml").ok_or("could not read the document body")?;
    let styles = zip.read("word/styles.xml").map(|x| parse_styles(&x)).unwrap_or_default();
    let mut numbering = zip.read("word/numbering.xml").map(|x| parse_numbering(&x)).unwrap_or_default();
    let rels = zip.read("word/_rels/document.xml.rels").map(|x| parse_rels(&x)).unwrap_or_default();

    let mut doc = Doc { blocks: Vec::new(), images: Vec::new() };
    let mut img_cache: HashMap<String, Option<usize>> = HashMap::new();
    let mut paras: Vec<ParaState> = Vec::new();
    let mut tables: Vec<TableState> = Vec::new();
    let mut fallback = 0usize;

    let mut r = Reader::from_reader(&xml[..]);
    r.config_mut().trim_text(false);
    let mut buf = Zeroizing::new(Vec::new());
    loop {
        let ev = match r.read_event_into(&mut buf) {
            Ok(e) => e,
            Err(_) => return Err("the document XML is malformed".into()),
        };
        match ev {
            Event::Eof => break,
            Event::Start(ref e) | Event::Empty(ref e) => {
                let start = matches!(ev, Event::Start(_));
                let name = local(e.name().as_ref()).to_vec();
                if fallback > 0 {
                    if start {
                        fallback += 1;
                    }
                    buf.clear();
                    continue;
                }
                match name.as_slice() {
                    b"Fallback" if start => fallback = 1,
                    b"p" => {
                        paras.push(ParaState::default());
                        if !start {
                            finish_para(&mut paras, &mut tables, &mut doc, &styles, &mut numbering, &rels, &mut zip, &mut img_cache);
                        }
                    }
                    b"pPr" if start => {
                        if let Some(p) = paras.last_mut() {
                            p.in_ppr = true;
                        }
                    }
                    b"pStyle" => {
                        if let Some(p) = paras.last_mut() {
                            p.style = attr(e, b"val");
                        }
                    }
                    b"ilvl" => {
                        if let Some(p) = paras.last_mut() {
                            p.ilvl = attr(e, b"val").and_then(|v| v.parse().ok());
                        }
                    }
                    b"numId" => {
                        if let Some(p) = paras.last_mut() {
                            p.num = attr(e, b"val");
                        }
                    }
                    b"r" if start => {
                        if let Some(p) = paras.last_mut() {
                            p.in_r = true;
                            p.b = false;
                            p.i = false;
                            p.u = false;
                            p.text.clear();
                        }
                    }
                    b"rPr" if start => {
                        if let Some(p) = paras.last_mut() {
                            p.in_rpr = p.in_r && !p.in_ppr;
                        }
                    }
                    b"b" | b"i" | b"u" => {
                        if let Some(p) = paras.last_mut() {
                            if p.in_rpr {
                                let v = on(e);
                                match name.as_slice() {
                                    b"b" => p.b = v,
                                    b"i" => p.i = v,
                                    _ => p.u = v,
                                }
                            }
                        }
                    }
                    b"t" if start => {
                        if let Some(p) = paras.last_mut() {
                            p.in_t = true;
                        }
                    }
                    b"tab" => {
                        if let Some(p) = paras.last_mut() {
                            if p.in_r && !p.in_ppr {
                                p.text.push_str("    ");
                            }
                        }
                    }
                    b"br" | b"cr" => {
                        if let Some(p) = paras.last_mut() {
                            if p.in_r {
                                if attr(e, b"type").as_deref() == Some("page") {
                                    p.page_break = true;
                                } else {
                                    p.text.push('\n');
                                }
                            }
                        }
                    }
                    b"blip" => {
                        if let (Some(p), Some(id)) = (paras.last_mut(), attr(e, b"embed")) {
                            p.images.push(id);
                        }
                    }
                    b"tbl" if start => tables.push(TableState::default()),
                    b"tr" if start => {
                        if let Some(t) = tables.last_mut() {
                            t.row.clear();
                        }
                    }
                    b"tc" if start => {
                        if let Some(t) = tables.last_mut() {
                            t.cell.clear();
                        }
                    }
                    _ => {}
                }
            }
            Event::Text(ref t) => {
                if fallback == 0 {
                    if let Some(p) = paras.last_mut() {
                        if p.in_t {
                            p.text.push_str(&t.xml_content(XmlVersion::Implicit1_0));
                        }
                    }
                }
            }
            // quick-xml reports `&amp;`, `&#x41;` etc. as separate events between text chunks.
            // Only character references and the five predefined entities are resolved; anything
            // else (custom DTD entities) is dropped, never expanded.
            Event::GeneralRef(ref g) => {
                if fallback == 0 {
                    if let Some(p) = paras.last_mut() {
                        if p.in_t {
                            match g.resolve_char_ref() {
                                Ok(Some(c)) => p.text.push(c),
                                Ok(None) => {
                                    if let Some(s) = resolve_predefined_entity(g) {
                                        p.text.push_str(s);
                                    }
                                }
                                Err(_) => {}
                            }
                        }
                    }
                }
            }
            Event::End(ref e) => {
                if fallback > 0 {
                    fallback -= 1;
                    buf.clear();
                    continue;
                }
                match local(e.name().as_ref()) {
                    b"t" => {
                        if let Some(p) = paras.last_mut() {
                            p.in_t = false;
                        }
                    }
                    b"rPr" => {
                        if let Some(p) = paras.last_mut() {
                            p.in_rpr = false;
                        }
                    }
                    b"pPr" => {
                        if let Some(p) = paras.last_mut() {
                            p.in_ppr = false;
                        }
                    }
                    b"r" => {
                        if let Some(p) = paras.last_mut() {
                            if !p.text.is_empty() {
                                let text = std::mem::take(&mut p.text);
                                p.runs.push(Run { text, bold: p.b, italic: p.i, underline: p.u });
                            }
                            p.in_r = false;
                        }
                    }
                    b"p" => finish_para(&mut paras, &mut tables, &mut doc, &styles, &mut numbering, &rels, &mut zip, &mut img_cache),
                    b"tc" => {
                        if let Some(t) = tables.last_mut() {
                            let c = std::mem::take(&mut t.cell);
                            t.row.push(c);
                        }
                    }
                    b"tr" => {
                        if let Some(t) = tables.last_mut() {
                            let row = std::mem::take(&mut t.row);
                            t.rows.push(row);
                        }
                    }
                    b"tbl" => {
                        if let Some(t) = tables.pop() {
                            match tables.last_mut() {
                                // nested table: flatten into the parent cell as text
                                Some(parent) => {
                                    for row in t.rows {
                                        let line: Vec<String> = row.iter().map(|c| c.iter().map(|r| r.text.as_str()).collect::<String>()).collect();
                                        if !parent.cell.is_empty() {
                                            parent.cell.push(plain("\n".into()));
                                        }
                                        parent.cell.push(plain(line.join(" | ")));
                                    }
                                }
                                None => doc.blocks.push(Block::Table(t.rows)),
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(doc)
}

#[allow(clippy::too_many_arguments)]
fn finish_para(
    paras: &mut Vec<ParaState>,
    tables: &mut [TableState],
    doc: &mut Doc,
    styles: &HashMap<String, String>,
    numbering: &mut Numbering,
    rels: &HashMap<String, String>,
    zip: &mut Zip,
    img_cache: &mut HashMap<String, Option<usize>>,
) {
    let Some(mut p) = paras.pop() else { return };
    let kind = para_kind(p.style.as_deref(), styles);
    let list = p.num.as_deref().is_some_and(|n| n != "0");
    let ilvl = p.ilvl.unwrap_or(0);
    let prefix = if list { numbering.prefix(p.num.as_deref().unwrap_or("0"), ilvl) } else { String::new() };
    let runs = std::mem::take(&mut p.runs);

    if let Some(t) = tables.last_mut() {
        if !t.cell.is_empty() {
            t.cell.push(plain("\n".into()));
        }
        if !prefix.is_empty() {
            t.cell.push(plain(format!("{prefix} ")));
        }
        t.cell.extend(runs);
        for _ in &p.images {
            t.cell.push(plain(" [image]".into()));
        }
        return;
    }
    doc.blocks.push(Block::Para { kind, prefix, indent: if list { 2 * ilvl } else { 0 }, list, runs });
    for id in &p.images {
        let idx = match img_cache.get(id) {
            Some(v) => *v,
            None => {
                let v = rels.get(id).map(|t| resolve(t)).and_then(|path| zip.read(&path)).and_then(|bytes| decode_image(&bytes, MAX_IMG_SIDE)).map(|px| {
                    doc.images.push(Rc::new(px));
                    doc.images.len() - 1
                });
                img_cache.insert(id.clone(), v);
                v
            }
        };
        doc.blocks.push(match idx {
            Some(i) => Block::Image(i),
            None => Block::Unsupported("[image in a format that cannot be shown]"),
        });
    }
    if p.page_break {
        doc.blocks.push(Block::PageBreak);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Build a .docx in memory (deflate-compressed entries, like Word writes).
    pub fn make_docx(parts: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data) in parts {
            let comp = miniz_oxide::deflate::compress_to_vec(data, 6);
            let off = out.len() as u32;
            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            out.extend_from_slice(&[20, 0, 0, 0, 8, 0, 0, 0, 0, 0]);
            out.extend_from_slice(&0u32.to_le_bytes()); // crc (not checked by the reader)
            out.extend_from_slice(&(comp.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&comp);
            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central.extend_from_slice(&[20, 0, 20, 0, 0, 0, 8, 0, 0, 0, 0, 0]);
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&(comp.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0; 12]);
            central.extend_from_slice(&off.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_off = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&(parts.len() as u16).to_le_bytes());
        out.extend_from_slice(&(parts.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    pub fn sample_docx() -> Vec<u8> {
        let mut png = Vec::new();
        image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(20, 10, image::Rgb([0, 200, 0])))
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        let body = br#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="w" xmlns:r="r" xmlns:a="a" xmlns:mc="mc"><w:body>
<w:p><w:pPr><w:pStyle w:val="Heading1"/><w:rPr><w:b/></w:rPr></w:pPr><w:r><w:t>Quarterly Plan</w:t></w:r></w:p>
<w:p><w:r><w:t xml:space="preserve">Normal </w:t></w:r><w:r><w:rPr><w:b/></w:rPr><w:t>bold</w:t></w:r><w:r><w:rPr><w:b w:val="0"/><w:i/></w:rPr><w:t xml:space="preserve"> and italic &amp; more</w:t></w:r></w:p>
<w:p><w:pPr><w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr></w:pPr><w:r><w:t>first step</w:t></w:r></w:p>
<w:p><w:pPr><w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr></w:pPr><w:r><w:t>second step</w:t></w:r></w:p>
<w:tbl><w:tr><w:tc><w:p><w:r><w:t>Name</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>Amount</w:t></w:r></w:p></w:tc></w:tr>
<w:tr><w:tc><w:p><w:r><w:t>Alpha</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>42</w:t></w:r></w:p></w:tc></w:tr></w:tbl>
<w:p><w:r><w:drawing><a:blip r:embed="rId9"/></w:drawing></w:r></w:p>
<w:p><w:r><mc:AlternateContent><mc:Choice><w:t>chosen</w:t></mc:Choice><mc:Fallback><w:p><w:r><w:t>DUPLICATE</w:t></w:r></w:p></mc:Fallback></mc:AlternateContent></w:r></w:p>
<w:p><w:r><w:t>after</w:t></w:r><w:r><w:br w:type="page"/></w:r></w:p>
</w:body></w:document>"#;
        let numbering = br#"<w:numbering xmlns:w="w"><w:abstractNum w:abstractNumId="5"><w:lvl w:ilvl="0"><w:numFmt w:val="decimal"/><w:lvlText w:val="%1."/></w:lvl></w:abstractNum><w:num w:numId="1"><w:abstractNumId w:val="5"/></w:num></w:numbering>"#;
        let styles = br#"<w:styles xmlns:w="w"><w:style w:styleId="Heading1"><w:name w:val="heading 1"/></w:style></w:styles>"#;
        let rels = br#"<Relationships><Relationship Id="rId9" Target="media/image1.png"/></Relationships>"#;
        make_docx(&[
            ("word/document.xml", body),
            ("word/numbering.xml", numbering),
            ("word/styles.xml", styles),
            ("word/_rels/document.xml.rels", rels),
            ("word/media/image1.png", &png),
        ])
    }

    #[test]
    fn parses_structure() {
        let d = sample_docx();
        assert!(is_docx(&d));
        let doc = parse(&d).unwrap();
        let text = |b: &Block| match b {
            Block::Para { runs, .. } => runs.iter().map(|r| r.text.as_str()).collect::<String>(),
            _ => String::new(),
        };
        assert!(matches!(&doc.blocks[0], Block::Para { kind: ParaKind::Heading(1), .. }));
        assert_eq!(text(&doc.blocks[0]), "Quarterly Plan");
        match &doc.blocks[1] {
            Block::Para { runs, .. } => {
                assert_eq!(runs.len(), 3);
                assert!(!runs[0].bold && runs[1].bold && !runs[2].bold && runs[2].italic);
                assert_eq!(runs[2].text, " and italic & more");
            }
            _ => panic!(),
        }
        assert!(matches!(&doc.blocks[2], Block::Para { prefix, list: true, .. } if prefix == "1."));
        assert!(matches!(&doc.blocks[3], Block::Para { prefix, .. } if prefix == "2."));
        match &doc.blocks[4] {
            Block::Table(rows) => {
                assert_eq!(rows.len(), 2);
                assert_eq!(rows[1][1][0].text, "42");
            }
            _ => panic!("expected table"),
        }
        assert!(doc.blocks.iter().any(|b| matches!(b, Block::Image(0))));
        assert_eq!(doc.images.len(), 1);
        assert_eq!((doc.images[0].w, doc.images[0].h), (20, 10));
        let all: String = doc.blocks.iter().map(text).collect();
        assert!(all.contains("chosen") && !all.contains("DUPLICATE"));
        assert!(matches!(doc.blocks.last(), Some(Block::PageBreak)));
    }

    #[test]
    fn entities_and_hostile_tags() {
        let body = br#"<?xml version="1.0"?><w:document xmlns:w="w"><w:body>
<w:p><w:r><w:t xml:space="preserve">A &amp; B &lt;&#x41;&#66;&gt; &quot;q&apos; &custom; end</w:t></w:r></w:p>
</w:body></w:document>"#;
        let doc = parse(&make_docx(&[("word/document.xml", body)])).unwrap();
        match &doc.blocks[0] {
            Block::Para { runs, .. } => {
                let t: String = runs.iter().map(|r| r.text.as_str()).collect();
                // char refs and predefined entities resolve; an undefined entity is dropped
                assert_eq!(t, "A & B <AB> \"q'  end");
            }
            _ => panic!(),
        }
        // RUSTSEC-2026-0194: a start tag with thousands of attributes must not take quadratic time
        let mut hostile = b"<w:document xmlns:w=\"w\"><w:body><w:p ".to_vec();
        for i in 0..20_000 {
            hostile.extend_from_slice(format!("a{i}=\"x\" ").as_bytes());
        }
        hostile.extend_from_slice(b"/></w:body></w:document>");
        let t = std::time::Instant::now();
        let _ = parse(&make_docx(&[("word/document.xml", &hostile)]));
        assert!(t.elapsed() < std::time::Duration::from_secs(5), "took {:?}", t.elapsed());
    }

    #[test]
    fn rejects_garbage_and_bombs() {
        assert!(!is_docx(b"PK\x03\x04 nonsense"));
        assert!(parse(b"PK\x03\x04 nonsense").is_err());
        // a claimed-huge entry is refused rather than allocated
        let big = vec![0u8; 1 << 20];
        let mut z = make_docx(&[("word/document.xml", &big)]);
        // patch the central directory's uncompressed size to 4 GiB - 1
        let cd = z.len() - 22 - (46 + "word/document.xml".len());
        z[cd + 24..cd + 28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse(&z).is_err());
    }
}
