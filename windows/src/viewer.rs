//! In-memory file viewer. The decrypted file lives only in a locked, zeroized buffer; nothing is
//! written to disk. Text is shown as text, images and PDF pages as real pixels, Word documents in a
//! reading view, anything else as hex.

use std::{cell::RefCell, rc::Rc};

use ratatui::{
    crossterm::event::KeyCode,
    style::{Modifier, Style},
    text::{Line, Span},
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    docx::{self, Block, Doc, ParaKind, Run},
    gui::{self, Fit, Overlay, Pixels},
    pdf::Pdf,
    secret::SecretInput,
    ui::{clean, ln, style, wrap, K},
    util::fmt_size,
};

/// Longest single line rendered (very long lines, e.g. minified files, are cut for display only).
const MAX_LINE_SHOWN: usize = 200_000;
const MAX_IMG_SIDE: u32 = 4096;
const HEADER_ROWS: usize = 3;

/// Decode PNG/JPEG/GIF/BMP/WebP into BGRA, refusing decompression bombs and downscaling anything
/// larger than `max_side`. Intermediate buffers that this code owns are wiped.
pub(crate) fn decode_image(data: &[u8], max_side: u32) -> Option<Pixels> {
    use image::{ImageFormat, ImageReader, Limits};
    let mut r = ImageReader::new(std::io::Cursor::new(data)).with_guessed_format().ok()?;
    if !matches!(r.format()?, ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::Gif | ImageFormat::Bmp | ImageFormat::WebP) {
        return None;
    }
    let mut lim = Limits::default();
    lim.max_image_width = Some(20_000);
    lim.max_image_height = Some(20_000);
    lim.max_alloc = Some(512 << 20);
    r.limits(lim);
    let full = r.decode().ok()?.into_rgba8();
    let (w, h) = full.dimensions();
    if w == 0 || h == 0 {
        return None;
    }
    if w <= max_side && h <= max_side {
        return Some(Pixels::from_rgba(w, h, full.into_raw()));
    }
    let s = max_side as f64 / w.max(h) as f64;
    let (nw, nh) = (((w as f64 * s) as u32).max(1), ((h as f64 * s) as u32).max(1));
    let small = image::imageops::thumbnail(&full, nw, nh);
    let mut raw = full.into_raw();
    raw.zeroize();
    Some(Pixels::from_rgba(nw, nh, small.into_raw()))
}

// ---------------------------------------------------------------- body kinds

struct PdfView {
    pdf: Pdf,
    page: u32,
    pix: Option<Rc<Pixels>>,
    overflow: f32,
    fit_page: bool,
    err: Option<String>,
}

impl PdfView {
    fn render(&mut self) {
        let (cw, _) = gui::cell_px();
        let want = (gui_cols() as i32 * cw) as u32;
        self.pix = None; // drop (and wipe) the previous page first
        match self.pdf.render(self.page, want.clamp(1400, 3000)) {
            Ok(p) => {
                self.pix = Some(Rc::new(p));
                self.err = None;
            }
            Err(e) => self.err = Some(e),
        }
    }

    /// Scroll step as a fraction of the overflow, about 15% of the visible height.
    fn step(&self) -> f32 {
        let Some(p) = &self.pix else { return 1.0 };
        let (cw, ch) = gui::cell_px();
        let bw = gui_cols() as f32 * cw as f32;
        let bh = (gui_rows().saturating_sub(HEADER_ROWS + 2)) as f32 * ch as f32;
        let scaled = p.h as f32 * bw / p.w as f32;
        let over = scaled - bh;
        if over <= 1.0 {
            1.0
        } else {
            (bh * 0.15 / over).min(1.0)
        }
    }

    fn go(&mut self, page: u32, overflow: f32) {
        if page != self.page {
            self.page = page;
            self.render();
        }
        self.overflow = overflow;
    }
}

fn gui_cols() -> usize {
    use ratatui::backend::Backend;
    gui::GuiBackend.size().map(|s| s.width as usize).unwrap_or(80)
}

fn gui_rows() -> usize {
    use ratatui::backend::Backend;
    gui::GuiBackend.size().map(|s| s.height as usize).unwrap_or(24)
}

/// One display row of a laid-out Word document.
enum Row {
    Text(Vec<(String, Style)>),
    Img { idx: usize, k: u16, total: u16, cols: u16 },
}

impl Drop for Row {
    fn drop(&mut self) {
        if let Row::Text(segs) = self {
            for (s, _) in segs.iter_mut() {
                s.zeroize();
            }
        }
    }
}

enum Body {
    /// `conv` holds a UTF-8 copy for UTF-16 files; otherwise the buffer itself is the text.
    Text { conv: Option<Zeroizing<String>>, lines: Vec<(usize, usize)> },
    Image(Rc<Pixels>),
    Pdf(Box<PdfView>),
    Doc { doc: Box<Doc>, layout: RefCell<Option<(usize, Rc<Vec<Row>>)>> },
    Binary,
}

pub struct FileView {
    pub short: String,
    name: String,
    data: SecretInput,
    body: Body,
    hex: bool,
    scroll: usize,
    note: Option<String>,
}

fn line_index(s: &str, start: usize) -> Vec<(usize, usize)> {
    let mut v = Vec::new();
    let mut a = start;
    for (i, _) in s.match_indices('\n') {
        if i >= start {
            v.push((a, i));
            a = i + 1;
        }
    }
    if a < s.len() || v.is_empty() {
        v.push((a, s.len()));
    }
    v
}

fn looks_like_text(s: &str) -> bool {
    let mut ctrl = 0usize;
    let mut total = 0usize;
    for c in s.chars() {
        total += 1;
        if c == '\0' {
            return false;
        }
        if c.is_control() && !matches!(c, '\n' | '\r' | '\t' | '\x0c') {
            ctrl += 1;
        }
    }
    ctrl * 100 <= total.max(1) * 2
}

fn decode_utf16(b: &[u8], le: bool) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(b.len() / 2 * 3 + 4));
    let units = b[2..].chunks_exact(2).map(|c| if le { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) });
    for c in char::decode_utf16(units) {
        out.push(c.unwrap_or('\u{fffd}'));
    }
    out
}

fn is_pdf(b: &[u8]) -> bool {
    b[..b.len().min(1024)].windows(5).any(|w| w == b"%PDF-")
}

const OLE_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

impl FileView {
    pub fn new(short: String, name: &str, data: SecretInput) -> FileView {
        let bytes = data.as_bytes();
        let mut note = None;
        let body = if is_pdf(bytes) {
            match Pdf::open(bytes) {
                Ok(pdf) => {
                    let mut v = PdfView { pdf, page: 0, pix: None, overflow: 0.0, fit_page: false, err: None };
                    v.render();
                    Body::Pdf(Box::new(v))
                }
                Err(e) => {
                    note = Some(format!("could not open PDF: {e}"));
                    Body::Binary
                }
            }
        } else if docx::is_docx(bytes) {
            match docx::parse(bytes) {
                Ok(doc) => Body::Doc { doc: Box::new(doc), layout: RefCell::new(None) },
                Err(e) => {
                    note = Some(format!("could not open Word document: {e}"));
                    Body::Binary
                }
            }
        } else if bytes.starts_with(&OLE_MAGIC) {
            note = Some("legacy Office format (.doc/.xls/.ppt) is not supported. Save it as .docx and encrypt that".into());
            Body::Binary
        } else if let Some(p) = decode_image(bytes, MAX_IMG_SIDE) {
            Body::Image(Rc::new(p))
        } else if bytes.len() >= 2 && (bytes[..2] == [0xff, 0xfe] || bytes[..2] == [0xfe, 0xff]) {
            let conv = decode_utf16(bytes, bytes[0] == 0xff);
            let lines = line_index(&conv, 0);
            Body::Text { conv: Some(conv), lines }
        } else {
            match std::str::from_utf8(bytes) {
                Ok(s) if looks_like_text(s) => {
                    let start = if s.starts_with('\u{feff}') { 3 } else { 0 };
                    Body::Text { conv: None, lines: line_index(s, start) }
                }
                _ => Body::Binary,
            }
        };
        let hex = matches!(body, Body::Binary);
        FileView { short, name: clean(name), data, body, hex, scroll: 0, note }
    }

    fn text(&self) -> &str {
        match &self.body {
            Body::Text { conv: Some(c), .. } => c,
            _ => self.data.as_str(),
        }
    }

    pub fn kind(&self) -> &'static str {
        match (&self.body, self.hex) {
            (Body::Binary, _) => "binary (hex)",
            (_, true) => "hex",
            (Body::Text { .. }, _) => "text",
            (Body::Image(_), _) => "image",
            (Body::Pdf(_), _) => "pdf",
            (Body::Doc { .. }, _) => "word document",
        }
    }

    fn doc_rows(&self, w: usize) -> Option<Rc<Vec<Row>>> {
        let Body::Doc { doc, layout } = &self.body else { return None };
        if let Some((lw, rows)) = layout.borrow().as_ref() {
            if *lw == w {
                return Some(rows.clone());
            }
        }
        let rows = Rc::new(layout_doc(doc, w));
        *layout.borrow_mut() = Some((w, rows.clone()));
        Some(rows)
    }

    fn rows(&self) -> usize {
        match (&self.body, self.hex) {
            (_, true) | (Body::Binary, _) => self.data.as_bytes().len().div_ceil(16),
            (Body::Text { lines, .. }, _) => lines.len(),
            (Body::Doc { layout, .. }, _) => layout.borrow().as_ref().map_or(1, |(_, r)| r.len()),
            _ => 1,
        }
    }

    pub fn key(&mut self, code: KeyCode, page: usize) {
        let page = page.max(1);
        if !self.hex {
            if let Body::Pdf(p) = &mut self.body {
                let last = p.pdf.pages - 1;
                let step = p.step();
                match code {
                    KeyCode::Down if !p.fit_page && p.overflow < 1.0 => p.overflow = (p.overflow + step).min(1.0),
                    KeyCode::Up if !p.fit_page && p.overflow > 0.0 => p.overflow = (p.overflow - step).max(0.0),
                    KeyCode::Down | KeyCode::PageDown | KeyCode::Right | KeyCode::Char(' ') if p.page < last => p.go(p.page + 1, 0.0),
                    KeyCode::Up | KeyCode::PageUp | KeyCode::Left if p.page > 0 => {
                        let o = if code == KeyCode::Up { 1.0 } else { 0.0 };
                        p.go(p.page - 1, o)
                    }
                    KeyCode::Home => p.go(0, 0.0),
                    KeyCode::End => p.go(last, 0.0),
                    KeyCode::Char('f') | KeyCode::Char('F') => p.fit_page = !p.fit_page,
                    KeyCode::Char('h') | KeyCode::Char('H') => {
                        self.hex = true;
                        self.scroll = 0;
                    }
                    _ => {}
                }
                return;
            }
        }
        match code {
            KeyCode::Up => self.scroll = self.scroll.saturating_sub(1),
            KeyCode::Down => self.scroll += 1,
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(page),
            KeyCode::PageDown | KeyCode::Char(' ') => self.scroll += page,
            KeyCode::Home => self.scroll = 0,
            KeyCode::End => self.scroll = usize::MAX,
            KeyCode::Char('h') | KeyCode::Char('H') if !matches!(self.body, Body::Binary) => {
                self.hex = !self.hex;
                self.scroll = 0;
            }
            _ => {}
        }
        self.scroll = self.scroll.min(self.rows().saturating_sub(1));
    }

    /// Lines for the body area, plus image overlays in body-relative cell coordinates.
    pub fn render(&self, w: usize, h: usize) -> (Vec<Line<'static>>, Vec<Overlay>) {
        let mut l = Vec::new();
        let mut ov = Vec::new();
        let pos = match (&self.body, self.hex) {
            (Body::Image(p), false) => format!("{}x{}", p.w, p.h),
            (Body::Pdf(p), false) => format!("page {}/{}{}", p.page + 1, p.pdf.pages, if p.fit_page { "  (whole page)" } else { "" }),
            (Body::Text { .. }, false) => format!("line {}/{}", self.scroll + 1, self.rows()),
            (Body::Doc { .. }, false) => String::new(),
            _ => format!("offset {:08x}", self.scroll * 16),
        };
        l.push(ln(K::Head, format!("FILE {}  {}   {}  {}  {}", self.short, self.name, self.kind(), fmt_size(self.data.as_bytes().len() as u64), pos)));
        match (&self.note, &self.body) {
            (Some(n), _) => l.push(ln(K::Warn, n)),
            (None, Body::Pdf(p)) if p.err.is_some() => l.push(ln(K::Err, p.err.as_deref().unwrap_or(""))),
            _ => l.push(ln(K::Dim, "decrypted in memory only. Nothing is written to disk; closing wipes it.")),
        }
        l.push(ln(K::N, ""));
        let room = h.saturating_sub(HEADER_ROWS).max(1);
        let rect = |rows: usize| (1u16, HEADER_ROWS as u16, w as u16, rows as u16);
        match (&self.body, self.hex) {
            (Body::Image(p), false) => {
                let (x, y, rw, rh) = rect(room);
                ov.push(Overlay { x, y, w: rw, h: rh, img: p.clone(), fit: Fit::Contain, smooth: true });
            }
            (Body::Pdf(p), false) => {
                if let Some(pix) = &p.pix {
                    let (x, y, rw, rh) = rect(room);
                    let fit = if p.fit_page { Fit::Contain } else { Fit::Width { overflow: p.overflow } };
                    ov.push(Overlay { x, y, w: rw, h: rh, img: pix.clone(), fit, smooth: true });
                }
            }
            (Body::Doc { doc, .. }, false) => {
                let rows = self.doc_rows(w).unwrap_or_default();
                let mut i = self.scroll;
                let mut run: Option<(usize, usize, u16, u16, u16, usize)> = None; // (idx, first line, k0, total, cols, count)
                let flush = |run: &mut Option<(usize, usize, u16, u16, u16, usize)>, ov: &mut Vec<Overlay>| {
                    if let Some((idx, y, k0, total, cols, count)) = run.take() {
                        ov.push(Overlay {
                            x: 1,
                            y: y as u16,
                            w: cols,
                            h: count as u16,
                            img: doc.images[idx].clone(),
                            fit: Fit::WidthOffset { frac: k0 as f32 / total as f32 },
                            smooth: true,
                        });
                    }
                };
                while l.len() < HEADER_ROWS + room && i < rows.len() {
                    match &rows[i] {
                        Row::Text(segs) => {
                            flush(&mut run, &mut ov);
                            let mut spans = vec![Span::raw(" ")];
                            spans.extend(segs.iter().map(|(s, st)| Span::styled(clean(s), *st)));
                            l.push(Line::from(spans));
                        }
                        Row::Img { idx, k, total, cols } => {
                            match &mut run {
                                Some(r) if r.0 == *idx => r.5 += 1,
                                _ => {
                                    flush(&mut run, &mut ov);
                                    run = Some((*idx, l.len(), *k, *total, *cols, 1));
                                }
                            }
                            l.push(Line::from(""));
                        }
                    }
                    i += 1;
                }
                flush(&mut run, &mut ov);
            }
            (Body::Text { lines, .. }, false) => {
                let text = self.text();
                let mut i = self.scroll;
                while l.len() < HEADER_ROWS + room && i < lines.len() {
                    let (a, b) = lines[i];
                    let mut end = b.min(a + MAX_LINE_SHOWN);
                    while !text.is_char_boundary(end) {
                        end -= 1;
                    }
                    let line = Zeroizing::new(text[a..end].replace('\r', "").replace('\t', "    "));
                    for piece in wrap(&line, w) {
                        if l.len() >= HEADER_ROWS + room {
                            break;
                        }
                        l.push(ln(K::Ok, piece));
                    }
                    if end < b && l.len() < HEADER_ROWS + room {
                        l.push(ln(K::Dim, "[line too long; rest not shown]"));
                    }
                    i += 1;
                }
            }
            _ => {
                let d = self.data.as_bytes();
                for r in self.scroll..self.scroll + room {
                    let off = r * 16;
                    if off >= d.len() {
                        break;
                    }
                    let chunk = &d[off..(off + 16).min(d.len())];
                    let mut hx = String::with_capacity(50);
                    for (i, b) in chunk.iter().enumerate() {
                        hx.push_str(&format!("{b:02x}{}", if i == 7 { "  " } else { " " }));
                    }
                    let ascii: String = chunk.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }).collect();
                    l.push(ln(K::Ok, format!("{off:08x}  {hx:<49} {ascii}")));
                }
            }
        }
        (l, ov)
    }

    pub fn hints(&self) -> &'static str {
        match (&self.body, self.hex) {
            (Body::Pdf(_), false) => "Up/Down scroll   PgUp/PgDn page   Home/End   F whole page   H hex   Esc close (wipes it)",
            (Body::Image(_), false) => "H hex   Esc close (wipes it from memory)",
            _ => "Up/Down PgUp/PgDn Home/End scroll   H text/hex   Esc close (wipes it from memory)",
        }
    }
}

// ---------------------------------------------------------------- Word layout

fn run_style(base: Style, r: &Run) -> Style {
    let mut s = base;
    if r.bold {
        s = s.add_modifier(Modifier::BOLD);
    }
    if r.italic {
        s = s.add_modifier(Modifier::ITALIC);
    }
    if r.underline {
        s = s.add_modifier(Modifier::UNDERLINED);
    }
    s
}

/// Greedy word wrap over styled segments. Newlines force a break; runs of spaces are kept
/// except at a wrap point.
fn wrap_styled(segs: &[(String, Style)], w: usize) -> Vec<Vec<(String, Style)>> {
    let w = w.max(4);
    let mut out: Vec<Vec<(String, Style)>> = Vec::new();
    let mut line: Vec<(String, Style)> = Vec::new();
    let mut len = 0usize;
    let add = |line: &mut Vec<(String, Style)>, s: &str, st: Style| match line.last_mut() {
        Some((t, lst)) if *lst == st => t.push_str(s),
        _ => line.push((s.to_string(), st)),
    };
    for (text, st) in segs {
        // neutralise control characters, but keep the line breaks that drive wrapping
        let text: String = text
            .replace('\t', "    ")
            .chars()
            .filter(|&c| c != '\r')
            .map(|c| if c != '\n' && c.is_control() { '\u{b7}' } else { c })
            .collect();
        let mut rest = text.as_str();
        while !rest.is_empty() {
            // next token: newline, run of spaces, or word
            let (tok, kind) = if let Some(r) = rest.strip_prefix('\n') {
                rest = r;
                ("\n", 0)
            } else if rest.starts_with(' ') {
                let n = rest.len() - rest.trim_start_matches(' ').len();
                let t = &rest[..n];
                rest = &rest[n..];
                (t, 1)
            } else {
                let n = rest.find([' ', '\n']).unwrap_or(rest.len());
                let t = &rest[..n];
                rest = &rest[n..];
                (t, 2)
            };
            let tl = tok.chars().count();
            match kind {
                0 => {
                    out.push(std::mem::take(&mut line));
                    len = 0;
                }
                1 => {
                    if len + tl <= w {
                        add(&mut line, tok, *st);
                        len += tl;
                    } else {
                        out.push(std::mem::take(&mut line));
                        len = 0;
                    }
                }
                _ => {
                    if len + tl > w && len > 0 {
                        out.push(std::mem::take(&mut line));
                        len = 0;
                    }
                    if tl <= w {
                        add(&mut line, tok, *st);
                        len += tl;
                    } else {
                        for c in tok.chars() {
                            if len == w {
                                out.push(std::mem::take(&mut line));
                                len = 0;
                            }
                            let mut b = [0u8; 4];
                            add(&mut line, c.encode_utf8(&mut b), *st);
                            len += 1;
                        }
                    }
                }
            }
        }
    }
    out.push(line);
    out
}

fn seg_len(segs: &[(String, Style)]) -> usize {
    segs.iter().map(|(s, _)| s.chars().count()).sum()
}

fn layout_table(t: &[Vec<Vec<Run>>], w: usize, base: Style, rows: &mut Vec<Row>) {
    let ncol = t.iter().map(|r| r.len()).max().unwrap_or(0);
    if ncol == 0 {
        return;
    }
    let border = style(K::Dim);
    let cells: Vec<Vec<Vec<(String, Style)>>> =
        t.iter().map(|r| (0..ncol).map(|c| r.get(c).map(|runs| runs.iter().map(|x| (x.text.clone(), run_style(base, x))).collect()).unwrap_or_default()).collect()).collect();
    let mut natural = vec![1usize; ncol];
    for r in &cells {
        for (c, segs) in r.iter().enumerate() {
            let joined: String = segs.iter().map(|(s, _)| s.as_str()).collect();
            let longest = joined.split('\n').map(|l| l.chars().count()).max().unwrap_or(0);
            natural[c] = natural[c].max(longest);
        }
    }
    let avail = w.saturating_sub(3 * ncol + 1).max(ncol * 3);
    let total: usize = natural.iter().sum();
    let widths: Vec<usize> = if total <= avail { natural.clone() } else { natural.iter().map(|n| (n * avail / total).max(3)).collect() };
    let rule = |l: &str, m: &str, r: &str| {
        let mut s = l.to_string();
        for (i, cw) in widths.iter().enumerate() {
            s.push_str(&"\u{2500}".repeat(cw + 2));
            s.push_str(if i + 1 == ncol { r } else { m });
        }
        Row::Text(vec![(s, border)])
    };
    rows.push(rule("\u{250c}", "\u{252c}", "\u{2510}"));
    for (ri, r) in cells.iter().enumerate() {
        let wrapped: Vec<Vec<Vec<(String, Style)>>> = r.iter().zip(&widths).map(|(segs, cw)| wrap_styled(segs, *cw)).collect();
        let height = wrapped.iter().map(|c| c.len()).max().unwrap_or(1);
        for li in 0..height {
            let mut segs = vec![("\u{2502} ".to_string(), border)];
            for (c, cw) in widths.iter().enumerate() {
                let part = wrapped[c].get(li).cloned().unwrap_or_default();
                let pad = cw.saturating_sub(seg_len(&part));
                segs.extend(part);
                segs.push((format!("{} ", " ".repeat(pad)), base));
                segs.push(((if c + 1 == ncol { "\u{2502}" } else { "\u{2502} " }).to_string(), border));
            }
            rows.push(Row::Text(segs));
        }
        if ri + 1 < cells.len() {
            rows.push(rule("\u{251c}", "\u{253c}", "\u{2524}"));
        }
    }
    rows.push(rule("\u{2514}", "\u{2534}", "\u{2518}"));
}

fn blank() -> Row {
    Row::Text(Vec::new())
}

fn layout_doc(doc: &Doc, w: usize) -> Vec<Row> {
    let (cw, ch) = gui::cell_px();
    let body = style(K::Ok);
    let head = style(K::Head);
    let mut rows: Vec<Row> = Vec::new();
    for b in &doc.blocks {
        match b {
            Block::Para { kind, prefix, indent, list, runs } => {
                let base = match kind {
                    ParaKind::Normal => body,
                    ParaKind::Title => head.add_modifier(Modifier::UNDERLINED),
                    ParaKind::Heading(_) => head,
                };
                let is_head = *kind != ParaKind::Normal;
                if is_head && !rows.is_empty() && !matches!(rows.last(), Some(Row::Text(s)) if s.is_empty()) {
                    rows.push(blank());
                }
                let mut segs: Vec<(String, Style)> = Vec::new();
                if !prefix.is_empty() {
                    segs.push((format!("{prefix} "), base));
                }
                for r in runs {
                    segs.push((r.text.clone(), run_style(base, r)));
                }
                if seg_len(&segs) == 0 {
                    rows.push(blank());
                    continue;
                }
                for mut line in wrap_styled(&segs, w.saturating_sub(*indent)) {
                    if *indent > 0 {
                        line.insert(0, (" ".repeat(*indent), base));
                    }
                    rows.push(Row::Text(line));
                }
                if !*list {
                    rows.push(blank());
                }
            }
            Block::Table(t) => {
                layout_table(t, w, body, &mut rows);
                rows.push(blank());
            }
            Block::Image(i) => {
                let img = &doc.images[*i];
                let mut cols = ((img.w as i32 + cw - 1) / cw).clamp(1, w.max(1) as i32);
                let mut total = ((img.h as f64 * (cols * cw) as f64 / img.w as f64) / ch as f64).ceil() as i32;
                if total > 40 {
                    cols = (cols * 40 / total).max(1);
                    total = ((img.h as f64 * (cols * cw) as f64 / img.w as f64) / ch as f64).ceil() as i32;
                }
                let total = total.max(1) as u16;
                for k in 0..total {
                    rows.push(Row::Img { idx: *i, k, total, cols: cols as u16 });
                }
                rows.push(blank());
            }
            Block::Unsupported(msg) => {
                rows.push(Row::Text(vec![(msg.to_string(), style(K::Dim))]));
                rows.push(blank());
            }
            Block::PageBreak => {
                rows.push(Row::Text(vec![("\u{2500}\u{2500}\u{2500}\u{2500} page break \u{2500}\u{2500}\u{2500}\u{2500}".into(), style(K::Dim))]));
                rows.push(blank());
            }
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn buf(b: &[u8]) -> SecretInput {
        let mut s = SecretInput::new(b.len() + 16);
        s.write_all(b).unwrap();
        s
    }

    fn flat(lines: &[Line]) -> String {
        lines.iter().map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect::<String>() + "\n").collect()
    }

    #[test]
    fn detects_text_utf16_binary_image() {
        let t = FileView::new("abc".into(), "a.txt", buf("hello\n\tworld\r\nthird".as_bytes()));
        assert_eq!(t.kind(), "text");
        let out = flat(&t.render(80, 20).0);
        assert!(out.contains("hello") && out.contains("    world") && out.contains("third") && !out.contains('\r'));

        let mut u16le = vec![0xff, 0xfe];
        for c in "hi there".encode_utf16() {
            u16le.extend_from_slice(&c.to_le_bytes());
        }
        let u = FileView::new("abc".into(), "w.txt", buf(&u16le));
        assert_eq!(u.kind(), "text");
        assert!(flat(&u.render(80, 20).0).contains("hi there"));

        let b = FileView::new("abc".into(), "x.bin", buf(&[0, 1, 2, 0x41, 0xff, 0x1b]));
        assert_eq!(b.kind(), "binary (hex)");
        assert!(flat(&b.render(80, 20).0).contains("00 01 02 41 ff 1b"));

        let mut png = Vec::new();
        let img = image::RgbImage::from_fn(8, 4, |x, _| if x < 4 { image::Rgb([255, 0, 0]) } else { image::Rgb([0, 0, 255]) });
        image::DynamicImage::ImageRgb8(img).write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png).unwrap();
        let i = FileView::new("abc".into(), "p.png", buf(&png));
        assert_eq!(i.kind(), "image");
        let (_, ov) = i.render(40, 20);
        assert_eq!(ov.len(), 1);
        let p = &ov[0].img;
        assert_eq!((p.w, p.h), (8, 4));
        assert_eq!(&p.bgra[0..4], &[0, 0, 255, 255], "BGRA red");
        assert_eq!(&p.bgra[(7 * 4)..(7 * 4 + 3)], &[255, 0, 0], "BGRA blue");

        let ole = FileView::new("abc".into(), "old.doc", buf(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0, 0]));
        assert!(flat(&ole.render(80, 20).0).contains("not supported"));
    }

    #[test]
    fn pdf_and_word() {
        crate::pdf::init();
        let mut p = FileView::new("abc".into(), "r.pdf", buf(&crate::pdf::tests::sample_pdf()));
        assert_eq!(p.kind(), "pdf");
        let (l, ov) = p.render(80, 30);
        assert!(flat(&l).contains("page 1/1"));
        assert_eq!(ov.len(), 1);
        p.key(KeyCode::Char('f'), 10);
        assert!(flat(&p.render(80, 30).0).contains("whole page"));

        let d = FileView::new("abc".into(), "plan.docx", buf(&crate::docx::tests::sample_docx()));
        assert_eq!(d.kind(), "word document");
        let (l, ov) = d.render(80, 60);
        let s = flat(&l);
        for want in ["Quarterly Plan", "Normal bold and italic & more", "1. first step", "2. second step", "Name", "Amount", "Alpha", "42", "chosen", "page break"] {
            assert!(s.contains(want), "missing {want:?} in:\n{s}");
        }
        assert!(s.contains('\u{250c}') && s.contains('\u{2502}'), "table borders");
        assert_eq!(ov.len(), 1, "inline image overlay");
        // bold run carries the BOLD modifier
        let bold = l.iter().flat_map(|x| x.spans.iter()).any(|sp| sp.content.contains("bold") && sp.style.add_modifier.contains(Modifier::BOLD));
        assert!(bold);
    }

    #[test]
    fn escape_sequences_are_neutralised() {
        let t = FileView::new("abc".into(), "evil\x1b[2J.txt", buf(b"safe \x1b]0;pwned\x07 text"));
        let out = flat(&t.render(80, 20).0);
        assert!(!out.contains('\x1b') && !out.contains('\x07'));
    }

    #[test]
    fn scrolling_and_hex_toggle() {
        let text: String = (0..100).map(|i| format!("row {i}\n")).collect();
        let mut t = FileView::new("abc".into(), "a.txt", buf(text.as_bytes()));
        t.key(KeyCode::PageDown, 10);
        assert!(flat(&t.render(80, 20).0).contains("row 10"));
        t.key(KeyCode::End, 10);
        assert!(flat(&t.render(80, 20).0).contains("row 99"));
        t.key(KeyCode::Char('h'), 10);
        assert_eq!(t.kind(), "hex");
        assert!(flat(&t.render(80, 20).0).contains("72 6f 77"));
    }

    #[test]
    fn styled_wrap_respects_width() {
        let st = Style::default();
        let segs = vec![("alpha beta ".to_string(), st), ("gammadeltaepsilonzeta".to_string(), st.add_modifier(Modifier::BOLD)), (" eta\ntheta".to_string(), st)];
        for w in [4usize, 7, 10, 25] {
            for line in wrap_styled(&segs, w) {
                assert!(seg_len(&line) <= w, "w={w} {line:?}");
            }
        }
        let lines = wrap_styled(&segs, 80);
        assert_eq!(lines.len(), 2, "{lines:?}");
        // control characters other than newline are neutralised
        let evil = wrap_styled(&[("a\x1b[2Jb".to_string(), st)], 80);
        assert!(evil.iter().flatten().all(|(s, _)| !s.contains('\x1b')));
    }
}
