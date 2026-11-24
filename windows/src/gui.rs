//! Scytale's own window: a terminal-style cell grid drawn with GDI, plus image overlays for
//! pictures, PDF pages and the setup QR code.
//!
//! Running in its own window (instead of a console) is what makes these possible:
//!  - the window is excluded from screenshots, screen recording and screen sharing
//!    (SetWindowDisplayAffinity only works on windows the calling process owns);
//!  - no other process can read the screen text through the console APIs;
//!  - documents and images can be drawn as real pixels.
//!
//! Everything runs on the main thread. The window procedure only queues events; drawing reads the
//! cell grid that the ratatui backend below fills in.

use std::{cell::RefCell, collections::VecDeque, io, rc::Rc, time::Duration};

use ratatui::{
    backend::{Backend, ClearType, WindowSize},
    buffer::Cell,
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
    layout::{Position, Size},
    style::{Color, Modifier},
};
use unicode_width::UnicodeWidthStr;
use windows_sys::Win32::{
    Foundation::{GlobalFree, HWND, LPARAM, LRESULT, RECT, SIZE, WPARAM},
    Graphics::Gdi::{
        BeginPaint, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, CreateFontW, CreateSolidBrush, DeleteDC,
        DeleteObject, EndPaint, ExtTextOutW, FillRect, GetDC, GetTextExtentPoint32W, GetTextFaceW,
        GetTextMetricsW, IntersectClipRect, InvalidateRect, ReleaseDC, RestoreDC, SaveDC, SelectObject,
        SetBkColor, SetBrushOrgEx, SetStretchBltMode, SetTextColor, StretchDIBits, UpdateWindow, BITMAPINFO,
        BITMAPINFOHEADER, ETO_CLIPPED, ETO_OPAQUE, HDC, HFONT, PAINTSTRUCT, SRCCOPY, TEXTMETRICW,
    },
    System::{
        DataExchange::{CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, SetClipboardData},
        LibraryLoader::GetModuleHandleW,
        Memory::{GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE},
    },
    UI::{
        HiDpi::{AdjustWindowRectExForDpi, GetDpiForWindow, SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2},
        Input::KeyboardAndMouse::GetKeyState,
        WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect, LoadCursorW,
            MessageBoxW, MsgWaitForMultipleObjects, PeekMessageW, RegisterClassW, SetForegroundWindow,
            SetWindowDisplayAffinity, SetWindowPos, ShowWindow, TranslateMessage, CS_HREDRAW, CS_VREDRAW,
            CW_USEDEFAULT, IDC_ARROW, MB_ICONINFORMATION, MB_OK, MSG, PM_REMOVE, QS_ALLINPUT, SWP_NOACTIVATE,
            SWP_NOMOVE, SWP_NOZORDER, SW_SHOW, WM_CHAR, WM_CLOSE, WM_ERASEBKGND, WM_KEYDOWN, WM_MOUSEWHEEL,
            WM_PAINT, WM_SIZE, WM_SYSKEYDOWN, WNDCLASSW, WS_OVERLAPPEDWINDOW,
        },
    },
};
use zeroize::Zeroizing;

const PAD: i32 = 8;
const BASE_FONT_PX: i32 = 16;
const WM_DPICHANGED: u32 = 0x02E0;
const WDA_EXCLUDEFROMCAPTURE: u32 = 0x11;

// ---------------------------------------------------------------- public types

/// Decoded image in BGRA, top-down. Wiped on drop.
pub struct Pixels {
    pub w: u32,
    pub h: u32,
    pub bgra: Zeroizing<Vec<u8>>,
}

impl Pixels {
    pub fn from_rgba(w: u32, h: u32, mut rgba: Vec<u8>) -> Pixels {
        for p in rgba.chunks_exact_mut(4) {
            p.swap(0, 2);
        }
        Pixels { w, h, bgra: Zeroizing::new(rgba) }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Fit {
    /// Whole image inside the rectangle, centred.
    Contain,
    /// Scaled to the rectangle's width; `overflow` 0..1 scrolls through the part that does not fit.
    Width { overflow: f32 },
    /// Scaled to the rectangle's width; `frac` of the image height is above the rectangle's top.
    WidthOffset { frac: f32 },
}

/// An image drawn over a rectangle of cells (cell coordinates).
#[derive(Clone)]
pub struct Overlay {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
    pub img: Rc<Pixels>,
    pub fit: Fit,
    /// false = nearest-neighbour (crisp QR modules)
    pub smooth: bool,
}

impl PartialEq for Overlay {
    fn eq(&self, o: &Self) -> bool {
        (self.x, self.y, self.w, self.h, self.smooth) == (o.x, o.y, o.w, o.h, o.smooth)
            && Rc::ptr_eq(&self.img, &o.img)
            && self.fit == o.fit
    }
}

pub enum Ev {
    Key(KeyEvent),
    Paste(Zeroizing<String>),
    Close,
}

// ---------------------------------------------------------------- window state

struct Win {
    hwnd: HWND,
    cols: u16,
    rows: u16,
    cw: i32,
    ch: i32,
    font_base: i32,
    dpi: u32,
    fonts: [HFONT; 4],
    face: Vec<u16>,
    grid: Vec<Cell>,
    cursor: (u16, u16),
    cursor_on: bool,
    overlays: Vec<Overlay>,
    events: VecDeque<Ev>,
    hi_surrogate: Option<u16>,
    dirty: bool,
}

thread_local! {
    static WIN: RefCell<Option<Win>> = const { RefCell::new(None) };
}

fn with_win<R>(f: impl FnOnce(&mut Win) -> R) -> Option<R> {
    WIN.with(|c| c.try_borrow_mut().ok().and_then(|mut g| g.as_mut().map(f)))
}

fn push(ev: Ev) {
    with_win(|w| w.events.push_back(ev));
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn rgb(r: u8, g: u8, b: u8) -> u32 {
    r as u32 | (g as u32) << 8 | (b as u32) << 16
}

const BG: (u8, u8, u8) = (0x0a, 0x0e, 0x0b);
const FG: (u8, u8, u8) = (0x3e, 0xc4, 0x6d);

fn colour(c: Color, fg: bool) -> u32 {
    let (r, g, b) = match c {
        Color::Reset => {
            if fg {
                FG
            } else {
                BG
            }
        }
        Color::Black => (0, 0, 0),
        Color::Red => (0xc8, 0x3c, 0x3c),
        Color::Green => FG,
        Color::Yellow => (0xe6, 0xc8, 0x4a),
        Color::Blue => (0x4a, 0x8c, 0xe6),
        Color::Magenta => (0xc0, 0x6a, 0xd8),
        Color::Cyan => (0x4a, 0xc8, 0xd0),
        Color::Gray => (0xa8, 0xb0, 0xaa),
        Color::DarkGray => (0x5c, 0x6b, 0x61),
        Color::LightRed => (0xff, 0x6b, 0x6b),
        Color::LightGreen => (0x7d, 0xff, 0x9e),
        Color::LightYellow => (0xff, 0xe8, 0x7a),
        Color::LightBlue => (0x7a, 0xb4, 0xff),
        Color::LightMagenta => (0xe0, 0x9a, 0xf0),
        Color::LightCyan => (0x8a, 0xec, 0xf0),
        Color::White => (0xe8, 0xe8, 0xe8),
        Color::Rgb(r, g, b) => (r, g, b),
        Color::Indexed(_) => {
            if fg {
                FG
            } else {
                BG
            }
        }
    };
    rgb(r, g, b)
}

// ---------------------------------------------------------------- fonts / layout

unsafe fn make_font(face: &[u16], px: i32, bold: bool, italic: bool) -> HFONT {
    // DEFAULT_CHARSET 1, OUT_DEFAULT_PRECIS 0, CLIP_DEFAULT_PRECIS 0, CLEARTYPE_QUALITY 5,
    // FIXED_PITCH | FF_MODERN 0x31
    CreateFontW(-px, 0, 0, 0, if bold { 700 } else { 400 }, italic as u32, 0, 0, 1, 0, 0, 5, 0x31, face.as_ptr())
}

unsafe fn pick_face(hwnd: HWND) -> Vec<u16> {
    for name in ["Cascadia Mono", "Consolas"] {
        let face = wide(name);
        let f = make_font(&face, 16, false, false);
        let dc = GetDC(hwnd);
        let old = SelectObject(dc, f);
        let mut got = [0u16; 64];
        let n = GetTextFaceW(dc, got.len() as i32, got.as_mut_ptr());
        SelectObject(dc, old);
        ReleaseDC(hwnd, dc);
        DeleteObject(f);
        if n > 0 && String::from_utf16_lossy(&got[..(n as usize).saturating_sub(1)]).eq_ignore_ascii_case(name) {
            return face;
        }
    }
    wide("Consolas")
}

fn set_font(w: &mut Win) {
    // SAFETY: GDI object management on handles this struct owns; none of these calls dispatch
    // window messages.
    unsafe {
        for f in w.fonts {
            if !f.is_null() {
                DeleteObject(f);
            }
        }
        let px = w.font_base * w.dpi as i32 / 96;
        w.fonts = [
            make_font(&w.face, px, false, false),
            make_font(&w.face, px, true, false),
            make_font(&w.face, px, false, true),
            make_font(&w.face, px, true, true),
        ];
        let dc = GetDC(w.hwnd);
        let old = SelectObject(dc, w.fonts[0]);
        let mut tm: TEXTMETRICW = std::mem::zeroed();
        GetTextMetricsW(dc, &mut tm);
        let mut sz = SIZE { cx: 0, cy: 0 };
        let m = [b'M' as u16];
        GetTextExtentPoint32W(dc, m.as_ptr(), 1, &mut sz);
        SelectObject(dc, old);
        ReleaseDC(w.hwnd, dc);
        w.cw = sz.cx.max(4);
        w.ch = tm.tmHeight.max(8);
    }
    relayout(w, true);
}

fn relayout(w: &mut Win, force: bool) {
    let mut rc = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    // SAFETY: reading our own client rect.
    unsafe { GetClientRect(w.hwnd, &mut rc) };
    let cols = ((rc.right - 2 * PAD) / w.cw).max(20) as u16;
    let rows = ((rc.bottom - 2 * PAD) / w.ch).max(8) as u16;
    if force || (cols, rows) != (w.cols, w.rows) {
        w.cols = cols;
        w.rows = rows;
        w.grid = vec![Cell::default(); cols as usize * rows as usize];
        w.dirty = true;
    }
}

// ---------------------------------------------------------------- painting

unsafe fn fill(dc: HDC, r: &RECT, c: u32) {
    let b = CreateSolidBrush(c);
    FillRect(dc, r, b);
    DeleteObject(b);
}

unsafe fn paint(w: &Win) {
    let mut ps: PAINTSTRUCT = std::mem::zeroed();
    let hdc = BeginPaint(w.hwnd, &mut ps);
    let mut rc = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    GetClientRect(w.hwnd, &mut rc);
    let (cw_px, ch_px) = (rc.right.max(1), rc.bottom.max(1));
    let mem = CreateCompatibleDC(hdc);
    let bmp = CreateCompatibleBitmap(hdc, cw_px, ch_px);
    let old_bmp = SelectObject(mem, bmp);
    fill(mem, &rc, colour(Color::Reset, false));
    let old_font = SelectObject(mem, w.fonts[0]);

    let cols = w.cols as usize;
    let mut buf: Vec<u16> = Vec::new();
    let mut dx: Vec<i32> = Vec::new();
    for row in 0..w.rows as usize {
        let y = PAD + row as i32 * w.ch;
        let mut col = 0usize;
        while col < cols {
            let c0 = &w.grid[row * cols + col];
            let key = (c0.fg, c0.bg, c0.modifier);
            let start = col;
            buf.clear();
            dx.clear();
            while col < cols {
                let c = &w.grid[row * cols + col];
                if (c.fg, c.bg, c.modifier) != key {
                    break;
                }
                let sym = if c.symbol().is_empty() { " " } else { c.symbol() };
                let width = UnicodeWidthStr::width(sym).clamp(1, 2);
                let units: Vec<u16> = sym.chars().map(|ch| if ch.is_control() { ' ' } else { ch }).collect::<String>().encode_utf16().collect();
                for (i, u) in units.iter().enumerate() {
                    buf.push(*u);
                    dx.push(if i == 0 { w.cw * width as i32 } else { 0 });
                }
                col += width;
            }
            let (mut fg, mut bg) = (colour(key.0, true), colour(key.1, false));
            if key.2.contains(Modifier::REVERSED) {
                std::mem::swap(&mut fg, &mut bg);
            }
            let font = match (key.2.contains(Modifier::BOLD), key.2.contains(Modifier::ITALIC)) {
                (false, false) => w.fonts[0],
                (true, false) => w.fonts[1],
                (false, true) => w.fonts[2],
                (true, true) => w.fonts[3],
            };
            SelectObject(mem, font);
            SetTextColor(mem, fg);
            SetBkColor(mem, bg);
            let x0 = PAD + start as i32 * w.cw;
            let r = RECT { left: x0, top: y, right: PAD + col.min(cols) as i32 * w.cw, bottom: y + w.ch };
            ExtTextOutW(mem, x0, y, ETO_OPAQUE | ETO_CLIPPED, &r, buf.as_ptr(), buf.len() as u32, dx.as_ptr());
            if key.2.contains(Modifier::UNDERLINED) {
                let u = RECT { left: r.left, top: r.bottom - 2, right: r.right, bottom: r.bottom - 1 };
                fill(mem, &u, fg);
            }
        }
    }
    if w.cursor_on && w.cursor.0 < w.cols && w.cursor.1 < w.rows {
        let x = PAD + w.cursor.0 as i32 * w.cw;
        let y = PAD + w.cursor.1 as i32 * w.ch;
        fill(mem, &RECT { left: x, top: y + w.ch - 3, right: x + w.cw, bottom: y + w.ch - 1 }, colour(Color::LightGreen, true));
    }
    for o in &w.overlays {
        draw_overlay(mem, w, o);
    }
    BitBlt(hdc, 0, 0, cw_px, ch_px, mem, 0, 0, SRCCOPY);
    SelectObject(mem, old_font);
    SelectObject(mem, old_bmp);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(w.hwnd, &ps);
}

unsafe fn draw_overlay(dc: HDC, w: &Win, o: &Overlay) {
    let (rx, ry) = (PAD + o.x as i32 * w.cw, PAD + o.y as i32 * w.ch);
    let (rw, rh) = (o.w as i32 * w.cw, o.h as i32 * w.ch);
    let (iw, ih) = (o.img.w as f64, o.img.h as f64);
    if rw <= 0 || rh <= 0 || o.img.w == 0 || o.img.h == 0 || o.img.bgra.len() < (o.img.w * o.img.h * 4) as usize {
        return;
    }
    let (dw, dh, dx, dy) = match o.fit {
        Fit::Contain => {
            let mut s = (rw as f64 / iw).min(rh as f64 / ih);
            if !o.smooth && s >= 1.0 {
                s = s.floor();
            }
            let (dw, dh) = (iw * s, ih * s);
            (dw, dh, (rw as f64 - dw) / 2.0, 0.0)
        }
        Fit::Width { overflow } => {
            let dh = ih * rw as f64 / iw;
            (rw as f64, dh, 0.0, -((dh - rh as f64).max(0.0) * overflow.clamp(0.0, 1.0) as f64))
        }
        Fit::WidthOffset { frac } => {
            let dh = ih * rw as f64 / iw;
            (rw as f64, dh, 0.0, -(dh * frac as f64))
        }
    };
    SaveDC(dc);
    IntersectClipRect(dc, rx, ry, rx + rw, ry + rh);
    // HALFTONE (4) for photos and pages, COLORONCOLOR (3) for crisp QR modules
    SetStretchBltMode(dc, if o.smooth { 4 } else { 3 });
    SetBrushOrgEx(dc, 0, 0, std::ptr::null_mut());
    let mut bmi: BITMAPINFO = std::mem::zeroed();
    bmi.bmiHeader = BITMAPINFOHEADER {
        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: o.img.w as i32,
        biHeight: -(o.img.h as i32), // top-down
        biPlanes: 1,
        biBitCount: 32,
        biCompression: 0, // BI_RGB
        biSizeImage: 0,
        biXPelsPerMeter: 0,
        biYPelsPerMeter: 0,
        biClrUsed: 0,
        biClrImportant: 0,
    };
    StretchDIBits(
        dc,
        rx + dx as i32,
        ry + dy as i32,
        dw.round().max(1.0) as i32,
        dh.round().max(1.0) as i32,
        0,
        0,
        o.img.w as i32,
        o.img.h as i32,
        o.img.bgra.as_ptr().cast(),
        &bmi,
        0, // DIB_RGB_COLORS
        SRCCOPY,
    );
    RestoreDC(dc, -1);
}

// ---------------------------------------------------------------- input

fn key_state(vk: i32) -> bool {
    // SAFETY: plain query.
    unsafe { GetKeyState(vk) < 0 }
}

enum KeyAct {
    Key(KeyEvent),
    Paste,
    Zoom(i32),
}

fn key_down(vk: u16) -> Option<KeyAct> {
    let ctrl = key_state(0x11);
    let alt = key_state(0x12);
    let shift = key_state(0x10);
    let mut mods = KeyModifiers::NONE;
    if ctrl {
        mods |= KeyModifiers::CONTROL;
    }
    if shift {
        mods |= KeyModifiers::SHIFT;
    }
    if alt {
        mods |= KeyModifiers::ALT;
    }
    let code = match vk {
        0x0D => KeyCode::Enter,
        0x08 => KeyCode::Backspace,
        0x09 if shift => KeyCode::BackTab,
        0x09 => KeyCode::Tab,
        0x1B => KeyCode::Esc,
        0x21 => KeyCode::PageUp,
        0x22 => KeyCode::PageDown,
        0x23 => KeyCode::End,
        0x24 => KeyCode::Home,
        0x25 => KeyCode::Left,
        0x26 => KeyCode::Up,
        0x27 => KeyCode::Right,
        0x28 => KeyCode::Down,
        0x2E => KeyCode::Delete,
        0x70..=0x7B => KeyCode::F((vk - 0x70 + 1) as u8),
        0x56 if ctrl && !alt => return Some(KeyAct::Paste),
        0xBB | 0x6B if ctrl && !alt => return Some(KeyAct::Zoom(1)),
        0xBD | 0x6D if ctrl && !alt => return Some(KeyAct::Zoom(-1)),
        0x30 | 0x60 if ctrl && !alt => return Some(KeyAct::Zoom(0)),
        0x41..=0x5A if ctrl && !alt => KeyCode::Char((vk as u8 as char).to_ascii_lowercase()),
        _ => return None, // printable keys arrive as WM_CHAR
    };
    Some(KeyAct::Key(KeyEvent::new(code, mods)))
}

fn clipboard_text(hwnd: HWND) -> Option<Zeroizing<String>> {
    // SAFETY: standard clipboard read; the locked buffer is bounded by GlobalSize.
    unsafe {
        if OpenClipboard(hwnd) == 0 {
            return None;
        }
        let mut out = None;
        let h = GetClipboardData(13); // CF_UNICODETEXT
        if !h.is_null() {
            let p = GlobalLock(h) as *const u16;
            if !p.is_null() {
                let max = (GlobalSize(h) / 2).min(64 * 1024);
                let s = std::slice::from_raw_parts(p, max);
                let n = s.iter().position(|&c| c == 0).unwrap_or(max);
                out = Some(Zeroizing::new(String::from_utf16_lossy(&s[..n])));
                GlobalUnlock(h);
            }
        }
        CloseClipboard();
        out
    }
}

/// Read the clipboard as text (courier: an encrypted block copied from an email). Explicit
/// command only; Scytale never reads the clipboard on its own.
pub fn read_clipboard() -> Option<Zeroizing<String>> {
    let hwnd = with_win(|w| w.hwnd)?;
    clipboard_text(hwnd)
}

/// Put text on the clipboard. Used only for courier output, which is ciphertext.
pub fn write_clipboard(text: &str) -> bool {
    let Some(hwnd) = with_win(|w| w.hwnd) else { return false };
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = wide.len() * 2;
    // SAFETY: standard clipboard write; the global block is sized for the UTF-16 text and NUL,
    // and ownership passes to the system only if SetClipboardData succeeds.
    unsafe {
        if OpenClipboard(hwnd) == 0 {
            return false;
        }
        let mut ok = false;
        if EmptyClipboard() != 0 {
            let h = GlobalAlloc(GMEM_MOVEABLE, bytes);
            if !h.is_null() {
                let p = GlobalLock(h) as *mut u16;
                if !p.is_null() {
                    std::ptr::copy_nonoverlapping(wide.as_ptr(), p, wide.len());
                    GlobalUnlock(h);
                    ok = !SetClipboardData(13, h).is_null(); // CF_UNICODETEXT
                }
                if !ok {
                    GlobalFree(h);
                }
            }
        }
        CloseClipboard();
        ok
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            let painted = WIN.with(|c| match c.try_borrow() {
                Ok(g) => g.as_ref().map(|w| paint(w)).is_some(),
                Err(_) => false,
            });
            if painted {
                return 0;
            }
        }
        WM_ERASEBKGND => return 1,
        WM_SIZE => {
            with_win(|w| relayout(w, false));
            InvalidateRect(hwnd, std::ptr::null(), 0);
            return 0;
        }
        WM_CLOSE => {
            push(Ev::Close);
            return 0;
        }
        WM_KEYDOWN | WM_SYSKEYDOWN => match key_down(wp as u16) {
            Some(KeyAct::Key(k)) => {
                push(Ev::Key(k));
                return 0;
            }
            Some(KeyAct::Paste) => {
                if let Some(t) = clipboard_text(hwnd) {
                    push(Ev::Paste(t));
                }
                return 0;
            }
            Some(KeyAct::Zoom(d)) => {
                with_win(|w| {
                    w.font_base = if d == 0 { BASE_FONT_PX } else { (w.font_base + d).clamp(10, 40) };
                    set_font(w);
                });
                InvalidateRect(hwnd, std::ptr::null(), 0);
                return 0;
            }
            None => {}
        },
        WM_CHAR => {
            let u = wp as u16;
            let ch = with_win(|w| {
                if (0xD800..0xDC00).contains(&u) {
                    w.hi_surrogate = Some(u);
                    None
                } else if (0xDC00..0xE000).contains(&u) {
                    let hi = w.hi_surrogate.take()?;
                    char::decode_utf16([hi, u]).next()?.ok()
                } else {
                    char::from_u32(u as u32)
                }
            })
            .flatten();
            if let Some(c) = ch {
                if !c.is_control() {
                    push(Ev::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)));
                }
            }
            return 0;
        }
        WM_MOUSEWHEEL => {
            let delta = ((wp >> 16) & 0xffff) as u16 as i16;
            let code = if delta > 0 { KeyCode::Up } else { KeyCode::Down };
            for _ in 0..3 {
                push(Ev::Key(KeyEvent::new(code, KeyModifiers::NONE)));
            }
            return 0;
        }
        WM_DPICHANGED => {
            let dpi = (wp & 0xffff) as u32;
            with_win(|w| {
                w.dpi = dpi.max(96);
                set_font(w);
            });
            let r = &*(lp as *const RECT);
            SetWindowPos(hwnd, std::ptr::null_mut(), r.left, r.top, r.right - r.left, r.bottom - r.top, SWP_NOZORDER | SWP_NOACTIVATE);
            return 0;
        }
        _ => {}
    }
    DefWindowProcW(hwnd, msg, wp, lp)
}

// ---------------------------------------------------------------- public API

/// Create and show the window. Returns whether screen-capture exclusion is active.
pub fn create() -> Result<bool, String> {
    // SAFETY: standard window creation. WIN is set only after CreateWindowExW returns, and no
    // borrow of WIN is held across calls that dispatch messages (SetWindowPos, ShowWindow...).
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        let hinst = GetModuleHandleW(std::ptr::null());
        let class = wide("ScytaleMain");
        let mut wc: WNDCLASSW = std::mem::zeroed();
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = hinst;
        wc.hCursor = LoadCursorW(std::ptr::null_mut(), IDC_ARROW);
        wc.lpszClassName = class.as_ptr();
        if RegisterClassW(&wc) == 0 {
            return Err("could not register the window class".into());
        }
        let title = wide("Scytale");
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            1200,
            800,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinst,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            return Err("could not create the window".into());
        }
        let protected = SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) != 0;
        let dpi = GetDpiForWindow(hwnd).max(96);
        let mut w = Win {
            hwnd,
            cols: 0,
            rows: 0,
            cw: 9,
            ch: 18,
            font_base: BASE_FONT_PX,
            dpi,
            fonts: [std::ptr::null_mut(); 4],
            face: pick_face(hwnd),
            grid: Vec::new(),
            cursor: (0, 0),
            cursor_on: false,
            overlays: Vec::new(),
            events: VecDeque::new(),
            hi_surrogate: None,
            dirty: true,
        };
        set_font(&mut w);
        let (cw, ch) = (w.cw, w.ch);
        WIN.with(|c| *c.borrow_mut() = Some(w));
        let mut r = RECT { left: 0, top: 0, right: 2 * PAD + 112 * cw, bottom: 2 * PAD + 38 * ch };
        AdjustWindowRectExForDpi(&mut r, WS_OVERLAPPEDWINDOW, 0, 0, dpi);
        SetWindowPos(hwnd, std::ptr::null_mut(), 0, 0, r.right - r.left, r.bottom - r.top, SWP_NOMOVE | SWP_NOZORDER);
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
        UpdateWindow(hwnd);
        Ok(protected)
    }
}

pub fn destroy() {
    if let Some(h) = with_win(|w| w.hwnd) {
        // SAFETY: our own window; no WIN borrow is held here.
        unsafe { DestroyWindow(h) };
    }
    WIN.with(|c| {
        if let Some(w) = c.borrow_mut().take() {
            for f in w.fonts {
                if !f.is_null() {
                    // SAFETY: fonts created by this module.
                    unsafe { DeleteObject(f) };
                }
            }
        }
    });
}

/// Wait up to `timeout` for input, pumping window messages.
pub fn next_event(timeout: Duration) -> Option<Ev> {
    if let Some(e) = with_win(|w| w.events.pop_front()).flatten() {
        return Some(e);
    }
    // SAFETY: standard message wait/pump on the thread that owns the window. No borrow is held.
    unsafe {
        MsgWaitForMultipleObjects(0, std::ptr::null(), 0, timeout.as_millis() as u32, QS_ALLINPUT);
        let mut m: MSG = std::mem::zeroed();
        while PeekMessageW(&mut m, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
    }
    with_win(|w| w.events.pop_front()).flatten()
}

/// Replace the image overlays (absolute cell coordinates). No-op when there is no window (tests).
pub fn set_overlays(v: Vec<Overlay>) {
    with_win(|w| {
        if w.overlays != v {
            w.overlays = v;
            w.dirty = true;
        }
    });
}

/// Cell size in pixels (sensible defaults when there is no window).
pub fn cell_px() -> (i32, i32) {
    with_win(|w| (w.cw, w.ch)).unwrap_or((9, 18))
}

pub fn message_box(title: &str, text: &str) {
    let (t, m) = (wide(title), wide(text));
    // SAFETY: owner-less message box with valid strings.
    unsafe { MessageBoxW(std::ptr::null_mut(), m.as_ptr(), t.as_ptr(), MB_OK | MB_ICONINFORMATION) };
}

/// ratatui backend that renders into the window.
pub struct GuiBackend;

impl Backend for GuiBackend {
    type Error = io::Error;

    fn draw<'a, I>(&mut self, content: I) -> io::Result<()>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        with_win(|w| {
            for (x, y, c) in content {
                if x < w.cols && y < w.rows {
                    w.grid[y as usize * w.cols as usize + x as usize] = c.clone();
                    w.dirty = true;
                }
            }
        });
        Ok(())
    }

    fn hide_cursor(&mut self) -> io::Result<()> {
        with_win(|w| {
            if w.cursor_on {
                w.cursor_on = false;
                w.dirty = true;
            }
        });
        Ok(())
    }

    fn show_cursor(&mut self) -> io::Result<()> {
        with_win(|w| {
            if !w.cursor_on {
                w.cursor_on = true;
                w.dirty = true;
            }
        });
        Ok(())
    }

    fn get_cursor_position(&mut self) -> io::Result<Position> {
        Ok(with_win(|w| Position { x: w.cursor.0, y: w.cursor.1 }).unwrap_or_default())
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> io::Result<()> {
        let p = position.into();
        with_win(|w| {
            if w.cursor != (p.x, p.y) {
                w.cursor = (p.x, p.y);
                w.dirty = true;
            }
        });
        Ok(())
    }

    fn clear(&mut self) -> io::Result<()> {
        with_win(|w| {
            for c in w.grid.iter_mut() {
                c.reset();
            }
            w.dirty = true;
        });
        Ok(())
    }

    fn clear_region(&mut self, clear_type: ClearType) -> io::Result<()> {
        with_win(|w| {
            let (cols, rows) = (w.cols as usize, w.rows as usize);
            let (cx, cy) = ((w.cursor.0 as usize).min(cols), (w.cursor.1 as usize).min(rows));
            let at = cy * cols + cx;
            let line = cy * cols;
            let range = match clear_type {
                ClearType::All => 0..cols * rows,
                ClearType::AfterCursor => at..cols * rows,
                ClearType::BeforeCursor => 0..(at + 1).min(cols * rows),
                ClearType::CurrentLine => line..(line + cols).min(cols * rows),
                ClearType::UntilNewLine => at..(line + cols).min(cols * rows),
            };
            // Clamp so the slice can never panic (panic = abort), whatever the cursor holds.
            let end = range.end.min(w.grid.len());
            let start = range.start.min(end);
            for c in &mut w.grid[start..end] {
                c.reset();
            }
            w.dirty = true;
        });
        Ok(())
    }

    fn size(&self) -> io::Result<Size> {
        Ok(with_win(|w| Size { width: w.cols, height: w.rows }).unwrap_or(Size { width: 80, height: 24 }))
    }

    fn window_size(&mut self) -> io::Result<WindowSize> {
        let (cols, rows, cw, ch) = with_win(|w| (w.cols, w.rows, w.cw, w.ch)).unwrap_or((80, 24, 9, 18));
        Ok(WindowSize {
            columns_rows: Size { width: cols, height: rows },
            pixels: Size { width: (cols as i32 * cw) as u16, height: (rows as i32 * ch) as u16 },
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some((hwnd, true)) = with_win(|w| (w.hwnd, std::mem::take(&mut w.dirty))) {
            // SAFETY: repaint our own window; the WIN borrow above has been released.
            unsafe {
                InvalidateRect(hwnd, std::ptr::null(), 0);
                UpdateWindow(hwnd);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Graphics::Gdi::{GetPixel, CreateCompatibleDC as Ccdc};

    /// Opens a real window for about a second, paints it a known colour and checks that a screen
    /// capture does NOT contain it. Run alone: cargo test -- --ignored capture_exclusion --nocapture
    #[test]
    #[ignore]
    fn capture_exclusion() {
        let protected = create().unwrap();
        assert!(protected, "SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) failed");
        // fill the grid with a solid magenta background
        let mut be = GuiBackend;
        let sz = be.size().unwrap();
        let mut cell = Cell::default();
        cell.set_bg(Color::Rgb(255, 0, 255));
        let mut cells: Vec<(u16, u16, Cell)> = Vec::new();
        for y in 0..sz.height {
            for x in 0..sz.width {
                cells.push((x, y, cell.clone()));
            }
        }
        be.draw(cells.iter().map(|(x, y, c)| (*x, *y, c))).unwrap();
        be.flush().unwrap();
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_millis(800) {
            next_event(Duration::from_millis(50));
        }
        let hwnd = with_win(|w| w.hwnd).unwrap();
        // what a screenshot tool sees: BitBlt from the screen DC at the window's centre
        let capture = || unsafe {
            let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
            windows_sys::Win32::UI::WindowsAndMessaging::GetWindowRect(hwnd, &mut r);
            let (cx, cy) = ((r.left + r.right) / 2, (r.top + r.bottom) / 2);
            let screen = GetDC(std::ptr::null_mut());
            let mem = Ccdc(screen);
            let bmp = CreateCompatibleBitmap(screen, 1, 1);
            let old = SelectObject(mem, bmp);
            BitBlt(mem, 0, 0, 1, 1, screen, cx, cy, SRCCOPY);
            let px = GetPixel(mem, 0, 0) & 0xffffff;
            SelectObject(mem, old);
            DeleteObject(bmp);
            DeleteDC(mem);
            ReleaseDC(std::ptr::null_mut(), screen);
            px
        };
        let protected_px = capture();
        println!("protected capture at window centre: {protected_px:06x} (magenta = ff00ff)");

        // control: with protection switched off the same capture must see the magenta window,
        // proving it really was on screen
        unsafe { SetWindowDisplayAffinity(hwnd, 0) };
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_millis(500) {
            next_event(Duration::from_millis(50));
        }
        let open_px = capture();
        println!("unprotected capture at window centre: {open_px:06x}");
        destroy();
        assert_eq!(open_px, rgb(255, 0, 255), "control failed: window was not visible, test is inconclusive");
        assert_ne!(protected_px, rgb(255, 0, 255), "window content appeared in a screen capture");
    }
}
