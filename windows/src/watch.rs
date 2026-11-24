//! Watches for Windows lock / user switch, sleep, shutdown and console close, so the app can wipe
//! and exit before (or the moment after) the machine leaves the user's hands.
//!
//! A hidden top-level window on its own thread (owned by this process, never shown) receives the
//! session and power broadcasts. Being on a separate thread lets it hold the system briefly while
//! the main thread wipes. The main window's close button is handled by the window itself.

use std::{
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, WPARAM},
    System::{LibraryLoader::GetModuleHandleW, RemoteDesktop::WTSRegisterSessionNotification},
    UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
        TranslateMessage, MSG, WNDCLASSW,
    },
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reason {
    WinLock,
    Suspend,
    Shutdown,
}

pub static EVENT: AtomicU8 = AtomicU8::new(0);
static ACK: AtomicBool = AtomicBool::new(false);

const WM_QUERYENDSESSION: u32 = 0x0011;
const WM_ENDSESSION: u32 = 0x0016;
const WM_POWERBROADCAST: u32 = 0x0218;
const WM_WTSSESSION_CHANGE: u32 = 0x02B1;
const PBT_APMSUSPEND: usize = 0x0004;
const WTS_CONSOLE_DISCONNECT: usize = 0x2;
const WTS_REMOTE_DISCONNECT: usize = 0x4;
const WTS_SESSION_LOCK: usize = 0x7;

pub fn signal(r: Reason) {
    let v = match r {
        Reason::WinLock => 1,
        Reason::Suspend => 2,
        Reason::Shutdown => 3,
    };
    // keep the first reason if several arrive
    let _ = EVENT.compare_exchange(0, v, Ordering::SeqCst, Ordering::SeqCst);
}

pub fn take() -> Option<Reason> {
    match EVENT.swap(0, Ordering::SeqCst) {
        1 => Some(Reason::WinLock),
        2 => Some(Reason::Suspend),
        3 => Some(Reason::Shutdown),
        _ => None,
    }
}

/// Called by the main loop once secrets are wiped.
pub fn ack() {
    ACK.store(true, Ordering::SeqCst);
}

/// Hold the notifying thread (the system is waiting on us) until the main loop has wiped, or
/// give up after a short grace period.
fn wait_for_wipe(limit: Duration) {
    let start = Instant::now();
    while !ACK.load(Ordering::SeqCst) && start.elapsed() < limit {
        std::thread::sleep(Duration::from_millis(20));
    }
}

unsafe extern "system" fn wndproc(h: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        WM_WTSSESSION_CHANGE
            if matches!(w, WTS_SESSION_LOCK | WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT) =>
        {
            signal(Reason::WinLock);
            0
        }
        WM_POWERBROADCAST if w == PBT_APMSUSPEND => {
            signal(Reason::Suspend);
            wait_for_wipe(Duration::from_millis(1500));
            1
        }
        WM_QUERYENDSESSION => {
            signal(Reason::Shutdown);
            wait_for_wipe(Duration::from_millis(1500));
            1
        }
        WM_ENDSESSION => {
            signal(Reason::Shutdown);
            wait_for_wipe(Duration::from_millis(1500));
            0
        }
        _ => DefWindowProcW(h, msg, w, l),
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Start the watcher. Returns false if the notification window could not be created (the caller
/// shows this, so the user knows lock/sleep protection is not active).
pub fn start() -> bool {
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    std::thread::spawn(move || {
        // SAFETY: standard Win32 window creation and message loop on this thread; the class name
        // and title buffers outlive the calls that use them.
        unsafe {
            let class = wide("ScytaleSessionWatch");
            let title = wide("Scytale");
            let hinst = GetModuleHandleW(std::ptr::null());
            let mut wc: WNDCLASSW = std::mem::zeroed();
            wc.lpfnWndProc = Some(wndproc);
            wc.hInstance = hinst;
            wc.lpszClassName = class.as_ptr();
            if RegisterClassW(&wc) == 0 {
                let _ = tx.send(false);
                return;
            }
            let hwnd = CreateWindowExW(
                0,
                class.as_ptr(),
                title.as_ptr(),
                0, // WS_OVERLAPPED, never shown
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                hinst,
                std::ptr::null(),
            );
            if hwnd.is_null() {
                let _ = tx.send(false);
                return;
            }
            let ok = WTSRegisterSessionNotification(hwnd, 0) != 0; // NOTIFY_FOR_THIS_SESSION
            let _ = tx.send(ok);
            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(3)).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowW, SendMessageW};

    /// Run alone (it shares the global event flag with the UI test):
    /// cargo test -- --ignored watcher_receives_real_messages
    #[test]
    #[ignore]
    fn watcher_receives_real_messages() {
        assert!(start(), "watch window or WTS registration failed");
        let class = wide("ScytaleSessionWatch");
        // SAFETY: looking up and messaging our own window.
        unsafe {
            let h = FindWindowW(class.as_ptr(), std::ptr::null());
            assert!(!h.is_null());
            let _ = take();
            SendMessageW(h, WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK, 0);
            assert_eq!(take(), Some(Reason::WinLock));
            SendMessageW(h, WM_WTSSESSION_CHANGE, 0x8, 0); // WTS_SESSION_UNLOCK: ignored
            assert_eq!(take(), None);
            ack();
            SendMessageW(h, WM_POWERBROADCAST, PBT_APMSUSPEND, 0);
            assert_eq!(take(), Some(Reason::Suspend));
            SendMessageW(h, WM_QUERYENDSESSION, 0, 0);
            assert_eq!(take(), Some(Reason::Shutdown));
        }
    }
}
