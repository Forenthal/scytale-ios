//! Terminal-style interface. One frame layout everywhere: title bar, body, hint bar.
//! Nothing here writes to disk except through `Vault` and the audit `Store`.

use std::{
    mem,
    path::{Path, PathBuf},
    rc::Rc,
    time::{Duration, Instant},
};

use data_encoding::BASE32_NOPAD;
use ratatui::{
    backend::Backend,
    crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame, Terminal,
};
use zeroize::Zeroizing;

use crate::{
    audit::{ev, Chain, Store, FREE_ATTEMPTS},
    crypto,
    gui::{self, Ev, Fit, Overlay, Pixels},
    secret::{Secret32, SecretInput},
    util::{fmt_dur, fmt_size, fmt_utc, unix_now},
    vault::{Kind, Session, Vault, MSG_CAP, VIEW_CAP},
    viewer::FileView,
    watch::{self, Reason},
};

const IDLE_SECS: u64 = 300;
const MSG_VIEW_SECS: u64 = 300;
const MIN_PW_CHARS: usize = 14;
const OUT_KEEP: usize = 400;

// ---------------------------------------------------------------- types

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum K {
    N,
    Dim,
    Ok,
    Err,
    Warn,
    Head,
}

pub(crate) fn style(k: K) -> Style {
    match k {
        K::N => Style::new().fg(Color::Green),
        K::Dim => Style::new().fg(Color::DarkGray),
        K::Ok => Style::new().fg(Color::LightGreen),
        K::Err => Style::new().fg(Color::LightRed).add_modifier(Modifier::BOLD),
        K::Warn => Style::new().fg(Color::Yellow),
        K::Head => Style::new().fg(Color::LightGreen).add_modifier(Modifier::BOLD),
    }
}

/// Replace control characters so file or message content can never send escape sequences to the
/// terminal.
pub(crate) fn clean(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { '\u{b7}' } else { c }).collect()
}

pub(crate) fn ln(k: K, s: impl AsRef<str>) -> Line<'static> {
    Line::from(Span::styled(format!(" {}", clean(s.as_ref())), style(k)))
}

struct OutLine {
    k: K,
    s: String,
}

#[derive(Clone, Copy, PartialEq)]
enum WKind {
    Setup,
    Recover,
    Passwd,
}

#[derive(Clone, Copy, PartialEq)]
enum Step {
    Rk,
    Pw,
    Totp,
    ShowRk,
}

struct Wizard {
    kind: WKind,
    step: Step,
    rk_in: SecretInput,
    pw1: SecretInput,
    pw2: SecretInput,
    field: u8,
    code: String,
    totp: Option<Zeroizing<Vec<u8>>>,
    rk: Option<Secret32>,
    mk: Option<Secret32>,
    qr: Zeroizing<String>,
    qr_px: Option<Rc<Pixels>>,
    secret_txt: Zeroizing<String>,
    totp_step: u64,
    err: Option<String>,
}

impl Wizard {
    fn new(kind: WKind, mk: Option<Secret32>) -> Wizard {
        Wizard {
            kind,
            step: match kind {
                WKind::Recover => Step::Rk,
                _ => Step::Pw,
            },
            rk_in: SecretInput::new(96),
            pw1: SecretInput::new(256),
            pw2: SecretInput::new(256),
            field: 0,
            code: String::new(),
            totp: None,
            rk: None,
            mk,
            qr: Zeroizing::new(String::new()),
            qr_px: None,
            secret_txt: Zeroizing::new(String::new()),
            totp_step: 0,
            err: None,
        }
    }
}

struct Login {
    pw: SecretInput,
    code: String,
    field: u8,
    note: Option<(K, String)>,
}

impl Login {
    fn new(note: Option<(K, String)>) -> Login {
        Login { pw: SecretInput::new(256), code: String::new(), field: 0, note }
    }
}

#[derive(Clone)]
enum Act {
    View { id: String },
    Read { id: String },
    Passwd,
    /// Open a courier message from the paired device.
    Recv { path: String },
    /// Seal a vault file for the paired device; `path` empty = the Desktop.
    SendFile { id: String, path: String },
}

struct Reauth {
    pw: SecretInput,
    act: Act,
    note: Option<String>,
}

struct View {
    short: String,
    text: SecretInput,
    until: Instant,
}

enum Mode {
    Login(Login),
    Wizard(Box<Wizard>),
    Shell,
    Compose(SecretInput),
    Reauth(Reauth),
    View(View),
    FileView(Box<FileView>),
    Wait,
}

enum Job {
    Login { pw: SecretInput, code: String },
    Commit(Box<Wizard>),
    Reauth { pw: SecretInput, act: Act },
    Enc(String),
}

enum ReauthResult {
    Ok,
    Bad,
    LockedOut,
}

pub struct App {
    vault: Vault,
    store: Option<Store>,
    mode: Mode,
    out: Vec<OutLine>,
    cmd: String,
    sess: Option<Session>,
    sess_start: Option<Instant>,
    job: Option<Job>,
    busy: Option<&'static str>,
    last_input: Instant,
    last_wall: u64,
    /// Body height from the last frame, used for page-sized scrolling in the file viewer.
    body_h: std::cell::Cell<usize>,
    warn: Option<&'static str>,
    pub quit: bool,
    /// Printed to the console after the interface closes (never contains secrets).
    pub exit_note: Option<String>,
    /// Courier state (identity, one-time keys, paired device), loaded on first use per session.
    courier: Option<crate::courier::State>,
    /// Set while composing a courier message: (destroy on receipt, output path).
    courier_target: Option<(bool, String)>,
    /// An encrypted courier message pasted at the prompt, waiting for `recv` (ciphertext).
    courier_paste: Option<Zeroizing<String>>,
}

// ---------------------------------------------------------------- app: lifecycle

impl App {
    pub fn new(dir: PathBuf, watch_ok: bool, capture_protected: bool) -> App {
        let vault = Vault::new(dir.clone());
        let mut app = App {
            vault,
            store: None,
            mode: Mode::Wait,
            out: Vec::new(),
            cmd: String::new(),
            sess: None,
            sess_start: None,
            job: None,
            busy: None,
            last_input: Instant::now(),
            last_wall: 0,
            body_h: std::cell::Cell::new(20),
            warn: match (watch_ok, capture_protected) {
                (true, true) => None,
                (false, true) => Some("WINDOWS LOCK/SLEEP DETECTION UNAVAILABLE"),
                (true, false) => Some("SCREEN CAPTURE PROTECTION UNAVAILABLE"),
                (false, false) => Some("LOCK/SLEEP DETECTION AND SCREEN CAPTURE PROTECTION UNAVAILABLE"),
            },
            quit: false,
            exit_note: None,
            courier: None,
            courier_target: None,
            courier_paste: None,
        };
        if !app.vault.exists() {
            app.mode = Mode::Wizard(Box::new(Wizard::new(WKind::Setup, None)));
            return app;
        }
        match Store::load(&dir) {
            Ok(mut s) => {
                let mut notes = Vec::new();
                if s.was_reset {
                    let _ = s.log(ev::STATE_RESET, 0);
                    notes.push("integrity check of the lockout state failed; locked for 15 minutes".to_string());
                }
                if s.st.session_start != 0 {
                    let _ = s.log(ev::ABORTED, 0);
                    s.st.session_start = 0;
                    let _ = s.save_state();
                }
                // say why the previous session ended (from the audit log)
                let last = s.read().ok().and_then(|(e, _)| e.into_iter().rev().find(|x| x.ev != ev::LOGIN_FAIL && x.ev != ev::LOCKOUT));
                let why = last.and_then(|e| {
                    let r = match e.ev.as_str() {
                        ev::TIMEOUT => "after 5 minutes without activity",
                        ev::WIN_LOCK => "because Windows was locked",
                        ev::SUSPEND => "because the PC went to sleep",
                        ev::SHUTDOWN => "because Windows shut down",
                        ev::ABORTED => "unexpectedly (the app was killed or crashed)",
                        _ => return None,
                    };
                    Some(format!("previous session closed {r} on {} UTC; its memory was wiped", fmt_utc(e.ts)))
                });
                app.store = Some(s);
                let note = notes.pop().map(|n| (K::Warn, n)).or(why.map(|n| (K::Dim, n)));
                app.mode = Mode::Login(Login::new(note));
            }
            Err(_) => {
                app.mode = Mode::Login(Login::new(Some((
                    K::Err,
                    "the audit key cannot be opened (different Windows account or machine). \
                     Press F2 to recover with your recovery key."
                        .to_string(),
                ))));
            }
        }
        app
    }

    pub fn run<B: Backend>(&mut self, term: &mut Terminal<B>) -> std::io::Result<()> {
        while !self.quit {
            term.draw(|f| draw(f, self)).map_err(|e| std::io::Error::other(e.to_string()))?;
            if let Some(job) = self.job.take() {
                self.run_job(job);
                self.busy = None;
                // a long operation is activity, not idle time or a sleep gap
                self.last_input = Instant::now();
                self.last_wall = unix_now();
                continue;
            }
            match gui::next_event(Duration::from_millis(200)) {
                Some(Ev::Key(k)) => self.on_key(k),
                Some(Ev::Paste(t)) => self.on_paste(&t),
                Some(Ev::Close) => self.terminate(ev::LOGOUT, "window closed"),
                None => {}
            }
            self.tick();
        }
        self.end_session(ev::LOGOUT);
        Ok(())
    }

    fn say(&mut self, k: K, s: impl Into<String>) {
        self.out.push(OutLine { k, s: s.into() });
        if self.out.len() > OUT_KEEP {
            self.out.drain(..self.out.len() - OUT_KEEP);
        }
    }

    fn audit(&mut self, event: &str, extra: u64) {
        let ok = self.store.as_mut().map_or(false, |s| s.log(event, extra).is_ok());
        if !ok {
            self.warn = Some("AUDIT LOG WRITE FAILED");
        }
    }

    fn end_session(&mut self, event: &str) {
        if self.sess.is_some() {
            let dur = self.sess_start.take().map_or(0, |i| i.elapsed().as_secs());
            self.audit(event, dur);
            if let Some(s) = self.store.as_mut() {
                s.st.session_start = 0;
                let _ = s.save_state();
            }
        }
        self.sess = None; // keys are zeroized on drop
        self.courier = None; // courier identity and one-time keys zeroized on drop
        self.courier_paste = None;
        self.courier_target = None;
        self.out.clear();
        self.cmd.clear();
    }

    fn lock_session(&mut self, event: &str, why: &str) {
        self.end_session(event);
        self.mode = Mode::Login(Login::new(Some((K::Warn, why.to_string()))));
    }

    /// Wipe everything held in memory, log the reason (if a session was open) and exit. The next
    /// start shows why on the login screen.
    fn terminate(&mut self, event: &str, _why: &str) {
        self.end_session(event);
        self.mode = Mode::Wait; // drops any open message, draft, file or password field
        self.job = None;
        self.quit = true;
        watch::ack();
    }

    /// Clipboard paste (Ctrl+V). Newlines are kept only in the message editor.
    fn on_paste(&mut self, text: &str) {
        self.last_input = Instant::now();
        // A whole encrypted courier message pasted at the prompt (far longer than a command line):
        // hold it for `recv` instead of flattening it into the command.
        if matches!(self.mode, Mode::Shell) && text.contains("-----BEGIN SCYTALE MESSAGE-----") {
            self.courier_paste = Some(Zeroizing::new(text.to_string()));
            self.say(K::Ok, format!("encrypted courier message pasted ({} characters). type recv to open it.", text.len()));
            return;
        }
        let printable = || text.chars().filter(|c| !c.is_control());
        match &mut self.mode {
            Mode::Login(l) => {
                if l.field == 0 {
                    printable().for_each(|c| {
                        l.pw.push(c);
                    });
                } else {
                    text.chars().filter(char::is_ascii_digit).take(6 - l.code.len()).for_each(|c| l.code.push(c));
                }
            }
            Mode::Wizard(w) => match w.step {
                Step::Rk => printable().for_each(|c| {
                    w.rk_in.push(c);
                }),
                Step::Pw => {
                    let f = if w.field == 0 { &mut w.pw1 } else { &mut w.pw2 };
                    printable().for_each(|c| {
                        f.push(c);
                    });
                }
                Step::Totp => text.chars().filter(char::is_ascii_digit).take(6 - w.code.len()).for_each(|c| w.code.push(c)),
                Step::ShowRk => {} // must be typed
            },
            Mode::Reauth(r) => printable().for_each(|c| {
                r.pw.push(c);
            }),
            Mode::Shell => {
                for c in text.chars() {
                    let c = if c == '\n' || c == '\t' { ' ' } else { c };
                    if !c.is_control() && self.cmd.len() < 1024 {
                        self.cmd.push(c);
                    }
                }
            }
            Mode::Compose(t) => {
                for c in text.chars() {
                    match c {
                        '\r' => {}
                        '\t' => (0..4).for_each(|_| {
                            t.push(' ');
                        }),
                        '\n' => {
                            t.push('\n');
                        }
                        c if !c.is_control() => {
                            t.push(c);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    fn tick(&mut self) {
        if let Some(r) = watch::take() {
            let (event, why) = match r {
                Reason::WinLock => (ev::WIN_LOCK, "Windows was locked or the user was switched"),
                Reason::Suspend => (ev::SUSPEND, "the PC went to sleep"),
                Reason::Shutdown => (ev::SHUTDOWN, "the window was closed or Windows is shutting down"),
            };
            return self.terminate(event, why);
        }
        // Fallback for a missed sleep notification: wall-clock time jumped between ticks.
        let now = unix_now();
        if self.last_wall != 0 && now > self.last_wall + 60 {
            return self.terminate(ev::SUSPEND, "a sleep or hibernate gap was detected");
        }
        self.last_wall = now;
        if self.last_input.elapsed().as_secs() >= IDLE_SECS {
            return self.terminate(ev::TIMEOUT, "no activity for 5 minutes");
        }
        let expired = matches!(&self.mode, Mode::View(v) if Instant::now() >= v.until);
        if expired {
            self.mode = Mode::Shell; // drops and wipes the message
            self.audit(ev::MSG_EXPIRE, 0);
            self.say(K::Warn, "message expired and was wiped from memory");
        }
    }

    // ------------------------------------------------------------ session start

    fn open_session(&mut self, mk: Secret32) -> Result<(), String> {
        let now = unix_now();
        let mut sess = Session::new(mk);
        let (dropped, shredded) = self
            .vault
            .load_index(&mut sess)
            .map_err(|e| format!("vault index failed its integrity check ({e}); not opened"))?;
        let store = self.store.as_mut().ok_or("audit store unavailable")?;
        store.st.session_start = now;
        if store.log(ev::LOGIN_OK, 0).is_err() {
            store.st.session_start = 0;
            return Err("audit log unavailable; login refused".into());
        }
        // last-login summary and chain health, from the audit log
        let mut lines: Vec<(K, String)> = Vec::new();
        if let Ok((entries, chain)) = store.read() {
            let oks: Vec<_> = entries.iter().filter(|e| e.ev == ev::LOGIN_OK).collect();
            if oks.len() >= 2 {
                let prev = oks[oks.len() - 2];
                let fails = entries.iter().filter(|e| e.seq > prev.seq && e.ev == ev::LOGIN_FAIL).count();
                lines.push((
                    if fails > 0 { K::Warn } else { K::Dim },
                    format!("last login {} UTC; {} failed attempt(s) since", fmt_utc(prev.ts), fails),
                ));
            }
            match chain {
                Chain::Intact => {}
                Chain::Broken(n) => lines.push((K::Err, format!("AUDIT LOG TAMPERING DETECTED at entry {n}"))),
                Chain::Truncated => lines.push((K::Err, "AUDIT LOG TRUNCATED: entries were removed".to_string())),
            }
        }
        self.sess = Some(sess);
        self.sess_start = Some(Instant::now());
        self.last_input = Instant::now();
        self.out.clear();
        self.say(K::Head, "SCYTALE 1.0  vault unlocked.  type 'help'.");
        for (k, l) in lines {
            self.say(k, l);
        }
        if dropped > 0 {
            self.say(K::Warn, format!("{dropped} index entr{} had no data file and were removed", if dropped == 1 { "y" } else { "ies" }));
        }
        if shredded > 0 {
            self.say(K::Warn, format!("{shredded} leftover vault file(s) from an interrupted operation were erased"));
        }
        self.mode = Mode::Shell;
        Ok(())
    }

    // ------------------------------------------------------------ jobs (run after the busy frame is drawn)

    fn run_job(&mut self, job: Job) {
        match job {
            Job::Login { pw, code } => self.run_login(pw, code),
            Job::Commit(w) => self.run_commit(*w),
            Job::Reauth { pw, act } => self.run_reauth(pw, act),
            Job::Enc(path) => {
                self.cmd_enc(&path);
                self.mode = Mode::Shell;
            }
        }
    }

    fn run_login(&mut self, pw: SecretInput, code: String) {
        let now = unix_now();
        let fail_note = |m: &str| Login::new(Some((K::Err, m.to_string())));
        let Some(store) = self.store.as_ref() else {
            self.mode = Mode::Login(fail_note("audit key unavailable; press F2 to recover"));
            return;
        };
        if let Some(r) = store.locked_remaining(now) {
            self.mode = Mode::Login(fail_note(&format!("locked: try again in {r} s")));
            return;
        }
        let last_step = store.st.last_step;
        let mk = self.vault.unlock(pw.as_bytes());
        drop(pw);
        let step = mk
            .as_ref()
            .and_then(|m| self.vault.totp_secret(m))
            .and_then(|t| crypto::totp_verify(&t, now, &code, last_step));

        match (mk, step) {
            (Some(mk), Some(step)) => {
                if let Some(s) = self.store.as_mut() {
                    s.register_success();
                    s.st.last_step = step;
                }
                match self.open_session(mk) {
                    Ok(()) => {}
                    Err(e) => {
                        self.mode = Mode::Login(fail_note(&e));
                        if let Some(s) = self.store.as_mut() {
                            let _ = s.log(ev::LOGIN_FAIL, 2);
                        }
                    }
                }
            }
            _ => {
                let mut msg = "authentication failed".to_string();
                if let Some(s) = self.store.as_mut() {
                    let lock = s.register_failure(now);
                    let _ = s.log(ev::LOGIN_FAIL, 0);
                    if let Some(secs) = lock {
                        let _ = s.log(ev::LOCKOUT, secs);
                        msg = format!("authentication failed; locked for {secs} s");
                    } else {
                        msg = format!("{msg}; {} attempt(s) before lockout", s.attempts_left());
                    }
                }
                self.mode = Mode::Login(fail_note(&msg));
            }
        }
    }

    fn reauth_check(&mut self, pw: &SecretInput) -> ReauthResult {
        let now = unix_now();
        if self.store.as_ref().map_or(false, |s| s.locked_remaining(now).is_some()) {
            return ReauthResult::LockedOut;
        }
        let mk = self.vault.unlock(pw.as_bytes());
        let ok = match (&mk, &self.sess) {
            (Some(m), Some(s)) => crypto::ct_eq(m.as_bytes(), s.mk.as_bytes()),
            _ => false,
        };
        if ok {
            return ReauthResult::Ok;
        }
        let mut locked = false;
        if let Some(s) = self.store.as_mut() {
            let lock = s.register_failure(now);
            let _ = s.log(ev::REAUTH_FAIL, 0);
            if let Some(secs) = lock {
                let _ = s.log(ev::LOCKOUT, secs);
                locked = true;
            }
        }
        if locked {
            ReauthResult::LockedOut
        } else {
            ReauthResult::Bad
        }
    }

    fn run_reauth(&mut self, pw: SecretInput, act: Act) {
        match self.reauth_check(&pw) {
            ReauthResult::Ok => {}
            ReauthResult::Bad => {
                self.mode = Mode::Reauth(Reauth {
                    pw: SecretInput::new(256),
                    act,
                    note: Some("authentication failed".into()),
                });
                return;
            }
            ReauthResult::LockedOut => {
                self.lock_session(ev::LOGOUT, "locked out after repeated failures");
                return;
            }
        }
        drop(pw);
        self.mode = Mode::Shell;
        match act {
            Act::View { id } => self.do_view(&id),
            Act::Read { id } => self.do_read(&id),
            Act::Passwd => {
                let mk = self.sess.as_ref().map(|s| Secret32::from_slice(s.mk.as_bytes()));
                self.mode = Mode::Wizard(Box::new(Wizard::new(WKind::Passwd, mk)));
            }
            Act::Recv { path } => self.do_recv(&path),
            Act::SendFile { id, path } => self.do_send_file(&id, &path),
        }
    }

    fn run_commit(&mut self, mut w: Wizard) {
        let dir = self.vault.dir.clone();
        let result: Result<(), String> = (|| match w.kind {
            WKind::Setup => {
                let (totp, rk) = (w.totp.as_ref().ok_or("internal")?, w.rk.as_ref().ok_or("internal")?);
                let mk = self.vault.create(w.pw1.as_bytes(), totp, rk)?;
                let mut store = Store::create(&dir)?;
                store.log(ev::SETUP, 0).map_err(|_| "audit log unavailable")?;
                store.st.last_step = w.totp_step;
                self.store = Some(store);
                self.open_session(mk)
            }
            WKind::Recover => {
                let mk = w.mk.take().ok_or("internal")?;
                let (totp, rk) = (w.totp.as_ref().ok_or("internal")?, w.rk.as_ref().ok_or("internal")?);
                self.vault.rewrite_header(&mk, w.pw1.as_bytes(), Some(rk), Some(totp))?;
                let mut store = match self.store.take() {
                    Some(s) => s,
                    None => Store::fresh(&dir)?,
                };
                store.register_success();
                store.st.last_step = w.totp_step;
                store.log(ev::RECOVERY, 0).map_err(|_| "audit log unavailable")?;
                self.store = Some(store);
                self.open_session(mk)
            }
            WKind::Passwd => {
                let mk = w.mk.take().ok_or("internal")?;
                self.vault.rewrite_header(&mk, w.pw1.as_bytes(), None, None)?;
                Ok(())
            }
        })();
        match result {
            Ok(()) => {
                w.pw1.clear();
                w.pw2.clear();
                match w.kind {
                    WKind::Passwd => {
                        self.audit(ev::PW_CHANGE, 0);
                        self.say(K::Ok, "password changed. The old password no longer works.");
                        self.mode = Mode::Shell;
                    }
                    _ => {
                        w.step = Step::ShowRk;
                        w.code.clear();
                        self.mode = Mode::Wizard(Box::new(w));
                    }
                }
            }
            Err(e) => {
                if w.kind == WKind::Passwd {
                    self.say(K::Err, format!("password change failed: {e}"));
                    self.mode = Mode::Shell;
                } else {
                    let mut nw = Wizard::new(w.kind, None);
                    nw.err = Some(e);
                    self.mode = Mode::Wizard(Box::new(nw));
                }
            }
        }
    }

    // ------------------------------------------------------------ keys

    fn on_key(&mut self, k: KeyEvent) {
        if k.kind != KeyEventKind::Press {
            return;
        }
        self.last_input = Instant::now();
        if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        let m = mem::replace(&mut self.mode, Mode::Wait);
        self.mode = match m {
            Mode::Login(l) => self.key_login(l, k),
            Mode::Wizard(w) => self.key_wizard(*w, k),
            Mode::Shell => self.key_shell(k),
            Mode::Compose(t) => self.key_compose(t, k),
            Mode::Reauth(r) => self.key_reauth(r, k),
            Mode::View(v) => self.key_view(v, k),
            Mode::FileView(v) => self.key_file_view(v, k),
            Mode::Wait => Mode::Wait,
        };
    }

    fn key_file_view(&mut self, mut v: Box<FileView>, k: KeyEvent) -> Mode {
        match k.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => {
                drop(v); // zeroizes the decrypted file
                crate::harden::reset_working_set();
                self.say(K::Dim, "file closed and wiped from memory");
                Mode::Shell
            }
            code => {
                v.key(code, self.body_h.get().saturating_sub(4));
                Mode::FileView(v)
            }
        }
    }

    fn key_login(&mut self, mut l: Login, k: KeyEvent) -> Mode {
        match k.code {
            KeyCode::Esc => self.quit = true,
            KeyCode::F(2) => {
                if self.vault.exists() {
                    return Mode::Wizard(Box::new(Wizard::new(WKind::Recover, None)));
                }
            }
            KeyCode::Tab | KeyCode::Up | KeyCode::Down => l.field ^= 1,
            KeyCode::Enter => {
                if l.field == 0 {
                    l.field = 1;
                } else if l.pw.is_empty() || l.code.len() != 6 {
                    l.note = Some((K::Err, "enter your password and the 6-digit code".into()));
                } else {
                    let now = unix_now();
                    if let Some(r) = self.store.as_ref().and_then(|s| s.locked_remaining(now)) {
                        l.note = Some((K::Err, format!("locked: try again in {r} s")));
                        l.pw.clear();
                        l.code.clear();
                        l.field = 0;
                    } else {
                        let pw = mem::replace(&mut l.pw, SecretInput::new(256));
                        let code = mem::take(&mut l.code);
                        self.job = Some(Job::Login { pw, code });
                        self.busy = Some("verifying (deriving keys, this takes a moment)");
                        l.field = 0;
                        l.note = None;
                    }
                }
            }
            KeyCode::Backspace => {
                if l.field == 0 {
                    l.pw.pop();
                } else {
                    l.code.pop();
                }
            }
            KeyCode::Char(c) => {
                if l.field == 0 {
                    l.pw.push(c);
                } else if c.is_ascii_digit() && l.code.len() < 6 {
                    l.code.push(c);
                }
            }
            _ => {}
        }
        Mode::Login(l)
    }

    fn key_wizard(&mut self, mut w: Wizard, k: KeyEvent) -> Mode {
        match (w.step, k.code) {
            (Step::ShowRk, KeyCode::Enter) => {
                if w.code.trim().eq_ignore_ascii_case("saved") {
                    return Mode::Shell;
                }
                w.err = Some("type SAVED once you have stored the recovery key".into());
                w.code.clear();
            }
            (Step::ShowRk, KeyCode::Backspace) => {
                w.code.pop();
            }
            (Step::ShowRk, KeyCode::Char(c)) if w.code.len() < 8 => w.code.push(c),
            (_, KeyCode::Esc) => {
                return match w.kind {
                    WKind::Setup => {
                        self.quit = true;
                        Mode::Wizard(Box::new(w))
                    }
                    WKind::Recover => Mode::Login(Login::new(None)),
                    WKind::Passwd => Mode::Shell,
                };
            }
            (Step::Rk, KeyCode::Enter) => {
                let text: String = w.rk_in.as_str().chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_uppercase();
                let rk = BASE32_NOPAD.decode(text.as_bytes()).ok().filter(|b| b.len() == 32).map(|b| Secret32::from_slice(&b));
                w.rk_in.clear();
                match rk.and_then(|rk| self.vault.unlock_recovery(&rk)) {
                    Some(mk) => {
                        w.mk = Some(mk);
                        w.step = Step::Pw;
                        w.err = None;
                    }
                    None => {
                        self.audit(ev::RECOV_FAIL, 0);
                        w.err = Some("that recovery key does not match this vault".into());
                    }
                }
            }
            (Step::Rk, KeyCode::Backspace) => w.rk_in.pop(),
            (Step::Rk, KeyCode::Char(c)) => {
                w.rk_in.push(c);
            }
            (Step::Pw, KeyCode::Tab | KeyCode::Up | KeyCode::Down) => w.field ^= 1,
            (Step::Pw, KeyCode::Backspace) => {
                if w.field == 0 { w.pw1.pop() } else { w.pw2.pop() }
            }
            (Step::Pw, KeyCode::Char(c)) => {
                if w.field == 0 { w.pw1.push(c) } else { w.pw2.push(c) };
            }
            (Step::Pw, KeyCode::Enter) => {
                if w.field == 0 {
                    w.field = 1;
                } else {
                    return self.wizard_password_done(w);
                }
            }
            (Step::Totp, KeyCode::Backspace) => {
                w.code.pop();
            }
            (Step::Totp, KeyCode::Char(c)) if c.is_ascii_digit() && w.code.len() < 6 => w.code.push(c),
            (Step::Totp, KeyCode::Enter) => {
                let secret = w.totp.as_ref().map(|t| t.to_vec());
                let hit = secret.and_then(|s| crypto::totp_verify(&s, unix_now(), &w.code, 0));
                match hit {
                    Some(step) => {
                        w.totp_step = step;
                        w.err = None;
                        self.busy = Some("creating vault (deriving keys, this takes a moment)");
                        self.job = Some(Job::Commit(Box::new(w)));
                        return Mode::Wait;
                    }
                    None => {
                        w.err = Some("code did not match; check the account was added and your clock is right".into());
                        w.code.clear();
                    }
                }
            }
            _ => {}
        }
        Mode::Wizard(Box::new(w))
    }

    fn wizard_password_done(&mut self, mut w: Wizard) -> Mode {
        let distinct = {
            let mut cs: Vec<char> = w.pw1.as_str().chars().collect();
            cs.sort_unstable();
            cs.dedup();
            cs.len()
        };
        if w.pw1.chars() < MIN_PW_CHARS || distinct < 6 {
            w.err = Some(format!("use at least {MIN_PW_CHARS} characters with some variety (a long passphrase is best)"));
            w.pw1.clear();
            w.pw2.clear();
            w.field = 0;
            return Mode::Wizard(Box::new(w));
        }
        if !crypto::ct_eq(w.pw1.as_bytes(), w.pw2.as_bytes()) {
            w.err = Some("the two entries do not match".into());
            w.pw1.clear();
            w.pw2.clear();
            w.field = 0;
            return Mode::Wizard(Box::new(w));
        }
        w.err = None;
        if w.kind == WKind::Passwd {
            self.busy = Some("re-keying vault (deriving keys, this takes a moment)");
            self.job = Some(Job::Commit(Box::new(w)));
            return Mode::Wait;
        }
        let mut t = Zeroizing::new(vec![0u8; 20]);
        crypto::random_bytes(&mut t);
        let b32 = BASE32_NOPAD.encode(&t);
        let uri = Zeroizing::new(format!(
            "otpauth://totp/Scytale:admin?secret={b32}&issuer=Scytale&algorithm=SHA1&digits=6&period=30"
        ));
        let code = qrcode::QrCode::new(uri.as_bytes()).ok();
        // Text version (reserves the space, and is what non-window renderers show)...
        w.qr = Zeroizing::new(
            code.as_ref()
                .map(|c| {
                    c.render::<qrcode::render::unicode::Dense1x2>()
                        .dark_color(qrcode::render::unicode::Dense1x2::Light)
                        .light_color(qrcode::render::unicode::Dense1x2::Dark)
                        .quiet_zone(true)
                        .build()
                })
                .unwrap_or_default(),
        );
        // ...and a pixel version drawn over it in the window, so phones can scan it reliably.
        w.qr_px = code.as_ref().map(|c| Rc::new(qr_pixels(c)));
        w.secret_txt = Zeroizing::new(b32);
        w.totp = Some(t);
        w.rk = Some(Secret32::random());
        w.step = Step::Totp;
        w.code.clear();
        Mode::Wizard(Box::new(w))
    }

    fn key_reauth(&mut self, mut r: Reauth, k: KeyEvent) -> Mode {
        match k.code {
            KeyCode::Esc => return Mode::Shell,
            KeyCode::Enter => {
                if !r.pw.is_empty() {
                    let pw = mem::replace(&mut r.pw, SecretInput::new(256));
                    self.job = Some(Job::Reauth { pw, act: r.act.clone() });
                    self.busy = Some("verifying");
                    return Mode::Wait;
                }
            }
            KeyCode::Backspace => r.pw.pop(),
            KeyCode::Char(c) => {
                r.pw.push(c);
            }
            _ => {}
        }
        Mode::Reauth(r)
    }

    fn key_compose(&mut self, mut t: SecretInput, k: KeyEvent) -> Mode {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        match k.code {
            KeyCode::Esc => {
                self.courier_target = None;
                self.say(K::Dim, "message discarded");
                return Mode::Shell;
            }
            KeyCode::Char('d') if ctrl && self.courier_target.is_some() => {
                let (burn, path) = self.courier_target.take().unwrap();
                self.courier_seal(t.as_bytes(), burn, &path);
                return Mode::Shell;
            }
            KeyCode::Char('d') if ctrl => {
                let res = match self.sess.as_mut() {
                    Some(s) => self.vault.add_message(s, t.as_bytes()),
                    None => Err("no session".into()),
                };
                match res {
                    Ok(item) => {
                        self.audit(ev::MSG_ENC, 0);
                        self.say(K::Ok, format!("message sealed as {}. 'read {}' opens it once; it then self-destructs.", item.short(), item.short()));
                    }
                    Err(e) => self.say(K::Err, format!("could not store message: {e}")),
                }
                return Mode::Shell;
            }
            KeyCode::Enter => {
                t.push('\n');
            }
            KeyCode::Backspace => t.pop(),
            KeyCode::Char(c) if !ctrl => {
                t.push(c);
            }
            _ => {}
        }
        Mode::Compose(t)
    }

    fn key_view(&mut self, v: View, k: KeyEvent) -> Mode {
        match k.code {
            KeyCode::Esc | KeyCode::Char('k') | KeyCode::Char('K') | KeyCode::Char('q') | KeyCode::Char('Q') => {
                drop(v);
                self.audit(ev::MSG_KILL, 0);
                self.say(K::Warn, "message terminated and wiped");
                Mode::Shell
            }
            _ => Mode::View(v),
        }
    }

    // ------------------------------------------------------------ shell

    fn key_shell(&mut self, k: KeyEvent) -> Mode {
        match k.code {
            KeyCode::Enter => {
                let line = mem::take(&mut self.cmd);
                self.say(K::Dim, format!("scytale> {line}"));
                return self.run_cmd(&line);
            }
            KeyCode::Esc => self.cmd.clear(),
            KeyCode::Backspace => {
                self.cmd.pop();
            }
            KeyCode::Char('l') if k.modifiers.contains(KeyModifiers::CONTROL) => self.out.clear(),
            KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => {
                if self.cmd.len() < 1024 {
                    self.cmd.push(c);
                }
            }
            _ => {}
        }
        Mode::Shell
    }

    fn run_cmd(&mut self, line: &str) -> Mode {
        let t = tokens(line);
        let Some(cmd) = t.first().map(|s| s.to_ascii_lowercase()) else {
            return Mode::Shell;
        };
        let arg = |i: usize| t.get(i).cloned();
        match cmd.as_str() {
            "help" | "?" => self.help(),
            "ls" | "list" => self.cmd_ls(),
            "clear" | "cls" => self.out.clear(),
            "enc" | "encrypt" => match path_arg(line) {
                Some(p) => {
                    self.busy = Some("encrypting, verifying, erasing original");
                    self.job = Some(Job::Enc(p));
                    return Mode::Wait;
                }
                None => self.say(K::Err, "usage: enc <path-to-file>"),
            },
            "dec" | "decrypt" | "view" => match arg(1) {
                Some(id) => match self.sess.as_ref().map(|s| s.find(&id).map(|i| (i.kind, i.size))) {
                    Some(Ok((Kind::File, size))) if size > VIEW_CAP => self.say(
                        K::Err,
                        format!("too large to view in memory (limit {})", fmt_size(VIEW_CAP)),
                    ),
                    Some(Ok((Kind::File, _))) => {
                        return Mode::Reauth(Reauth { pw: SecretInput::new(256), act: Act::View { id }, note: None })
                    }
                    Some(Ok((Kind::Msg, _))) => self.say(K::Err, "that is a message; use 'read'"),
                    Some(Err(e)) => self.say(K::Err, e),
                    None => {}
                },
                None => self.say(K::Err, "usage: dec <id>"),
            },
            "msg" | "message" => {
                self.say(K::Dim, "composing; Ctrl+D seals, Esc discards");
                return Mode::Compose(SecretInput::new(MSG_CAP));
            }
            "read" | "open" => match arg(1) {
                Some(id) => match self.sess.as_ref().map(|s| s.find(&id).map(|i| i.kind)) {
                    Some(Ok(Kind::Msg)) => {
                        return Mode::Reauth(Reauth { pw: SecretInput::new(256), act: Act::Read { id }, note: None })
                    }
                    Some(Ok(Kind::File)) => self.say(K::Err, "that is a file; use 'dec'"),
                    Some(Err(e)) => self.say(K::Err, e),
                    None => {}
                },
                None => self.say(K::Err, "usage: read <id>"),
            },
            "pair" => self.cmd_pair(line, &t),
            "send" => match t.get(1).map(|s| s.to_ascii_lowercase()) {
                Some(b) if b == "yes" || b == "no" => {
                    let rest = line.trim_start()[4..].trim_start()[b.len()..].trim().trim_matches('"').to_string();
                    // "text" = raw encrypted text to the clipboard (empty path); no path = a file on
                    // the Desktop; otherwise the file or folder given.
                    let (path, dest) = if rest.eq_ignore_ascii_case("text") {
                        (String::new(), "the clipboard as encrypted text".to_string())
                    } else if rest.is_empty() {
                        let d = Self::default_outbox();
                        let shown = d.display().to_string();
                        (shown.clone(), format!("a file in {shown}"))
                    } else {
                        (rest.clone(), format!("a file at {rest}"))
                    };
                    match self.courier_state().map(|c| c.peer.as_ref().map(|p| (p.verified, c.peer_prekeys_left()))) {
                        Ok(Some((true, n))) if n > 0 => {
                            self.courier_target = Some((b == "yes", path));
                            self.say(K::Dim, format!(
                                "courier message; destroy when received: {}; output: {dest}. Ctrl+D seals, Esc discards",
                                if b == "yes" { "YES" } else { "no" }
                            ));
                            return Mode::Compose(SecretInput::new(crate::courier::TEXT_CAP));
                        }
                        Ok(Some((true, _))) => self.say(K::Err, "no one-time keys left from the other device. import a new key bundle from it."),
                        Ok(Some((false, _))) => self.say(K::Err, "pairing not verified. compare safety numbers ('pair'), then 'pair verify MATCH'."),
                        Ok(None) => self.say(K::Err, "no device paired. see 'pair'."),
                        Err(e) => self.say(K::Err, e),
                    }
                }
                _ => self.say(K::Err, "usage: send <yes|no> [path | text]   (yes = destroy when received; no path = file on the Desktop; text = encrypted text to the clipboard)"),
            },
            "sendfile" => {
                let Some(id) = arg(1) else {
                    self.say(K::Err, "usage: sendfile <id> [path]   (a vault file, not a photo; no path = file on the Desktop)");
                    return Mode::Shell;
                };
                // everything after the id is the output path (may contain spaces; quotes optional)
                let mut it = line.trim_start().splitn(2, char::is_whitespace);
                it.next();
                let after = it.next().unwrap_or("").trim_start();
                let path = after[after.find(char::is_whitespace).unwrap_or(after.len())..].trim().trim_matches('"').to_string();
                let check = match self.sess.as_ref().map(|s| s.find(&id).cloned()) {
                    Some(Ok(item)) if item.kind == Kind::Msg => Err("that is a message; only files can be sent with sendfile".to_string()),
                    Some(Ok(item)) if crate::courier::is_image(&item.name, &[]) => {
                        Err(Self::courier_error(crate::courier::Error::Photo).to_string())
                    }
                    Some(Ok(item)) if item.size == 0 || item.size > crate::courier::FILE_CAP as u64 => {
                        Err(Self::courier_error(crate::courier::Error::FileTooLarge).to_string())
                    }
                    Some(Ok(_)) => Ok(()),
                    Some(Err(e)) => Err(e),
                    None => return Mode::Shell,
                };
                if let Err(e) = check {
                    self.say(K::Err, e);
                    return Mode::Shell;
                }
                match self.courier_state().map(|c| c.peer.as_ref().map(|p| (p.verified, c.peer_prekeys_left()))) {
                    Ok(Some((true, n))) if n > 0 => {
                        return Mode::Reauth(Reauth { pw: SecretInput::new(256), act: Act::SendFile { id, path }, note: None })
                    }
                    Ok(Some((true, _))) => self.say(K::Err, "no one-time keys left from the other device. import a new key bundle from it."),
                    Ok(Some((false, _))) => self.say(K::Err, "pairing not verified. compare safety numbers ('pair'), then 'pair verify MATCH'."),
                    Ok(None) => self.say(K::Err, "no device paired. see 'pair'."),
                    Err(e) => self.say(K::Err, e),
                }
            }
            "recv" | "receive" => {
                // No path: open an encrypted text block copied from an email (read from the clipboard).
                let path = path_arg(line).unwrap_or_default();
                return Mode::Reauth(Reauth { pw: SecretInput::new(256), act: Act::Recv { path }, note: None });
            }
            "purge" | "rm" | "del" => self.cmd_purge(&t),
            "audit" => self.cmd_audit(arg(1).and_then(|n| n.parse().ok()).unwrap_or(25)),
            "passwd" | "password" => return Mode::Reauth(Reauth { pw: SecretInput::new(256), act: Act::Passwd, note: None }),
            "lock" => {
                self.lock_session(ev::LOGOUT, "locked");
                return mem::replace(&mut self.mode, Mode::Wait);
            }
            "exit" | "quit" => self.quit = true,
            "wipe" => {
                if t.get(1).map(String::as_str) == Some("DESTROY") {
                    self.panic_wipe();
                    return Mode::Wait;
                }
                self.say(K::Err, "PANIC WIPE destroys the entire vault: every file, message, key and the audit log.");
                self.say(K::Err, "There is no undo and no recovery, not even with the recovery key.");
                self.say(K::Warn, "to proceed type exactly:  wipe DESTROY");
            }
            _ => self.say(K::Err, format!("unknown command '{cmd}'. type 'help'.")),
        }
        Mode::Shell
    }

    fn panic_wipe(&mut self) {
        // No more writes of any kind: drop the session and the audit store first.
        self.courier = None;
        self.courier_target = None;
        self.sess = None;
        self.sess_start = None;
        self.store = None;
        self.out.clear();
        let failed = self.vault.destroy_all();
        self.exit_note = Some(if failed == 0 {
            "Scytale: vault destroyed. Nothing remains in %LOCALAPPDATA%\\Scytale.".to_string()
        } else {
            format!(
                "Scytale: vault keys destroyed, so the data cannot be decrypted, but {failed} file(s) could not be \
                 erased. Delete %LOCALAPPDATA%\\Scytale yourself."
            )
        });
        self.quit = true;
    }

    fn help(&mut self) {
        for (k, s) in [
            (K::Head, "commands"),
            (K::N, "  ls                         list vault contents"),
            (K::N, "  enc <file>                 encrypt a file into the vault, then erase the original"),
            (K::N, "  dec <id>                   view a file inside Scytale, decrypted in memory only (asks for password)"),
            (K::N, "  msg                        write a self-destructing message"),
            (K::N, "  read <id>                  open a message once (asks for password); wiped after 5 min"),
            (K::N, "  purge <id> yes             permanently destroy a file or an unread message"),
            (K::N, "  audit [n]                  show the last n audit entries (default 25)"),
            (K::N, "  passwd                     change the admin password"),
            (K::N, "  pair                       courier pairing status and safety number"),
            (K::N, "  pair export <path>         write this PC's signed key bundle (public keys) to a file"),
            (K::N, "  pair import <path>         import the other device's key bundle"),
            (K::N, "  pair verify MATCH          after comparing safety numbers on both screens"),
            (K::N, "  send <yes|no> [path|text]  seal a courier message (yes = destroy when received);"),
            (K::N, "                             no path: file on the Desktop; text: encrypted text to the clipboard"),
            (K::N, "  sendfile <id> [path]       seal a vault file (not a photo) for the paired device (asks for password);"),
            (K::N, "                             up to 12 MiB; no path: file on the Desktop"),
            (K::N, "  recv [path]                open a courier message or file (asks for password);"),
            (K::N, "                             no path: an encrypted message copied from an email; files go into the vault"),
            (K::N, "  lock | exit                lock the vault | lock and quit"),
            (K::Err, "  wipe DESTROY               PANIC WIPE: destroy the entire vault immediately, no undo"),
            (K::Dim, "ids are the 6-character codes shown by 'ls'; 4 characters are enough if unique."),
            (K::Dim, "Scytale wipes memory and exits after 5 minutes idle, or when Windows locks or sleeps."),
        ] {
            self.say(k, s);
        }
    }

    fn cmd_ls(&mut self) {
        let Some(s) = self.sess.as_ref() else { return };
        let mut rows: Vec<(K, String)> = Vec::new();
        for i in &s.items {
            let (ty, name) = match i.kind {
                Kind::File => ("file", i.name.clone()),
                Kind::Msg => ("msg ", "-".to_string()),
            };
            rows.push((K::N, format!("{:<7} {} {:>10}  {}  {}", i.short(), ty, fmt_size(i.size), &fmt_utc(i.created)[..16], name)));
        }
        if rows.is_empty() {
            self.say(K::Dim, "vault is empty");
            return;
        }
        self.say(K::Head, format!("{:<7} {} {:>10}  {:<16}  {}", "ID", "TYPE", "SIZE", "CREATED (UTC)", "NAME"));
        for (k, r) in rows {
            self.say(k, r);
        }
    }

    fn cmd_enc(&mut self, path: &str) {
        let Some(s) = self.sess.as_mut() else { return };
        match self.vault.add_file(s, Path::new(path)) {
            Ok((item, warn)) => {
                self.audit(ev::FILE_ENC, 0);
                self.say(K::Ok, format!("encrypted as {} and verified. The vault now holds the only copy.", item.short()));
                match warn {
                    None => self.say(K::Ok, "original overwritten and deleted"),
                    Some(w) => self.say(K::Warn, w),
                }
                self.say(K::Dim, "note: on SSDs and synced folders old bytes can survive; BitLocker is the real guarantee.");
            }
            Err(e) if e == crate::util::ioe(std::io::ErrorKind::NotFound.into()) => {
                self.say(K::Err, format!("encrypt failed: no file at {path}"));
                self.say(K::Dim, "use the full path including the extension (.jpg vs .jpeg). Explorer: Shift+right-click > Copy as path, then Ctrl+V");
            }
            Err(e) => self.say(K::Err, format!("encrypt failed: {e}")),
        }
    }

    fn do_view(&mut self, id: &str) {
        let Some(s) = self.sess.as_ref() else { return };
        let item = match s.find(id) {
            Ok(i) => i.clone(),
            Err(e) => return self.say(K::Err, e),
        };
        match self.vault.open_file(s, &item) {
            Ok(data) => {
                self.audit(ev::FILE_DEC, 0);
                self.mode = Mode::FileView(Box::new(FileView::new(item.short(), &item.name, data)));
            }
            Err(e) => {
                crate::harden::reset_working_set();
                self.say(K::Err, format!("could not open file: {e}"));
            }
        }
    }

    fn do_read(&mut self, id: &str) {
        let Some(s) = self.sess.as_mut() else { return };
        let item = match s.find(id) {
            Ok(i) => i.clone(),
            Err(e) => return self.say(K::Err, e),
        };
        match self.vault.open_and_destroy_message(s, &item.id) {
            Ok(text) => {
                self.audit(ev::MSG_DEC, 0);
                self.mode = Mode::View(View {
                    short: item.short(),
                    text,
                    until: Instant::now() + Duration::from_secs(MSG_VIEW_SECS),
                });
            }
            Err(e) => self.say(K::Err, format!("could not open message: {e}")),
        }
    }

    // ------------------------------------------------------------ courier

    fn courier_path(&self) -> PathBuf {
        self.vault.dir.join("courier.scy")
    }

    fn courier_key(&self) -> Option<Secret32> {
        self.sess.as_ref().map(|s| crypto::hkdf(s.mk.as_bytes(), b"scytale/v1", b"courier"))
    }

    /// The sealed courier state, loaded on first use (or empty). The vault must be open.
    fn courier_state(&mut self) -> Result<&mut crate::courier::State, String> {
        if self.courier.is_none() {
            let key = self.courier_key().ok_or("vault is locked")?;
            let state = match std::fs::read(self.courier_path()) {
                Ok(raw) => {
                    let pt = crypto::open(key.as_bytes(), b"scytale/courier-state", &raw)
                        .ok_or("courier state failed authentication (corrupt or modified)")?;
                    crate::courier::State::from_bytes(&pt).map_err(|_| "courier state is corrupt".to_string())?
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => crate::courier::State::default(),
                Err(e) => return Err(crate::util::ioe(e)),
            };
            self.courier = Some(state);
        }
        Ok(self.courier.as_mut().unwrap())
    }

    fn courier_save(&mut self) -> Result<(), String> {
        let key = self.courier_key().ok_or("vault is locked")?;
        let bytes = self.courier.as_ref().ok_or("courier not loaded")?.to_bytes();
        let sealed = crypto::seal(key.as_bytes(), b"scytale/courier-state", &bytes);
        crate::util::write_atomic(&self.courier_path(), &sealed)
    }

    fn courier_error(e: crate::courier::Error) -> &'static str {
        use crate::courier::Error as E;
        match e {
            E::Malformed => "not a Scytale courier file",
            E::BadSignature => "signature invalid: forged or altered. rejected",
            E::UnknownSender => "not from the paired device, or not addressed to this one. rejected",
            E::NotVerified => "pairing not verified: compare safety numbers, then 'pair verify MATCH'",
            E::NotPaired => "no device paired",
            E::AlreadyOpened => "already opened: its one-time key is destroyed, no copy can ever be read",
            E::Decrypt => "decryption failed: altered or corrupt. rejected",
            E::NoPrekeys => "no one-time keys left: import a new key bundle from the other device",
            E::TooLong => "message empty or over 16 KiB",
            E::DifferentPeer => "another device is already paired: 'pair unpair yes' first",
            E::OwnBundle => "that is this PC's own key bundle",
            E::Photo => "photos and other images cannot be sent by courier. rejected",
            E::FileTooLarge => "file empty or over 12 MiB",
        }
    }

    /// Where `send` writes when no path is given: the Desktop (or the user folder if there is none).
    fn default_outbox() -> PathBuf {
        let home = std::env::var_os("USERPROFILE").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
        let desktop = home.join("Desktop");
        if desktop.is_dir() {
            desktop
        } else {
            home
        }
    }

    /// Resolve an output path: an existing folder gets a generated file name. Never overwrites.
    fn courier_out_path(path: &str, default_name: &str) -> PathBuf {
        let p = PathBuf::from(path);
        if p.is_dir() {
            p.join(default_name)
        } else {
            p
        }
    }

    fn courier_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| if e.kind() == std::io::ErrorKind::AlreadyExists { "that file already exists".to_string() } else { crate::util::ioe(e) })?;
        f.write_all(bytes).map_err(crate::util::ioe)?;
        f.sync_all().map_err(crate::util::ioe)
    }

    fn cmd_pair(&mut self, line: &str, t: &[String]) {
        let sub = t.get(1).map(|s| s.to_ascii_lowercase());
        let rest = || {
            let l = line.trim_start();
            let after = l[4..].trim_start();
            after[sub.as_deref().unwrap_or("").len()..].trim().trim_matches('"').to_string()
        };
        match sub.as_deref() {
            None | Some("status") => match self.courier_state() {
                Ok(c) => {
                    let (paired, verified, left, own) =
                        (c.peer.is_some(), c.peer.as_ref().is_some_and(|p| p.verified), c.peer_prekeys_left(), c.own_prekeys_unused());
                    let number = c.safety_number();
                    if !paired {
                        self.say(K::Dim, "no device paired. 'pair export <path>' then email it; 'pair import <path>' for theirs.");
                        return;
                    }
                    self.say(if verified { K::Ok } else { K::Warn }, format!(
                        "paired, {}. {left} one-time key(s) left to send, {own} issued.",
                        if verified { "verified" } else { "NOT verified" }
                    ));
                    if let Some(n) = number {
                        self.say(K::Head, format!("safety number:  {n}"));
                        if !verified {
                            self.say(K::Warn, "compare it with the other device. if identical: pair verify MATCH. if not: a key was swapped, do not verify.");
                        }
                    }
                }
                Err(e) => self.say(K::Err, e),
            },
            Some("export") => {
                let path = rest();
                if path.is_empty() {
                    return self.say(K::Err, "usage: pair export <path or folder>");
                }
                let text = match self.courier_state() {
                    Ok(c) => c.export_bundle(unix_now()),
                    Err(e) => return self.say(K::Err, e),
                };
                if let Err(e) = self.courier_save() {
                    return self.say(K::Err, format!("could not save courier state: {e}"));
                }
                let out = Self::courier_out_path(&path, &format!("Scytale PC key bundle {}.scykey", fmt_utc(unix_now()).replace(':', ".")));
                match Self::courier_write(&out, text.as_bytes()) {
                    Ok(()) => {
                        self.audit(ev::COURIER_BUNDLE, 0);
                        self.say(K::Ok, format!("key bundle written: {}", out.display()));
                        self.say(K::Dim, "public keys only. email it to the other device and import it there.");
                    }
                    Err(e) => self.say(K::Err, format!("could not write: {e}")),
                }
            }
            Some("import") => {
                let path = rest();
                let data = match std::fs::read(&path) {
                    Ok(d) if d.len() <= 4 << 20 => d,
                    Ok(_) => return self.say(K::Err, "file too large to be a key bundle"),
                    Err(e) => return self.say(K::Err, format!("could not read {path}: {}", crate::util::ioe(e))),
                };
                let r = match self.courier_state() {
                    Ok(c) => c.import_bundle(&data),
                    Err(e) => return self.say(K::Err, e),
                };
                match r {
                    Ok(number) => {
                        if let Err(e) = self.courier_save() {
                            return self.say(K::Err, format!("could not save courier state: {e}"));
                        }
                        self.audit(ev::COURIER_PAIR, 0);
                        self.say(K::Ok, "key bundle accepted.");
                        self.say(K::Head, format!("safety number:  {number}"));
                        self.say(K::Warn, "if not yet verified: compare with the other device, then: pair verify MATCH");
                    }
                    Err(e) => {
                        self.audit(ev::COURIER_REJECT, e as u64);
                        self.say(K::Err, Self::courier_error(e));
                    }
                }
            }
            Some("verify") => {
                if t.get(2).map(String::as_str) != Some("MATCH") {
                    return self.say(K::Warn, "compare safety numbers first ('pair'), then type exactly:  pair verify MATCH");
                }
                let ok = self.courier_state().map(|c| c.verify_peer()).unwrap_or(false);
                if ok && self.courier_save().is_ok() {
                    self.audit(ev::COURIER_VERIFY, 0);
                    self.say(K::Ok, "pairing verified.");
                } else {
                    self.say(K::Err, "no device paired.");
                }
            }
            Some("unpair") => {
                if t.get(2).map(|s| s.to_ascii_lowercase()).as_deref() != Some("yes") {
                    return self.say(K::Warn, "messages in transit become unreadable. repeat as:  pair unpair yes");
                }
                if self.courier_state().map(|c| c.unpair()).is_ok() && self.courier_save().is_ok() {
                    self.audit(ev::COURIER_UNPAIR, 0);
                    self.say(K::Ok, "unpaired.");
                }
            }
            _ => self.say(K::Err, "usage: pair | pair export <path> | pair import <path> | pair verify MATCH | pair unpair yes"),
        }
    }

    /// Seal a courier message and write it. The used one-time key is saved before the file exists.
    fn courier_seal(&mut self, text: &[u8], burn: bool, path: &str) {
        let env = match self.courier_state() {
            Ok(c) => c.seal(text, burn, unix_now()),
            Err(e) => return self.say(K::Err, e),
        };
        let env = match env {
            Ok(e) => e,
            Err(e) => return self.say(K::Err, format!("not sealed: {}", Self::courier_error(e))),
        };
        if let Err(e) = self.courier_save() {
            return self.say(K::Err, format!("not sealed: could not save courier state: {e}"));
        }
        if path.is_empty() {
            // Raw encrypted message: the armored text goes to the clipboard (ciphertext only).
            let text = crate::courier::armor_message(&env);
            if gui::write_clipboard(&text) {
                self.audit(ev::COURIER_SEND, u64::from(burn));
                self.say(K::Ok, format!("sealed{} and copied to the clipboard as encrypted text.", if burn { " (destroy when received)" } else { "" }));
                self.say(K::Dim, "paste it into the body of an email. only the paired device can open it.");
            } else {
                self.say(K::Err, "sealed, but the clipboard was unavailable; that one-time key is spent, seal again");
            }
            return;
        }
        let out = Self::courier_out_path(path, &format!("Scytale message {}.scy", fmt_utc(unix_now()).replace(':', ".")));
        let armored = out.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("txt"));
        let bytes = if armored { crate::courier::armor_message(&env).into_bytes() } else { env };
        match Self::courier_write(&out, &bytes) {
            Ok(()) => {
                self.audit(ev::COURIER_SEND, u64::from(burn));
                self.say(K::Ok, format!("sealed{}: {}", if burn { " (destroy when received)" } else { "" }, out.display()));
                self.say(K::Dim, if armored { "attach it or paste its text into an email." } else { "attach it to an email." });
            }
            Err(e) => self.say(K::Err, format!("sealed but could not write the file ({e}); that one-time key is spent, seal again")),
        }
    }

    /// Seal a vault file for the paired device (after password re-entry) and write the .scy file.
    /// The plaintext exists only in locked memory and is wiped as soon as it is sealed; the used
    /// one-time key is saved before the file exists.
    fn do_send_file(&mut self, id: &str, path: &str) {
        let Some(s) = self.sess.as_ref() else { return };
        let item = match s.find(id) {
            Ok(i) if i.kind == Kind::File => i.clone(),
            Ok(_) => return self.say(K::Err, "that is a message; only files can be sent with sendfile"),
            Err(e) => return self.say(K::Err, e),
        };
        let plain = match self.vault.open_file(s, &item) {
            Ok(d) => d,
            Err(e) => {
                crate::harden::reset_working_set();
                return self.say(K::Err, format!("could not open file: {e}"));
            }
        };
        self.audit(ev::FILE_DEC, 0);
        let sealed = match self.courier_state() {
            Ok(c) => c.seal_file(&item.name, plain.as_bytes(), unix_now()),
            Err(e) => {
                drop(plain);
                crate::harden::reset_working_set();
                return self.say(K::Err, e);
            }
        };
        drop(plain); // wiped
        crate::harden::reset_working_set();
        let env = match sealed {
            Ok(e) => e,
            Err(e) => return self.say(K::Err, format!("not sealed: {}", Self::courier_error(e))),
        };
        if let Err(e) = self.courier_save() {
            return self.say(K::Err, format!("not sealed: could not save courier state: {e}"));
        }
        let dir = if path.is_empty() { Self::default_outbox().display().to_string() } else { path.to_string() };
        let out = Self::courier_out_path(&dir, &format!("Scytale file {}.scy", fmt_utc(unix_now()).replace(':', ".")));
        match Self::courier_write(&out, &env) {
            Ok(()) => {
                self.audit(ev::COURIER_SEND_FILE, 0);
                self.say(K::Ok, format!("{} sealed: {}", item.short(), out.display()));
                self.say(K::Dim, "attach it to an email. only the paired device can open it; the file name is sealed inside.");
            }
            Err(e) => self.say(K::Err, format!("sealed but could not write the file ({e}); that one-time key is spent, send again")),
        }
    }

    /// Open a courier message (after password re-entry). Forward secrecy is saved before the
    /// text is shown; kept messages are also stored in the vault. Files go into the vault only.
    fn do_recv(&mut self, path: &str) {
        let data = if path.is_empty() {
            // Raw encrypted message: pasted at the prompt, or else still on the clipboard.
            if let Some(p) = self.courier_paste.take() {
                p.as_bytes().to_vec()
            } else {
                match gui::read_clipboard() {
                Some(t) if !t.trim().is_empty() => t.as_bytes().to_vec(),
                    _ => return self.say(K::Err, "no message. paste the encrypted block (Ctrl+V) or copy it, then recv; or give a file path."),
                }
            }
        } else {
            match std::fs::read(path) {
                Ok(d) if d.len() <= 17 << 20 => d,
                Ok(_) => return self.say(K::Err, "file too large to be a courier message"),
                Err(e) => return self.say(K::Err, format!("could not read {path}: {}", crate::util::ioe(e))),
            }
        };
        let got = match self.courier_state() {
            Ok(c) => c.open(&data),
            Err(e) => return self.say(K::Err, e),
        };
        let got = match got {
            Ok(g) => g,
            Err(e) => {
                self.audit(ev::COURIER_REJECT, e as u64);
                return self.say(K::Err, Self::courier_error(e));
            }
        };
        if let Err(e) = self.courier_save() {
            return self.say(K::Err, format!("not opened: could not save courier state: {e}"));
        }
        if let Some(name) = got.file_name.clone() {
            // a file is never shown here: it goes straight into the vault, encrypted
            let stored = match self.sess.as_mut() {
                Some(s) => self.vault.add_bytes(s, &name, &got.text).map(|i| i.short()),
                None => Err("vault is locked".into()),
            };
            drop(got);
            match stored {
                Ok(id) => {
                    self.audit(ev::FILE_ENC, 0);
                    self.audit(ev::COURIER_RECV_FILE, 0);
                    self.say(K::Ok, format!("file received: \"{name}\" encrypted into the vault as {id}. view it with: dec {id}"));
                }
                Err(e) => self.say(K::Err, format!("could not store the file: {e}. its one-time key is spent; ask for it again")),
            }
            return;
        }
        if !got.burn {
            let name = format!("Received message {}.txt", fmt_utc(got.created).replace(':', "."));
            let stored = match self.sess.as_mut() {
                Some(s) => self.vault.add_bytes(s, &name, &got.text).map(|i| i.short()),
                None => Err("vault is locked".into()),
            };
            match stored {
                Ok(id) => self.say(K::Ok, format!("message kept in the vault as {id}")),
                Err(e) => self.say(K::Err, format!("could not store the message: {e}")),
            }
        }
        let mut text = SecretInput::new(crate::courier::TEXT_CAP + 16);
        use std::io::Write as _;
        let _ = text.write_all(&got.text);
        self.audit(ev::COURIER_RECV, u64::from(got.burn));
        self.mode = Mode::View(View {
            short: if got.burn { "courier (destroyed on receipt)".into() } else { "courier".into() },
            text,
            until: Instant::now() + Duration::from_secs(MSG_VIEW_SECS),
        });
    }

    fn cmd_purge(&mut self, t: &[String]) {
        let Some(id) = t.get(1) else {
            return self.say(K::Err, "usage: purge <id> yes");
        };
        let Some(s) = self.sess.as_mut() else { return };
        let item = match s.find(id) {
            Ok(i) => i.clone(),
            Err(e) => return self.say(K::Err, e),
        };
        if t.get(2).map(|x| x.to_ascii_lowercase()).as_deref() != Some("yes") {
            return self.say(K::Warn, format!("this destroys {} permanently. repeat as: purge {} yes", item.short(), item.short()));
        }
        match self.vault.purge(s, &item.id) {
            Ok(()) => {
                self.audit(if item.kind == Kind::File { ev::FILE_PURGE } else { ev::MSG_PURGE }, 0);
                self.say(K::Ok, format!("{} destroyed", item.short()));
            }
            Err(e) => self.say(K::Err, format!("purge failed: {e}")),
        }
    }

    fn cmd_audit(&mut self, n: usize) {
        let Some(store) = self.store.as_ref() else { return };
        match store.read() {
            Ok((entries, chain)) => {
                let mut lines: Vec<(K, String)> = Vec::new();
                for e in entries.iter().rev().take(n.clamp(1, 200)).rev() {
                    let extra = match e.ev.as_str() {
                        ev::LOGOUT | ev::TIMEOUT | ev::WIN_LOCK | ev::SUSPEND | ev::SHUTDOWN => {
                            format!("  session {}", fmt_dur(e.extra))
                        }
                        ev::LOCKOUT => format!("  {} s", e.extra),
                        ev::COURIER_SEND | ev::COURIER_RECV if e.extra == 1 => "  destroy on receipt".to_string(),
                        ev::COURIER_REJECT => format!("  reason {}", e.extra),
                        _ => String::new(),
                    };
                    let k = match e.ev.as_str() {
                        ev::LOGIN_FAIL | ev::REAUTH_FAIL | ev::LOCKOUT | ev::RECOV_FAIL | ev::STATE_RESET => K::Warn,
                        _ => K::N,
                    };
                    lines.push((k, format!("{:>5}  {} UTC  {}{}", e.seq, fmt_utc(e.ts), e.ev, extra)));
                }
                let verdict = match chain {
                    Chain::Intact => (K::Ok, "log integrity: intact".to_string()),
                    Chain::Broken(n) => (K::Err, format!("log integrity: BROKEN at entry {n}")),
                    Chain::Truncated => (K::Err, "log integrity: TRUNCATED".to_string()),
                };
                for (k, l) in lines {
                    self.say(k, l);
                }
                self.say(verdict.0, verdict.1);
            }
            Err(e) => self.say(K::Err, format!("cannot read audit log: {e}")),
        }
    }
}

/// Everything after the command word, as one path: spaces need no quotes, and surrounding quotes
/// (Explorer's "Copy as path") are removed.
fn path_arg(line: &str) -> Option<String> {
    let rest = line.trim_start();
    let rest = rest[rest.find(char::is_whitespace)?..].trim();
    let rest = rest.strip_prefix('"').unwrap_or(rest);
    let rest = rest.strip_suffix('"').unwrap_or(rest).trim();
    (!rest.is_empty()).then(|| rest.to_string())
}

fn tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (mut cur, mut quoted, mut any) = (String::new(), false, false);
    for c in s.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any || !cur.is_empty() {
                    out.push(mem::take(&mut cur));
                    any = false;
                }
            }
            c => cur.push(c),
        }
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    out
}


// ---------------------------------------------------------------- drawing

/// QR code as an image: black modules on white with the standard 4-module quiet zone.
fn qr_pixels(code: &qrcode::QrCode) -> Pixels {
    let n = code.width() as u32;
    let q = 4u32;
    let s = n + 2 * q;
    let colors = code.to_colors();
    let mut rgba = vec![255u8; (s * s * 4) as usize];
    for y in 0..n {
        for x in 0..n {
            if colors[(y * n + x) as usize] == qrcode::Color::Dark {
                let i = (((y + q) * s + x + q) * 4) as usize;
                rgba[i..i + 3].fill(0);
            }
        }
    }
    Pixels::from_rgba(s, s, rgba)
}

pub(crate) fn wrap(s: &str, w: usize) -> Vec<String> {
    let w = w.max(8);
    let mut out = Vec::new();
    for raw in s.split('\n') {
        let mut line = String::new();
        let mut len = 0;
        for (i, word) in raw.split(' ').enumerate() {
            let wl = word.chars().count();
            if i > 0 {
                // the single space that preceded this word: a line break replaces it if the word
                // would not fit, otherwise it is kept (so indentation and runs of spaces survive)
                if len > 0 && wl > 0 && len + 1 + wl > w {
                    out.push(mem::take(&mut line));
                    len = 0;
                } else if len < w {
                    line.push(' ');
                    len += 1;
                } else {
                    out.push(mem::take(&mut line));
                    len = 0;
                }
            }
            for c in word.chars() {
                if len == w {
                    out.push(mem::take(&mut line));
                    len = 0;
                }
                line.push(c);
                len += 1;
            }
        }
        out.push(line);
    }
    out
}

fn mask(n: usize) -> String {
    "*".repeat(n.min(40))
}

fn field(label: &str, val: &str, active: bool) -> Line<'static> {
    let (mark, st) = if active { (">", style(K::Head)) } else { (" ", style(K::N)) };
    Line::from(vec![
        Span::styled(format!(" {mark} {label:<10}"), st),
        Span::styled(val.to_string(), style(K::Ok)),
        Span::styled(if active { "_" } else { "" }, style(K::Dim)),
    ])
}

fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    let rows = Layout::vertical([Constraint::Length(1), Constraint::Min(1), Constraint::Length(1)]).split(area);
    let w = area.width as usize;

    // title bar
    let label = app.label();
    let idle = IDLE_SECS.saturating_sub(app.last_input.elapsed().as_secs());
    let right = match (&app.sess, app.sess_start) {
        (Some(_), Some(st)) => format!("session {}  auto-exit {:02}:{:02}", fmt_dur(st.elapsed().as_secs()), idle / 60, idle % 60),
        _ => format!("locked  auto-exit {:02}:{:02}", idle / 60, idle % 60),
    };
    let left = format!(" SCYTALE | {label}");
    let pad = w.saturating_sub(left.chars().count() + right.chars().count() + 1);
    f.render_widget(
        Paragraph::new(format!("{left}{}{right} ", " ".repeat(pad)))
            .style(Style::new().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)),
        rows[0],
    );

    // body
    let (lines, cursor, overlays) = app.body(rows[1].width.saturating_sub(2) as usize, rows[1].height as usize);
    f.render_widget(Paragraph::new(lines), rows[1]);
    if let Some((c, r)) = cursor {
        f.set_cursor_position((rows[1].x + c, rows[1].y + r));
    }
    gui::set_overlays(
        overlays
            .into_iter()
            .map(|mut o| {
                o.x += rows[1].x;
                o.y += rows[1].y;
                o.h = o.h.min(rows[1].height.saturating_sub(o.y - rows[1].y));
                o
            })
            .collect(),
    );

    // hint bar
    let hint = if let Some(b) = app.busy {
        format!(" [ {b} ... ]")
    } else {
        format!(" {}", app.hints())
    };
    let hint_style = if app.warn.is_some() { style(K::Err) } else { style(K::Dim) };
    let hint = match app.warn {
        Some(wn) => format!("{hint}   !! {wn}"),
        None => hint,
    };
    f.render_widget(Paragraph::new(hint).style(hint_style), rows[2]);
}

impl App {
    fn label(&self) -> &'static str {
        match &self.mode {
            Mode::Login(_) => "authenticate",
            Mode::Wizard(w) => match w.kind {
                WKind::Setup => "first-time setup",
                WKind::Recover => "recovery",
                WKind::Passwd => "change password",
            },
            Mode::Shell => "vault",
            Mode::Compose(_) if self.courier_target.is_some() => "courier message",
            Mode::Compose(_) => "new message",
            Mode::Reauth(_) => "re-authenticate",
            Mode::View(_) => "message",
            Mode::FileView(_) => "file viewer",
            Mode::Wait => "working",
        }
    }

    fn hints(&self) -> &'static str {
        match &self.mode {
            Mode::Login(_) => "Enter next/submit   Tab switch field   F2 recovery   Esc quit",
            Mode::Wizard(w) => match w.step {
                Step::ShowRk => "Enter continue",
                Step::Totp => "Enter verify   Backspace delete   Esc cancel",
                _ => "Enter next   Tab switch field   Esc cancel",
            },
            Mode::Shell => "type a command   Ctrl+L clear   Esc clear line   Ctrl+C exit",
            Mode::Compose(_) if self.courier_target.is_some() => "Enter new line   Ctrl+D seal   Esc discard",
            Mode::Compose(_) => "Enter new line   Ctrl+D seal and store   Esc discard",
            Mode::Reauth(_) => "Enter confirm   Esc cancel",
            Mode::View(_) => "K / Esc / Q terminate now (leaving destroys it)",
            Mode::FileView(v) => v.hints(),
            Mode::Wait => "",
        }
    }

    fn body(&self, w: usize, h: usize) -> (Vec<Line<'static>>, Option<(u16, u16)>, Vec<Overlay>) {
        let mut l: Vec<Line<'static>> = Vec::new();
        let mut cur: Option<(u16, u16)> = None;
        let mut ov: Vec<Overlay> = Vec::new();
        self.body_h.set(h);
        match &self.mode {
            Mode::Wait => {}
            Mode::FileView(v) => (l, ov) = v.render(w, h),
            Mode::Login(x) => {
                l.push(ln(K::N, ""));
                l.push(ln(K::Head, "AUTHENTICATION REQUIRED"));
                l.push(ln(K::N, ""));
                l.push(field("password", &mask(x.pw.chars()), x.field == 0));
                l.push(field("code", &x.code, x.field == 1));
                l.push(ln(K::N, ""));
                if let Some((k, n)) = &x.note {
                    for s in wrap(n, w) {
                        l.push(ln(*k, s));
                    }
                }
                let (cx, cy) = if x.field == 0 { (14 + x.pw.chars().min(40), 3) } else { (14 + x.code.len(), 4) };
                cur = Some((cx as u16, cy));
            }
            Mode::Wizard(x) => cur = self.wizard_body(x, w, &mut l, &mut ov),
            Mode::Reauth(x) => {
                l.push(ln(K::N, ""));
                l.push(ln(K::Head, "CONFIRM IT IS YOU"));
                l.push(ln(
                    K::N,
                    match x.act {
                        Act::View { .. } => "Re-enter your password to view this file. It is decrypted in memory only.",
                        Act::Read { .. } => "Re-enter your password to open this message. It can be opened only once.",
                        Act::Passwd => "Re-enter your current password to change it.",
                        Act::Recv { .. } => "Re-enter your password to open this courier message. Its one-time key is destroyed when it opens.",
                        Act::SendFile { .. } => "Re-enter your password to send this file. It is decrypted in memory only, sealed for the paired device, then wiped.",
                    },
                ));
                l.push(ln(K::N, ""));
                l.push(field("password", &mask(x.pw.chars()), true));
                if let Some(n) = &x.note {
                    l.push(ln(K::N, ""));
                    l.push(ln(K::Err, n));
                }
                cur = Some((14 + x.pw.chars().min(40) as u16, 4));
            }
            Mode::Compose(t) => {
                l.push(ln(K::Head, format!("NEW MESSAGE   {} / {} bytes", t.as_bytes().len(), MSG_CAP)));
                l.push(ln(K::Dim, "stored encrypted. 'read' opens it once, then it is destroyed."));
                l.push(ln(K::N, ""));
                let wrapped = wrap(t.as_str(), w);
                let room = h.saturating_sub(4).max(1);
                let start = wrapped.len().saturating_sub(room);
                for s in &wrapped[start..] {
                    l.push(ln(K::Ok, s));
                }
                let last = wrapped.last().map_or(0, |s| s.chars().count());
                cur = Some((1 + last as u16, (l.len() as u16).saturating_sub(1)));
            }
            Mode::View(v) => {
                let left = v.until.saturating_duration_since(Instant::now()).as_secs();
                l.push(ln(K::Head, format!("MESSAGE {}   self-destructs in {:02}:{:02}", v.short, left / 60, left % 60)));
                l.push(ln(K::Warn, "already deleted from disk. This is the only copy, and it exists only on this screen."));
                l.push(ln(K::N, ""));
                let wrapped = wrap(v.text.as_str(), w);
                let room = h.saturating_sub(3).max(1);
                for s in wrapped.iter().take(room) {
                    l.push(ln(K::Ok, s));
                }
                if wrapped.len() > room {
                    l.push(ln(K::Warn, "[message continues beyond the screen: enlarge the window]"));
                }
            }
            Mode::Shell => {
                let mut all: Vec<Line<'static>> = Vec::new();
                for o in &self.out {
                    for s in wrap(&o.s, w) {
                        all.push(ln(o.k, s));
                    }
                }
                all.push(Line::from(vec![
                    Span::styled(" scytale> ", style(K::Head)),
                    Span::styled(clean(&self.cmd), style(K::Ok)),
                ]));
                let start = all.len().saturating_sub(h);
                l = all.split_off(start);
                cur = Some((10 + self.cmd.chars().count() as u16, (l.len() as u16).saturating_sub(1)));
            }
        }
        (l, cur, ov)
    }

    fn wizard_body(&self, x: &Wizard, w: usize, l: &mut Vec<Line<'static>>, ov: &mut Vec<Overlay>) -> Option<(u16, u16)> {
        l.push(ln(K::N, ""));
        let cur;
        match x.step {
            Step::Rk => {
                l.push(ln(K::Head, "RECOVERY"));
                for s in wrap("Enter the recovery key you saved at setup. You will then choose a new password and a new authenticator, and receive a new recovery key.", w) {
                    l.push(ln(K::N, s));
                }
                l.push(ln(K::N, ""));
                l.push(field("key", &mask(x.rk_in.chars()), true));
                cur = Some((14 + x.rk_in.chars().min(40) as u16, (l.len() as u16).saturating_sub(1)));
            }
            Step::Pw => {
                let title = match x.kind {
                    WKind::Setup => "CREATE THE ADMIN PASSWORD",
                    WKind::Recover => "CHOOSE A NEW PASSWORD",
                    WKind::Passwd => "CHOOSE A NEW PASSWORD",
                };
                l.push(ln(K::Head, title));
                for s in wrap(&format!("At least {MIN_PW_CHARS} characters; a long passphrase of several words is best. It cannot be recovered. Only the recovery key can reset it."), w) {
                    l.push(ln(K::N, s));
                }
                l.push(ln(K::N, ""));
                l.push(field("password", &mask(x.pw1.chars()), x.field == 0));
                l.push(field("confirm", &mask(x.pw2.chars()), x.field == 1));
                let y = (l.len() as u16).saturating_sub(2) + x.field as u16;
                cur = Some((14 + (if x.field == 0 { x.pw1.chars() } else { x.pw2.chars() }).min(40) as u16, y));
            }
            Step::Totp => {
                l.push(ln(K::Head, "ADD THE AUTHENTICATOR"));
                for s in wrap("Scan this with an authenticator app (or enter the secret by hand), then type the 6-digit code it shows.", w) {
                    l.push(ln(K::N, s));
                }
                let (top, mut width) = (l.len(), 0usize);
                for q in x.qr.lines() {
                    width = width.max(q.chars().count());
                    l.push(Line::from(Span::styled(format!(" {q}"), Style::new().fg(Color::White).bg(Color::Black))));
                }
                if let Some(px) = &x.qr_px {
                    ov.push(Overlay {
                        x: 1,
                        y: top as u16,
                        w: width as u16,
                        h: (l.len() - top) as u16,
                        img: px.clone(),
                        fit: Fit::Contain,
                        smooth: false,
                    });
                }
                l.push(ln(K::Dim, format!("secret: {}", &*x.secret_txt)));
                l.push(field("code", &x.code, true));
                cur = Some((14 + x.code.len() as u16, (l.len() as u16).saturating_sub(1)));
            }
            Step::ShowRk => {
                l.push(ln(K::Head, "YOUR RECOVERY KEY. SHOWN ONCE"));
                for s in wrap("This is the only way back in if you lose the password or this Windows account. Write it down and keep it OFFLINE, away from this PC. Anyone holding it can open the vault.", w) {
                    l.push(ln(K::Warn, s));
                }
                l.push(ln(K::N, ""));
                if let Some(rk) = &x.rk {
                    let enc = Zeroizing::new(BASE32_NOPAD.encode(rk.as_bytes()));
                    let groups: Vec<&str> = enc.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap_or("")).collect();
                    for half in groups.chunks(7) {
                        l.push(Line::from(Span::styled(format!("   {}", half.join("-")), style(K::Head))));
                    }
                }
                l.push(ln(K::N, ""));
                l.push(field("type SAVED", &x.code, true));
                cur = Some((14 + x.code.len() as u16, (l.len() as u16).saturating_sub(1)));
            }
        }
        if let Some(e) = &x.err {
            l.push(ln(K::N, ""));
            for s in wrap(e, w) {
                l.push(ln(K::Err, s));
            }
        }
        cur
    }
}

#[allow(dead_code)]
const _: u32 = FREE_ATTEMPTS;

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    fn key(app: &mut App, code: KeyCode) {
        app.on_key(KeyEvent::new(code, KeyModifiers::NONE));
        if let Some(j) = app.job.take() {
            app.run_job(j);
            app.busy = None;
        }
    }
    fn ctrl(app: &mut App, c: char) {
        app.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL));
    }
    fn typ(app: &mut App, s: &str) {
        for c in s.chars() {
            key(app, KeyCode::Char(c));
        }
    }
    fn screen(app: &App) -> String {
        let mut t = Terminal::new(TestBackend::new(110, 60)).unwrap();
        t.draw(|f| draw(f, app)).unwrap();
        let buf = t.backend().buffer().clone();
        let mut s = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }
    fn code_for(secret: &[u8]) -> String {
        format!("{:06}", crypto::totp_code(secret, unix_now() / crypto::TOTP_STEP))
    }

    #[test]
    fn path_arg_takes_the_whole_path() {
        let p = r"C:\Users\me\My Pictures\beach day.jpeg";
        assert_eq!(path_arg(&format!("enc {p}")).as_deref(), Some(p));
        assert_eq!(path_arg(&format!("  encrypt   \"{p}\"  ")).as_deref(), Some(p));
        assert_eq!(path_arg("enc"), None);
        assert_eq!(path_arg("enc   \"\" "), None);
    }

    #[test]
    fn wrap_keeps_indentation_and_width() {
        assert_eq!(wrap("    indented  twice", 40), vec!["    indented  twice"]);
        let text = "fn main() {\n        let x = averyveryveryverylongidentifierthatdoesnotfit + other_value * 2;\n}";
        for w in [8usize, 12, 20, 33, 80] {
            for l in wrap(text, w) {
                assert!(l.chars().count() <= w, "width {w}: {l:?}");
            }
        }
        let joined: String = wrap("alpha beta gamma delta", 11).join("|");
        assert_eq!(joined, "alpha beta|gamma delta");
    }

    #[test]
    fn full_flow_through_the_interface() {
        let dir = std::env::temp_dir().join(format!("scytale-test-ui-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pw = "orange glacier piano 42";

        // ---- setup
        let mut app = App::new(dir.clone(), true, true);
        assert!(screen(&app).contains("CREATE THE ADMIN PASSWORD"));
        typ(&mut app, "short");
        key(&mut app, KeyCode::Enter);
        typ(&mut app, "short");
        key(&mut app, KeyCode::Enter);
        assert!(screen(&app).contains("at least 14"));
        typ(&mut app, pw);
        key(&mut app, KeyCode::Enter);
        typ(&mut app, pw);
        key(&mut app, KeyCode::Enter);
        let s = screen(&app);
        assert!(s.contains("ADD THE AUTHENTICATOR") && s.contains("secret:"));
        match &app.mode {
            Mode::Wizard(w) => {
                let qr = w.qr_px.as_ref().expect("pixel QR");
                assert!(qr.w == qr.h && qr.w > 25);
                assert_eq!(&qr.bgra[0..3], &[255, 255, 255], "quiet zone is white");
            }
            _ => panic!("expected wizard"),
        }
        let secret = match &app.mode {
            Mode::Wizard(w) => w.totp.as_ref().unwrap().to_vec(),
            _ => panic!("expected wizard"),
        };
        typ(&mut app, "000000");
        key(&mut app, KeyCode::Enter);
        let wrong = crypto::totp_verify(&secret, unix_now(), "000000", 0).is_none();
        if wrong {
            assert!(screen(&app).contains("did not match"));
        }
        if let Mode::Wizard(w) = &mut app.mode {
            w.code.clear();
        }
        typ(&mut app, &code_for(&secret));
        key(&mut app, KeyCode::Enter);
        assert!(screen(&app).contains("RECOVERY KEY"));
        typ(&mut app, "saved");
        key(&mut app, KeyCode::Enter);
        assert!(matches!(app.mode, Mode::Shell));
        assert!(screen(&app).contains("vault unlocked"));

        // ---- files
        let work = dir.with_extension("work");
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).unwrap();
        let src = work.join("plan.txt");
        std::fs::write(&src, b"top secret plan").unwrap();
        typ(&mut app, &format!("enc \"{}\"", src.display()));
        key(&mut app, KeyCode::Enter);
        assert!(!src.exists(), "{}", screen(&app));
        assert!(screen(&app).contains("original overwritten and deleted"));
        let fid = app.sess.as_ref().unwrap().items[0].short();
        typ(&mut app, "ls");
        key(&mut app, KeyCode::Enter);
        assert!(screen(&app).contains("plan.txt"));

        // decrypt: wrong password, then right one
        let out = work.join("out");
        std::fs::create_dir_all(&out).unwrap();
        // view inside Scytale: nothing written anywhere
        typ(&mut app, &format!("dec {fid}"));
        key(&mut app, KeyCode::Enter);
        assert!(screen(&app).contains("view this file"));
        typ(&mut app, pw);
        key(&mut app, KeyCode::Enter);
        let s = screen(&app);
        assert!(s.contains("top secret plan") && s.contains("decrypted in memory only") && s.contains("plan.txt"), "{s}");
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
        key(&mut app, KeyCode::Down);
        key(&mut app, KeyCode::Char('h'));
        assert!(screen(&app).contains("74 6f 70")); // "top" in hex
        key(&mut app, KeyCode::Esc);
        assert!(matches!(app.mode, Mode::Shell) && screen(&app).contains("wiped from memory"));
        assert!(std::fs::read_to_string(dir.join("audit.log")).unwrap().contains(",FILE_DEC,"));

        // wrong password at re-authentication is refused and counted
        typ(&mut app, &format!("dec {fid}"));
        key(&mut app, KeyCode::Enter);
        assert!(screen(&app).contains("CONFIRM IT IS YOU"));
        typ(&mut app, "nope nope nope");
        key(&mut app, KeyCode::Enter);
        assert!(screen(&app).contains("authentication failed"));
        assert!(std::fs::read_to_string(dir.join("audit.log")).unwrap().contains(",REAUTH_FAIL,"));
        key(&mut app, KeyCode::Esc);

        // export no longer exists: nothing can write plaintext out of the vault
        typ(&mut app, &format!("export {fid} \"{}\"", out.display()));
        key(&mut app, KeyCode::Enter);
        assert!(screen(&app).contains("unknown command"));
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);

        // paste goes into the command line, newlines flattened
        app.on_paste("ls\n");
        assert_eq!(app.cmd, "ls ");
        app.cmd.clear();

        // ---- messages
        typ(&mut app, "msg");
        key(&mut app, KeyCode::Enter);
        typ(&mut app, "line one");
        key(&mut app, KeyCode::Enter);
        typ(&mut app, "line two");
        ctrl(&mut app, 'd');
        assert!(screen(&app).contains("message sealed"));
        let mid = app.sess.as_ref().unwrap().items.iter().find(|i| i.kind == Kind::Msg).unwrap().short();
        typ(&mut app, &format!("read {mid}"));
        key(&mut app, KeyCode::Enter);
        typ(&mut app, pw);
        key(&mut app, KeyCode::Enter);
        let s = screen(&app);
        assert!(s.contains("self-destructs in 0") && s.contains("line one") && s.contains("line two"));
        assert!(app.sess.as_ref().unwrap().items.iter().all(|i| i.kind != Kind::Msg), "gone from disk on open");
        key(&mut app, KeyCode::Char('k'));
        assert!(screen(&app).contains("terminated"));
        typ(&mut app, &format!("read {mid}"));
        key(&mut app, KeyCode::Enter);
        assert!(screen(&app).contains("no such item"));

        // expiry path
        typ(&mut app, "msg");
        key(&mut app, KeyCode::Enter);
        typ(&mut app, "short lived");
        ctrl(&mut app, 'd');
        let mid2 = app.sess.as_ref().unwrap().items.iter().find(|i| i.kind == Kind::Msg).unwrap().short();
        typ(&mut app, &format!("read {mid2}"));
        key(&mut app, KeyCode::Enter);
        typ(&mut app, pw);
        key(&mut app, KeyCode::Enter);
        if let Mode::View(v) = &mut app.mode {
            v.until = Instant::now();
        }
        app.tick();
        assert!(screen(&app).contains("expired"));

        // ---- purge
        typ(&mut app, &format!("purge {fid}"));
        key(&mut app, KeyCode::Enter);
        assert!(screen(&app).contains("repeat as"));
        typ(&mut app, &format!("purge {fid} yes"));
        key(&mut app, KeyCode::Enter);
        assert!(app.sess.as_ref().unwrap().items.is_empty());

        // ---- audit has events, no names
        typ(&mut app, "audit 50");
        key(&mut app, KeyCode::Enter);
        let s = screen(&app);
        assert!(s.contains("FILE_ENC") && s.contains("MSG_EXPIRE") && s.contains("log integrity: intact"));
        let log = std::fs::read_to_string(dir.join("audit.log")).unwrap();
        assert!(!log.contains("plan") && !log.contains("line one") && !log.contains("out"));

        // ---- courier, through the real keyboard paths, against a simulated iPhone
        let mut phone = crate::courier::State::default();
        let phone_bundle = work.join("phone.scykey");
        std::fs::write(&phone_bundle, phone.export_bundle(1)).unwrap();
        typ(&mut app, &format!("pair import \"{}\"", phone_bundle.display()));
        key(&mut app, KeyCode::Enter);
        assert!(screen(&app).contains("key bundle accepted"), "{}", screen(&app));
        let bundles = work.join("bundles");
        std::fs::create_dir_all(&bundles).unwrap();
        typ(&mut app, &format!("pair export \"{}\"", bundles.display()));
        key(&mut app, KeyCode::Enter);
        let pc_bundle = std::fs::read_dir(&bundles).unwrap().next().expect("bundle written").unwrap().path();
        assert_eq!(phone.import_bundle(&std::fs::read(&pc_bundle).unwrap()).unwrap(), phone.safety_number().unwrap());
        typ(&mut app, "pair verify MATCH");
        key(&mut app, KeyCode::Enter);
        assert!(screen(&app).contains("pairing verified"));
        phone.verify_peer();

        // send to a folder (unquoted path, as typed): a .scy file must appear and open on the phone
        let outbox = work.join("outbox");
        std::fs::create_dir_all(&outbox).unwrap();
        typ(&mut app, &format!("send yes {}", outbox.display()));
        key(&mut app, KeyCode::Enter);
        assert!(matches!(app.mode, Mode::Compose(_)), "{}", screen(&app));
        typ(&mut app, "hello phone");
        ctrl(&mut app, 'd');
        let sent: Vec<_> = std::fs::read_dir(&outbox).unwrap().map(|e| e.unwrap().path()).collect();
        assert_eq!(sent.len(), 1, "{}", screen(&app));
        assert_eq!(sent[0].extension().unwrap(), "scy");
        let got = phone.open(&std::fs::read(&sent[0]).unwrap()).unwrap();
        assert_eq!(&got.text[..], b"hello phone");
        assert!(got.burn);
        // send to an explicit .txt path: armored text
        let txt = outbox.join("reply.txt");
        typ(&mut app, &format!("send no \"{}\"", txt.display()));
        key(&mut app, KeyCode::Enter);
        typ(&mut app, "as text");
        ctrl(&mut app, 'd');
        assert!(std::fs::read_to_string(&txt).unwrap().starts_with("-----BEGIN SCYTALE MESSAGE-----"));

        // receive: the phone's armored block pasted at the prompt, then recv
        let env = phone.seal(b"reply from the phone", false, 1).unwrap();
        let armored = crate::courier::armor_message(&env);
        app.on_paste(&armored);
        assert!(app.cmd.is_empty(), "the block must not flood the command line");
        assert!(screen(&app).contains("type recv to open it"));
        typ(&mut app, "recv");
        key(&mut app, KeyCode::Enter);
        assert!(screen(&app).contains("courier message"), "{}", screen(&app));
        typ(&mut app, pw);
        key(&mut app, KeyCode::Enter);
        assert!(screen(&app).contains("reply from the phone"), "{}", screen(&app));
        key(&mut app, KeyCode::Esc);
        assert!(app.sess.as_ref().unwrap().items.iter().any(|i| i.name.starts_with("Received message")));

        // ---- idle: wipe and exit (with an open message on screen)
        typ(&mut app, "msg");
        key(&mut app, KeyCode::Enter);
        typ(&mut app, "draft text");
        app.last_input = Instant::now() - Duration::from_secs(IDLE_SECS + 1);
        app.tick();
        assert!(app.quit && app.sess.is_none() && matches!(app.mode, Mode::Wait));
        assert!(std::fs::read_to_string(dir.join("audit.log")).unwrap().contains(",TIMEOUT,"));

        // idle also exits from the login screen, without a session to log; the reason is shown
        let mut app = App::new(dir.clone(), true, true);
        assert!(screen(&app).contains("previous session closed after 5 minutes without activity"));
        app.last_input = Instant::now() - Duration::from_secs(IDLE_SECS + 1);
        app.tick();
        assert!(app.quit);

        // ---- login: a replayed code is refused
        let mut app = App::new(dir.clone(), true, true);
        typ(&mut app, pw);
        key(&mut app, KeyCode::Enter);
        typ(&mut app, &code_for(&secret));
        key(&mut app, KeyCode::Enter);
        assert!(app.sess.is_none(), "same TOTP step must not be accepted twice");
        app.store.as_mut().unwrap().st.last_step = 0; // simulate the next 30 s window
        app.store.as_mut().unwrap().register_success();
        typ(&mut app, pw);
        key(&mut app, KeyCode::Enter);
        typ(&mut app, &code_for(&secret));
        key(&mut app, KeyCode::Enter);
        assert!(app.sess.is_some());
        assert!(screen(&app).contains("last login"));

        // ---- Windows lock notification: wipe and exit
        watch::signal(Reason::WinLock);
        app.tick();
        assert!(app.quit && app.sess.is_none());
        assert!(std::fs::read_to_string(dir.join("audit.log")).unwrap().contains(",WIN_LOCK,"));

        // ---- restart: app reopens at login; then panic wipe
        let mut app = App::new(dir.clone(), true, true);
        assert!(screen(&app).contains("AUTHENTICATION REQUIRED"));
        app.store.as_mut().unwrap().st.last_step = 0;
        typ(&mut app, pw);
        key(&mut app, KeyCode::Enter);
        typ(&mut app, &code_for(&secret));
        key(&mut app, KeyCode::Enter);
        assert!(app.sess.is_some());
        typ(&mut app, "wipe");
        key(&mut app, KeyCode::Enter);
        assert!(screen(&app).contains("wipe DESTROY") && dir.join("vault.hdr").exists());
        typ(&mut app, "wipe destroy");
        key(&mut app, KeyCode::Enter);
        assert!(dir.join("vault.hdr").exists(), "confirmation is case-sensitive");
        typ(&mut app, "wipe DESTROY");
        key(&mut app, KeyCode::Enter);
        assert!(app.quit && app.sess.is_none() && app.store.is_none());
        assert!(!dir.exists(), "vault folder must be gone");
        assert!(app.exit_note.as_deref().unwrap().contains("vault destroyed"));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&work);
    }
}
