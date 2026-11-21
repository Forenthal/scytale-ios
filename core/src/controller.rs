//! UI-independent controller with the same setup / login / recovery / lockout rules as the Windows
//! app's ui.rs. The iOS interface drives it through ffi.rs and only ever receives status codes and
//! the few strings it must display (QR modules, authenticator secret, recovery key). Passwords,
//! codes and keys are typed directly into the fixed buffers here and never exist in Swift.

use data_encoding::BASE32_NOPAD;
use zeroize::Zeroizing;

use crate::{
    audit::{ev, Chain, Store, TERMINATE_AT},
    clock::{self, Now},
    crypto,
    secret::{Secret32, SecretInput},
    util::unix_now,
    vault::{Session, Vault},
};

pub const MIN_PW_CHARS: usize = 14;
const MIN_DISTINCT: usize = 6;
const PW_CAP: usize = 256;
const RK_CAP: usize = 160;
const CODE_CAP: usize = 6;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Field {
    Pw1 = 0,
    Pw2 = 1,
    Code = 2,
    Rk = 3,
}

impl Field {
    pub fn from_i32(v: i32) -> Option<Field> {
        Some(match v {
            0 => Field::Pw1,
            1 => Field::Pw2,
            2 => Field::Code,
            3 => Field::Rk,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    Setup = 0,
    Login = 1,
    Unlocked = 2,
}

/// What the login screen should say when the app starts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StartNote {
    NeedsSetup = 0,
    None = 1,
    PrevTimeout = 2,
    PrevBackground = 3,
    PrevDeviceLock = 4,
    PrevAborted = 5,
    StateReset = 6,
    AuditKeyMissing = 7,
    PrevCapture = 8,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LockReason {
    Logout = 0,
    Timeout = 1,
    Background = 2,
    DeviceLock = 3,
    Capture = 4,
}

impl LockReason {
    pub fn from_i32(v: i32) -> LockReason {
        match v {
            1 => LockReason::Timeout,
            2 => LockReason::Background,
            3 => LockReason::DeviceLock,
            4 => LockReason::Capture,
            _ => LockReason::Logout,
        }
    }

    fn event(self) -> &'static str {
        match self {
            LockReason::Logout => ev::LOGOUT,
            LockReason::Timeout => ev::TIMEOUT,
            LockReason::Background => ev::BACKGROUND,
            LockReason::DeviceLock => ev::DEVICE_LOCK,
            LockReason::Capture => ev::CAPTURE,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PwErr {
    Weak = 1,
    Mismatch = 2,
    WrongState = 3,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LoginOutcome {
    Ok,
    Failed { attempts_left: u32 },
    FailedLocked { secs: u64 },
    Locked { secs: u64 },
    Incomplete,
    AuditUnavailable,
    IndexFailed,
    /// 15 wrong admin passwords: the vault was destroyed.
    Terminated,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CommitErr {
    NotReady = 1,
    Vault = 2,
    Audit = 3,
    Index = 4,
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Summary {
    pub last_login: u64,
    pub fails_since: u32,
    /// 0 intact, 1 broken (at `chain_at`), 2 truncated
    pub chain: i32,
    pub chain_at: u64,
    pub dropped: u32,
    pub shredded: u32,
}

#[derive(PartialEq, Eq)]
enum Kind {
    Setup,
    Recover,
}

/// Material generated for a new vault (or a recovery) until it is committed and shown.
struct Pending {
    kind: Kind,
    totp: Zeroizing<Vec<u8>>,
    totp_step: u64,
    rk: Secret32,
    pepper: Secret32,
    pepper_ok: bool,
    code_ok: bool,
    committed: bool,
}

pub struct Core {
    pub vault: Vault,
    store: Option<Store>,
    sess: Option<Session>,
    sess_start: u64,
    pending: Option<Pending>,
    recover_mk: Option<Secret32>,
    pub summary: Summary,
    pw1: SecretInput,
    pw2: SecretInput,
    code: SecretInput,
    rk_in: SecretInput,
    /// SHA-256 of the device pepper used at login: re-authentication must produce the same pepper
    /// from the Secure Enclave (i.e. pass Face ID against the current enrolment).
    pepper_hash: Option<[u8; 32]>,
    /// One decrypt is authorised by one successful re-authentication.
    reauth_ok: bool,
    /// Some re-authentication succeeded during this session (for "Face ID once per session").
    reauth_session: bool,
    /// The configuration screen was unlocked with Face ID.
    config_ok: bool,
    /// The file currently decrypted for the viewer (locked memory, wiped on close).
    view: Option<SecretInput>,
    /// Courier state (identity, one-time keys, paired device), loaded on first use per session.
    courier: Option<crate::courier::State>,
    /// Last courier output (envelope or bundle) for the platform to copy out. Not secret.
    courier_out: Vec<u8>,
    /// Tags (sealed in the vault), loaded on first use per session.
    tags: Option<crate::tags::Tags>,
    audit_cache: Option<(Vec<crate::audit::Entry>, Chain)>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReauthOutcome {
    Ok,
    Bad { attempts_left: u32 },
    /// Too many failures: the session was ended.
    LockedOut,
    NoSession,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ViewErr {
    NotAuthorised = 1,
    NotFound = 2,
    TooLarge = 3,
    Integrity = 4,
    NoSession = 5,
    IsMessage = 6,
}

fn sha256(b: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(b).into()
}

fn grouped(s: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(s.len() + s.len() / 4));
    for (i, c) in s.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

impl Core {
    pub fn new(vault: Vault) -> Core {
        Core {
            vault,
            store: None,
            sess: None,
            sess_start: 0,
            pending: None,
            recover_mk: None,
            summary: Summary::default(),
            pw1: SecretInput::new(PW_CAP),
            pw2: SecretInput::new(PW_CAP),
            code: SecretInput::new(CODE_CAP),
            rk_in: SecretInput::new(RK_CAP),
            pepper_hash: None,
            reauth_ok: false,
            reauth_session: false,
            config_ok: false,
            view: None,
            courier: None,
            courier_out: Vec::new(),
            tags: None,
            audit_cache: None,
        }
    }

    pub fn phase(&self) -> Phase {
        if self.sess.is_some() {
            Phase::Unlocked
        } else if self.vault.exists() && !self.pending.as_ref().is_some_and(|p| p.kind == Kind::Setup) {
            Phase::Login
        } else {
            Phase::Setup
        }
    }

    // ------------------------------------------------------------ start

    /// Called once at launch with the audit key from the Keychain (None if it is missing).
    /// Returns the note for the login screen and its timestamp.
    pub fn start(&mut self, audit_key: Option<Secret32>) -> (StartNote, u64) {
        if !self.vault.exists() {
            return (StartNote::NeedsSetup, 0);
        }
        let Some(key) = audit_key else {
            return (StartNote::AuditKeyMissing, 0);
        };
        let Ok(mut s) = Store::load(&self.vault.dir, key, clock::now()) else {
            return (StartNote::AuditKeyMissing, 0);
        };
        let mut note = (StartNote::None, 0);
        if s.was_reset {
            let _ = s.log(ev::STATE_RESET, 0);
            note = (StartNote::StateReset, unix_now());
        }
        if s.st.session_start != 0 {
            let _ = s.log(ev::ABORTED, 0);
            s.st.session_start = 0;
            let _ = s.save_state();
        }
        if note.0 == StartNote::None {
            let last = s
                .read()
                .ok()
                .and_then(|(e, _)| e.into_iter().rev().find(|x| x.ev != ev::LOGIN_FAIL && x.ev != ev::LOCKOUT));
            if let Some(e) = last {
                let n = match e.ev.as_str() {
                    ev::TIMEOUT => StartNote::PrevTimeout,
                    ev::BACKGROUND => StartNote::PrevBackground,
                    ev::DEVICE_LOCK => StartNote::PrevDeviceLock,
                    ev::ABORTED => StartNote::PrevAborted,
                    ev::CAPTURE => StartNote::PrevCapture,
                    _ => StartNote::None,
                };
                note = (n, e.ts);
            }
        }
        self.store = Some(s);
        note
    }

    // ------------------------------------------------------------ input

    fn field(&mut self, f: Field) -> &mut SecretInput {
        match f {
            Field::Pw1 => &mut self.pw1,
            Field::Pw2 => &mut self.pw2,
            Field::Code => &mut self.code,
            Field::Rk => &mut self.rk_in,
        }
    }

    /// Append typed text. Control characters are dropped; the code field accepts digits only.
    pub fn push(&mut self, f: Field, text: &str) -> bool {
        let mut all = true;
        for c in text.chars() {
            let ok = match f {
                Field::Code => c.is_ascii_digit() && self.code.as_bytes().len() < CODE_CAP && self.code.push(c),
                _ => !c.is_control() && self.field(f).push(c),
            };
            all &= ok;
        }
        all
    }

    pub fn backspace(&mut self, f: Field) {
        self.field(f).pop();
    }

    pub fn clear(&mut self, f: Field) {
        self.field(f).clear();
    }

    pub fn count(&mut self, f: Field) -> usize {
        self.field(f).chars()
    }

    fn clear_all(&mut self) {
        self.pw1.clear();
        self.pw2.clear();
        self.code.clear();
        self.rk_in.clear();
    }

    // ------------------------------------------------------------ setup / recovery

    /// Validate the two password entries and generate the authenticator secret, recovery key and
    /// device pepper. `recover` continues a recovery started with `recover_check`.
    pub fn setup_begin(&mut self, recover: bool) -> Result<(), PwErr> {
        if self.sess.is_some() || (recover && self.recover_mk.is_none()) || (!recover && self.vault.exists()) {
            return Err(PwErr::WrongState);
        }
        let distinct = {
            let mut cs: Vec<char> = self.pw1.as_str().chars().collect();
            cs.sort_unstable();
            cs.dedup();
            let n = cs.len();
            cs.iter_mut().for_each(|c| *c = '\0');
            n
        };
        if self.pw1.chars() < MIN_PW_CHARS || distinct < MIN_DISTINCT {
            self.pw1.clear();
            self.pw2.clear();
            return Err(PwErr::Weak);
        }
        if !crypto::ct_eq(self.pw1.as_bytes(), self.pw2.as_bytes()) {
            self.pw1.clear();
            self.pw2.clear();
            return Err(PwErr::Mismatch);
        }
        let mut totp = Zeroizing::new(vec![0u8; 20]);
        crypto::random_bytes(&mut totp);
        self.pending = Some(Pending {
            kind: if recover { Kind::Recover } else { Kind::Setup },
            totp,
            totp_step: 0,
            rk: Secret32::random(),
            pepper: Secret32::random(),
            pepper_ok: false,
            code_ok: false,
            committed: false,
        });
        self.code.clear();
        Ok(())
    }

    fn totp_uri(&self) -> Option<Zeroizing<String>> {
        let p = self.pending.as_ref()?;
        let b32 = Zeroizing::new(BASE32_NOPAD.encode(&p.totp));
        Some(Zeroizing::new(format!(
            "otpauth://totp/Scytale%20iPhone:admin?secret={}&issuer=Scytale%20iPhone&algorithm=SHA1&digits=6&period=30",
            b32.as_str()
        )))
    }

    /// QR modules for the authenticator, row by row (1 = dark). Returns (width, modules).
    pub fn setup_qr(&self) -> Option<(usize, Zeroizing<Vec<u8>>)> {
        let uri = self.totp_uri()?;
        let code = qrcode::QrCode::new(uri.as_bytes()).ok()?;
        let mods = Zeroizing::new(
            code.to_colors().iter().map(|c| u8::from(*c == qrcode::Color::Dark)).collect::<Vec<u8>>(),
        );
        Some((code.width(), mods))
    }

    /// The authenticator secret as grouped base32, for typing into an authenticator by hand.
    pub fn setup_secret_text(&self) -> Option<Zeroizing<String>> {
        let p = self.pending.as_ref()?;
        Some(grouped(&BASE32_NOPAD.encode(&p.totp)))
    }

    /// The new device pepper, for the platform to wrap with the Secure Enclave key.
    pub fn setup_pepper(&self) -> Option<&[u8; 32]> {
        self.pending.as_ref().map(|p| p.pepper.as_bytes())
    }

    /// The platform proves the Secure Enclave round trip (Face ID) returns the same pepper.
    pub fn setup_pepper_verify(&mut self, unwrapped: &[u8]) -> bool {
        let Some(p) = self.pending.as_mut() else { return false };
        p.pepper_ok = crypto::ct_eq(unwrapped, p.pepper.as_bytes());
        p.pepper_ok
    }

    /// Check the 6-digit code typed from the authenticator.
    pub fn setup_code(&mut self, now: u64) -> bool {
        let Some(p) = self.pending.as_mut() else { return false };
        let hit = crypto::totp_verify(&p.totp, now, self.code.as_str(), 0);
        self.code.clear();
        match hit {
            Some(step) => {
                p.totp_step = step;
                p.code_ok = true;
                true
            }
            None => false,
        }
    }

    /// Create the vault (or re-key it after recovery) and open a session.
    pub fn setup_commit(&mut self, wrapped_pepper: &[u8], new_audit_key: Option<Secret32>) -> Result<(), CommitErr> {
        let ready = self.pending.as_ref().is_some_and(|p| p.pepper_ok && p.code_ok && !p.committed);
        if !ready {
            return Err(CommitErr::NotReady);
        }
        let p = self.pending.as_ref().unwrap();
        let pepper_hash = sha256(p.pepper.as_bytes());
        let dir = self.vault.dir.clone();
        let mk = match p.kind {
            Kind::Setup => {
                let key = new_audit_key.ok_or(CommitErr::NotReady)?;
                let mk = self
                    .vault
                    .create(self.pw1.as_bytes(), &p.totp, &p.rk, &p.pepper, wrapped_pepper)
                    .map_err(|_| CommitErr::Vault)?;
                let mut store = Store::create(&dir, key).map_err(|_| CommitErr::Audit)?;
                store.log(ev::SETUP, 0).map_err(|_| CommitErr::Audit)?;
                store.st.last_step = p.totp_step;
                self.store = Some(store);
                mk
            }
            Kind::Recover => {
                let mk = self.recover_mk.take().ok_or(CommitErr::NotReady)?;
                if let Err(_) = self.vault.rewrite_header(
                    &mk,
                    self.pw1.as_bytes(),
                    &p.pepper,
                    wrapped_pepper,
                    Some(&p.rk),
                    Some(&p.totp),
                ) {
                    self.recover_mk = Some(mk);
                    return Err(CommitErr::Vault);
                }
                let mut store = match (self.store.take(), new_audit_key) {
                    (Some(s), _) => s,
                    (None, Some(k)) => Store::fresh(&dir, k).map_err(|_| CommitErr::Audit)?,
                    (None, None) => return Err(CommitErr::Audit),
                };
                store.register_success();
                store.st.last_step = p.totp_step;
                store.log(ev::RECOVERY, 0).map_err(|_| CommitErr::Audit)?;
                self.store = Some(store);
                mk
            }
        };
        self.pw1.clear();
        self.pw2.clear();
        self.code.clear();
        if let Some(p) = self.pending.as_mut() {
            p.committed = true;
            // the authenticator secret and pepper are no longer needed in memory
            p.totp.iter_mut().for_each(|b| *b = 0);
            p.pepper = Secret32::zeroed();
        }
        self.open_session(mk).map_err(|_| CommitErr::Index)?;
        self.pepper_hash = Some(pepper_hash);
        Ok(())
    }

    /// The recovery key, shown once after commit, as grouped base32.
    pub fn setup_recovery_text(&self) -> Option<Zeroizing<String>> {
        let p = self.pending.as_ref().filter(|p| p.committed)?;
        Some(grouped(&BASE32_NOPAD.encode(p.rk.as_bytes())))
    }

    /// Recovery key has been saved (or setup abandoned): drop everything pending.
    pub fn setup_finish(&mut self) {
        self.pending = None;
        self.recover_mk = None;
        self.clear_all();
    }

    /// Recovery step 1: check the typed recovery key against the vault.
    pub fn recover_check(&mut self) -> bool {
        let text: Zeroizing<String> = Zeroizing::new(
            self.rk_in.as_str().chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_uppercase(),
        );
        self.rk_in.clear();
        let rk = BASE32_NOPAD
            .decode(text.as_bytes())
            .ok()
            .map(Zeroizing::new)
            .filter(|b| b.len() == 32)
            .map(|b| Secret32::from_slice(&b));
        match rk.and_then(|rk| self.vault.unlock_recovery(&rk)) {
            Some(mk) => {
                self.recover_mk = Some(mk);
                // the new-password form always starts empty
                self.pw1.clear();
                self.pw2.clear();
                self.code.clear();
                true
            }
            None => {
                if let Some(s) = self.store.as_mut() {
                    let _ = s.log(ev::RECOV_FAIL, 0);
                }
                false
            }
        }
    }

    // ------------------------------------------------------------ login

    pub fn wrapped_pepper(&self) -> Option<Vec<u8>> {
        self.vault.wrapped_pepper().ok()
    }

    pub fn locked_remaining(&self, now: impl Into<Now>) -> Option<u64> {
        self.store.as_ref().and_then(|s| s.locked_remaining(now))
    }

    /// 0 none; 1 = 5–9 wrong passwords ("termination in 10"); 2 = 10–14 ("termination in 5").
    pub fn termination_level(&self) -> u32 {
        match self.store.as_ref().map_or(0, |s| s.st.pw_fails) {
            n if n >= 10 => 2,
            n if n >= 5 => 1,
            _ => 0,
        }
    }

    // ------------------------------------------------------------ configuration

    /// The configuration in force (hardened defaults when none is stored or it is not custom).
    pub fn config(&self) -> crate::config::Config {
        self.config_stored().effective()
    }

    /// The stored configuration, including choices that are inactive while hardened.
    pub fn config_stored(&self) -> crate::config::Config {
        self.store.as_ref().map_or_else(Default::default, |s| crate::config::Config::from_bytes(&s.st.config))
    }

    /// Unlock the configuration screen: consumes a successful Face ID re-authentication.
    pub fn config_begin(&mut self) -> bool {
        self.config_ok = self.sess.is_some() && std::mem::replace(&mut self.reauth_ok, false);
        self.config_ok
    }

    pub fn config_end(&mut self) {
        self.config_ok = false;
    }

    /// Store a new configuration (screen must be unlocked; values must be valid).
    pub fn set_config(&mut self, c: crate::config::Config) -> bool {
        if !self.config_ok || self.sess.is_none() || !c.valid() {
            return false;
        }
        let Some(store) = self.store.as_mut() else { return false };
        store.st.config = c.to_bytes();
        if store.save_state().is_err() {
            return false;
        }
        self.audit(ev::CONFIG_CHANGE);
        true
    }

    /// One re-authentication normally authorises one decrypt. With "Face ID once per session",
    /// any successful re-authentication earlier in the session also authorises it.
    fn take_authorisation(&mut self) -> bool {
        let once = std::mem::replace(&mut self.reauth_ok, false);
        once || (!self.config().faceid_each_open && self.reauth_session)
    }

    /// Whether opening an item needs Face ID right now.
    pub fn reauth_required(&self) -> bool {
        self.config().faceid_each_open || !self.reauth_session
    }

    /// 15 wrong admin passwords: destroy the vault (the platform then deletes the Secure Enclave
    /// key and Keychain items). Everything is gone, including the audit log.
    fn terminate(&mut self) {
        self.panic_wipe();
    }

    /// Password + code (typed into the fields) + pepper from Face ID (None if Face ID failed).
    ///
    /// Every failure counts toward the lockout. Only a wrong *password* counts toward termination,
    /// and a password can only be tested once Face ID has released the pepper, so someone without
    /// the owner's face cannot advance it. The failed factor is recorded in the audit log
    /// (extra: 1 password, 3 code, 4 Face ID); the screen only ever says "authentication failed".
    pub fn login(&mut self, pepper: Option<Secret32>, now: impl Into<Now>) -> LoginOutcome {
        let now = now.into();
        if self.sess.is_some() || !self.vault.exists() {
            return LoginOutcome::Incomplete;
        }
        let Some(store) = self.store.as_mut() else {
            self.pw1.clear();
            self.code.clear();
            return LoginOutcome::AuditUnavailable;
        };
        if let Some(secs) = store.lock_check(now) {
            self.pw1.clear();
            self.code.clear();
            return LoginOutcome::Locked { secs };
        }
        let require_totp = crate::config::Config::from_bytes(&store.st.config).effective().require_totp;
        if self.pw1.is_empty() || (require_totp && self.code.as_bytes().len() != CODE_CAP) {
            return LoginOutcome::Incomplete;
        }
        let last_step = store.st.last_step;
        let had_pepper = pepper.is_some();
        let mk = self.vault.unlock(self.pw1.as_bytes(), pepper.as_ref());
        let pepper_hash = pepper.as_ref().map(|p| sha256(p.as_bytes()));
        drop(pepper);
        let step = if require_totp {
            mk.as_ref()
                .and_then(|m| self.vault.totp_secret(m))
                .and_then(|t| crypto::totp_verify(&t, now.wall, self.code.as_str(), last_step))
        } else {
            // Configured "password + Face ID only": the code is not asked for.
            mk.as_ref().map(|_| last_step)
        };
        self.pw1.clear();
        self.code.clear();

        let failed_factor = match (had_pepper, mk.is_some()) {
            (false, _) => 4,
            (true, false) => 1,
            (true, true) => 3,
        };
        let store = self.store.as_mut().unwrap();
        if step.is_none() && failed_factor == 1 && store.register_pw_failure() >= TERMINATE_AT {
            self.terminate();
            return LoginOutcome::Terminated;
        }
        match (mk, step) {
            (Some(mk), Some(step)) => {
                store.register_success();
                store.st.last_step = step;
                match self.open_session(mk) {
                    Ok(()) => {
                        self.pepper_hash = pepper_hash;
                        LoginOutcome::Ok
                    }
                    Err(o) => {
                        if let Some(s) = self.store.as_mut() {
                            let _ = s.log(ev::LOGIN_FAIL, 2);
                        }
                        o
                    }
                }
            }
            _ => {
                let lock = store.register_failure(now);
                let _ = store.log(ev::LOGIN_FAIL, failed_factor);
                match lock {
                    Some(secs) => {
                        let _ = store.log(ev::LOCKOUT, secs);
                        LoginOutcome::FailedLocked { secs }
                    }
                    None => {
                        let _ = store.save_state();
                        LoginOutcome::Failed { attempts_left: store.attempts_left() }
                    }
                }
            }
        }
    }

    fn open_session(&mut self, mk: Secret32) -> Result<(), LoginOutcome> {
        let now = unix_now();
        let mut sess = Session::new(mk);
        let (dropped, shredded) = self.vault.load_index(&mut sess).map_err(|_| LoginOutcome::IndexFailed)?;
        let store = self.store.as_mut().ok_or(LoginOutcome::AuditUnavailable)?;
        store.st.session_start = now;
        if store.log(ev::LOGIN_OK, 0).is_err() {
            store.st.session_start = 0;
            return Err(LoginOutcome::AuditUnavailable);
        }
        let mut sum = Summary { dropped: dropped as u32, shredded: shredded as u32, ..Summary::default() };
        if let Ok((entries, chain)) = store.read() {
            let oks: Vec<_> = entries.iter().filter(|e| e.ev == ev::LOGIN_OK).collect();
            if oks.len() >= 2 {
                let prev = oks[oks.len() - 2];
                sum.last_login = prev.ts;
                sum.fails_since =
                    entries.iter().filter(|e| e.seq > prev.seq && e.ev == ev::LOGIN_FAIL).count() as u32;
            }
            match chain {
                Chain::Intact => {}
                Chain::Broken(n) => {
                    sum.chain = 1;
                    sum.chain_at = n;
                }
                Chain::Truncated => sum.chain = 2,
            }
        }
        self.summary = sum;
        self.sess = Some(sess);
        self.sess_start = now;
        Ok(())
    }

    // ------------------------------------------------------------ vault contents

    pub fn items(&self) -> &[crate::vault::Item] {
        self.sess.as_ref().map_or(&[], |s| &s.items)
    }

    /// Re-authentication before a decrypt: the platform passes the pepper the Secure Enclave
    /// returned after Face ID (None if Face ID did not match). Failures count toward the same
    /// lockout as logins; reaching a lockout ends the session (as in the Windows build).
    pub fn reauth(&mut self, pepper: Option<&[u8]>, now: impl Into<Now>) -> ReauthOutcome {
        let now = now.into();
        self.reauth_ok = false;
        let (Some(want), true) = (self.pepper_hash, self.sess.is_some()) else {
            return ReauthOutcome::NoSession;
        };
        if self.locked_remaining(now).is_some() {
            self.lock(LockReason::Logout);
            return ReauthOutcome::LockedOut;
        }
        let ok = pepper.is_some_and(|p| p.len() == 32 && crypto::ct_eq(&sha256(p), &want));
        if ok {
            self.reauth_ok = true;
            self.reauth_session = true;
            return ReauthOutcome::Ok;
        }
        let Some(store) = self.store.as_mut() else { return ReauthOutcome::NoSession };
        let lock = store.register_failure(now);
        let _ = store.log(ev::REAUTH_FAIL, 0);
        match lock {
            Some(secs) => {
                let _ = store.log(ev::LOCKOUT, secs);
                self.lock(LockReason::Logout);
                ReauthOutcome::LockedOut
            }
            None => {
                let _ = store.save_state();
                ReauthOutcome::Bad { attempts_left: store.attempts_left() }
            }
        }
    }

    /// Encrypt a file (opened in place from the Files app) into the vault. The original is left
    /// for the platform to delete through the file provider if the user asks.
    pub fn import_file(&mut self, path: &std::path::Path) -> crate::util::Res<crate::vault::Item> {
        let sess = self.sess.as_mut().ok_or("vault is locked")?;
        let (item, _) = self.vault.add_file(sess, path, false)?;
        self.audit(ev::FILE_ENC);
        Ok(item)
    }

    /// Encrypt bytes already in memory (camera capture, photo library) into the vault.
    pub fn import_bytes(&mut self, name: &str, bytes: &[u8], photo: bool) -> crate::util::Res<crate::vault::Item> {
        let sess = self.sess.as_mut().ok_or("vault is locked")?;
        let mut src = bytes;
        let item = self.vault.add_stream(sess, name, &mut src)?;
        self.audit(if photo { ev::PHOTO_ENC } else { ev::FILE_ENC });
        Ok(item)
    }

    /// Decrypt a file into locked memory for the viewer. Consumes the re-authentication.
    pub fn view_open(&mut self, id: &[u8; 16]) -> Result<usize, ViewErr> {
        let authorised = self.take_authorisation();
        self.view = None;
        let sess = self.sess.as_ref().ok_or(ViewErr::NoSession)?;
        if !authorised {
            return Err(ViewErr::NotAuthorised);
        }
        let item = sess.get(id).ok_or(ViewErr::NotFound)?.clone();
        if item.kind != crate::vault::Kind::File {
            return Err(ViewErr::IsMessage);
        }
        if item.size > crate::vault::VIEW_CAP {
            return Err(ViewErr::TooLarge);
        }
        let buf = match self.vault.open_file(sess, &item) {
            Ok(b) => b,
            Err(_) => {
                self.audit(ev::FILE_DEC_FAIL);
                return Err(ViewErr::Integrity);
            }
        };
        let n = buf.as_bytes().len();
        self.view = Some(buf);
        self.audit(ev::FILE_DEC);
        Ok(n)
    }

    pub fn view_bytes(&self) -> Option<&[u8]> {
        self.view.as_ref().map(|v| v.as_bytes())
    }

    pub fn view_close(&mut self) {
        self.view = None;
    }

    /// Permanently destroy one item.
    pub fn purge(&mut self, id: &[u8; 16]) -> bool {
        let Some(sess) = self.sess.as_mut() else { return false };
        let Some(kind) = sess.get(id).map(|i| i.kind) else { return false };
        if self.vault.purge(sess, id).is_err() {
            return false;
        }
        self.audit(if kind == crate::vault::Kind::Msg { ev::MSG_PURGE } else { ev::FILE_PURGE });
        // its tags go with it
        if let Ok(t) = self.tags_state() {
            if t.set_many_off(id) {
                let _ = self.tags_save();
            }
        }
        true
    }

    // ------------------------------------------------------------ tags

    fn tags_key(&self) -> Option<Secret32> {
        self.sess.as_ref().map(|s| crypto::hkdf(s.mk.as_bytes(), b"scytale/v1", b"tags"))
    }

    /// Load the sealed tag set (or start empty); assignments for vanished items are dropped.
    fn tags_state(&mut self) -> Result<&mut crate::tags::Tags, i32> {
        if self.tags.is_none() {
            let key = self.tags_key().ok_or(-1)?;
            let path = self.vault.dir.join("tags.scy");
            let mut t = match std::fs::read(&path) {
                Ok(raw) => {
                    let pt = crypto::open(key.as_bytes(), b"scytale/tags", &raw).ok_or(-2)?;
                    crate::tags::Tags::from_bytes(&pt).ok_or(-2)?
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => crate::tags::Tags::default(),
                Err(_) => return Err(-2),
            };
            let live: Vec<[u8; 16]> = self.items().iter().map(|i| i.id).collect();
            let changed = t.retain_items(&live);
            self.tags = Some(t);
            if changed {
                self.tags_save()?;
            }
        }
        Ok(self.tags.as_mut().unwrap())
    }

    fn tags_save(&mut self) -> Result<(), i32> {
        let key = self.tags_key().ok_or(-1)?;
        let bytes = self.tags.as_ref().ok_or(-1)?.to_bytes();
        let sealed = crypto::seal(key.as_bytes(), b"scytale/tags", &bytes);
        crate::util::write_atomic(&self.vault.dir.join("tags.scy"), &sealed).map_err(|_| -3)
    }

    /// The whole tag set, serialised (definitions and assignments) for the interface.
    pub fn tags_bytes(&mut self) -> Result<zeroize::Zeroizing<Vec<u8>>, i32> {
        Ok(self.tags_state()?.to_bytes())
    }

    pub fn tag_create(&mut self, name: &str, color: u8) -> Result<u16, i32> {
        let id = self.tags_state()?.create(name, color).map_err(|e| e as i32)?;
        self.tags_save()?;
        Ok(id)
    }

    pub fn tag_update(&mut self, id: u16, name: &str, color: u8) -> Result<(), i32> {
        self.tags_state()?.update(id, name, color).map_err(|e| e as i32)?;
        self.tags_save()
    }

    pub fn tag_delete(&mut self, id: u16) -> Result<(), i32> {
        if !self.tags_state()?.delete(id) {
            return Err(crate::tags::TagErr::NoSuchTag as i32);
        }
        self.tags_save()
    }

    /// Tag or untag a file in the vault.
    pub fn tag_set(&mut self, item: &[u8; 16], id: u16, on: bool) -> Result<(), i32> {
        if !self.items().iter().any(|i| &i.id == item) {
            return Err(-5);
        }
        self.tags_state()?.set(item, id, on).map_err(|e| e as i32)?;
        self.tags_save()
    }

    // ------------------------------------------------------------ messages

    /// Seal a burn-after-reading message.
    pub fn msg_seal(&mut self, text: &[u8]) -> bool {
        let Some(sess) = self.sess.as_mut() else { return false };
        if self.vault.add_message(sess, text).is_err() {
            return false;
        }
        self.audit(ev::MSG_ENC);
        true
    }

    /// Open a message once (needs re-authentication). It is destroyed on disk *before* its text is
    /// made available; the text is held in locked memory like an open file.
    pub fn msg_open(&mut self, id: &[u8; 16]) -> Result<usize, ViewErr> {
        let authorised = self.take_authorisation();
        self.view = None;
        let sess = self.sess.as_mut().ok_or(ViewErr::NoSession)?;
        if !authorised {
            return Err(ViewErr::NotAuthorised);
        }
        if sess.get(id).map(|i| i.kind) != Some(crate::vault::Kind::Msg) {
            return Err(ViewErr::NotFound);
        }
        let buf = self.vault.open_and_destroy_message(sess, id).map_err(|_| ViewErr::Integrity)?;
        let n = buf.as_bytes().len();
        self.view = Some(buf);
        self.audit(ev::MSG_DEC);
        Ok(n)
    }

    // ------------------------------------------------------------ courier

    fn courier_path(&self) -> std::path::PathBuf {
        self.vault.dir.join("courier.scy")
    }

    fn courier_key(&self) -> Option<Secret32> {
        self.sess.as_ref().map(|s| crypto::hkdf(s.mk.as_bytes(), b"scytale/v1", b"courier"))
    }

    /// Load the sealed courier state (or start empty). Vault must be open.
    fn courier(&mut self) -> Result<&mut crate::courier::State, i32> {
        if self.courier.is_none() {
            let key = self.courier_key().ok_or(-1)?;
            let state = match std::fs::read(self.courier_path()) {
                Ok(raw) => {
                    let pt = crypto::open(key.as_bytes(), b"scytale/courier-state", &raw).ok_or(-2)?;
                    crate::courier::State::from_bytes(&pt).map_err(|_| -2)?
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => crate::courier::State::default(),
                Err(_) => return Err(-2),
            };
            self.courier = Some(state);
        }
        Ok(self.courier.as_mut().unwrap())
    }

    fn courier_save(&mut self) -> Result<(), i32> {
        let key = self.courier_key().ok_or(-1)?;
        let bytes = self.courier.as_ref().ok_or(-1)?.to_bytes();
        let sealed = crypto::seal(key.as_bytes(), b"scytale/courier-state", &bytes);
        crate::util::write_atomic(&self.courier_path(), &sealed).map_err(|_| -3)
    }

    /// (paired, verified, one-time keys left for sending, own one-time keys outstanding)
    pub fn courier_status(&mut self) -> Result<(bool, bool, usize, usize), i32> {
        let c = self.courier()?;
        Ok((
            c.peer.is_some(),
            c.peer.as_ref().is_some_and(|p| p.verified),
            c.peer_prekeys_left(),
            c.own_prekeys_unused(),
        ))
    }

    /// Export this device's signed key bundle into the output buffer.
    pub fn courier_export_bundle(&mut self) -> Result<usize, i32> {
        let text = self.courier()?.export_bundle(unix_now());
        self.courier_save()?;
        self.audit(ev::COURIER_BUNDLE);
        self.courier_out = text.into_bytes();
        Ok(self.courier_out.len())
    }

    /// Import the other device's bundle. Returns the safety number to compare.
    pub fn courier_import_bundle(&mut self, input: &[u8]) -> Result<String, i32> {
        let r = self.courier()?.import_bundle(input);
        match r {
            Ok(n) => {
                self.courier_save()?;
                self.audit(ev::COURIER_PAIR);
                Ok(n)
            }
            Err(e) => {
                self.audit_extra(ev::COURIER_REJECT, e as u64);
                Err(e as i32)
            }
        }
    }

    pub fn courier_safety_number(&mut self) -> Option<String> {
        self.courier().ok()?.safety_number()
    }

    /// The user compared the safety numbers on both screens and they match.
    pub fn courier_verify(&mut self) -> bool {
        let ok = self.courier().map(|c| c.verify_peer()).unwrap_or(false);
        if ok && self.courier_save().is_ok() {
            self.audit(ev::COURIER_VERIFY);
            return true;
        }
        false
    }

    pub fn courier_unpair(&mut self) -> bool {
        if self.courier().map(|c| c.unpair()).is_err() || self.courier_save().is_err() {
            return false;
        }
        self.audit(ev::COURIER_UNPAIR);
        true
    }

    /// Seal a message for the paired device. The used one-time key is recorded on disk before
    /// the envelope is released. Output: armored text, or the raw .scy file bytes.
    pub fn courier_send(&mut self, text: &[u8], burn: bool, armored: bool) -> Result<usize, i32> {
        let env = self.courier()?.seal(text, burn, unix_now()).map_err(|e| e as i32)?;
        self.courier_save()?;
        self.audit_extra(ev::COURIER_SEND, u64::from(burn));
        self.courier_out = if armored { crate::courier::armor_message(&env).into_bytes() } else { env };
        Ok(self.courier_out.len())
    }

    pub fn courier_out(&self) -> &[u8] {
        &self.courier_out
    }

    /// Open a message from the paired device (needs re-authentication). Its one-time key is
    /// destroyed and saved before the text is made available (in the view buffer). If the sender
    /// did not ask for destruction, the message is also kept in the vault as a text file.
    /// Returns the sender's destroy-on-receipt flag.
    pub fn courier_receive(&mut self, input: &[u8]) -> Result<bool, i32> {
        let authorised = self.take_authorisation();
        self.view = None;
        if self.sess.is_none() {
            return Err(-1);
        }
        if !authorised {
            return Err(-4);
        }
        let got = match self.courier()?.open(input) {
            Ok(g) => g,
            Err(e) => {
                self.audit_extra(ev::COURIER_REJECT, e as u64);
                return Err(e as i32);
            }
        };
        // Forward secrecy is committed to disk before anything is shown.
        self.courier_save()?;
        if !got.burn {
            let name = format!("Received message {}.txt", crate::courier_name_stamp(got.created));
            let sess = self.sess.as_mut().ok_or(-1)?;
            let mut src: &[u8] = &got.text;
            self.vault.add_stream(sess, &name, &mut src).map_err(|_| -3)?;
        }
        let mut buf = SecretInput::new(crate::courier::TEXT_CAP + 16);
        use std::io::Write as _;
        buf.write_all(&got.text).map_err(|_| -3)?;
        self.view = Some(buf);
        self.audit_extra(ev::COURIER_RECV, u64::from(got.burn));
        Ok(got.burn)
    }

    // ------------------------------------------------------------ audit / login log

    /// Load the audit log for display (vault must be open). Returns the entry count.
    pub fn audit_load(&mut self) -> usize {
        self.audit_cache = None;
        if self.sess.is_none() {
            return 0;
        }
        let Some(r) = self.store.as_ref().and_then(|s| s.read().ok()) else { return 0 };
        let n = r.0.len();
        self.audit_cache = Some(r);
        n
    }

    pub fn audit_entry(&self, i: usize) -> Option<&crate::audit::Entry> {
        self.audit_cache.as_ref().and_then(|(e, _)| e.get(i))
    }

    /// 0 intact, 1 broken at the returned entry, 2 truncated, -1 not loaded.
    pub fn audit_chain(&self) -> (i32, u64) {
        match self.audit_cache.as_ref().map(|(_, c)| c) {
            Some(Chain::Intact) => (0, 0),
            Some(Chain::Broken(n)) => (1, *n),
            Some(Chain::Truncated) => (2, 0),
            None => (-1, 0),
        }
    }

    // ------------------------------------------------------------ session end

    /// End the session: log why and for how long, wipe keys and every input buffer.
    pub fn lock(&mut self, why: LockReason) {
        if self.sess.is_some() {
            let dur = unix_now().saturating_sub(self.sess_start);
            if let Some(s) = self.store.as_mut() {
                let _ = s.log(why.event(), dur);
                s.st.session_start = 0;
                let _ = s.save_state();
            }
        }
        self.sess = None; // keys are zeroized on drop
        self.sess_start = 0;
        self.view = None; // decrypted file zeroized on drop
        self.courier = None; // identity and one-time keys zeroized on drop
        self.tags = None;
        self.courier_out.clear();
        self.audit_cache = None;
        self.reauth_ok = false;
        self.reauth_session = false;
        self.config_ok = false;
        self.pepper_hash = None;
        // an un-saved recovery key is dropped too: the vault still opens with the password
        self.pending = None;
        self.recover_mk = None;
        self.summary = Summary::default();
        self.clear_all();
    }

    /// Record a security event that does not end the session (e.g. a screenshot was taken).
    pub fn audit(&mut self, event: &str) -> bool {
        self.audit_extra(event, 0)
    }

    pub fn audit_extra(&mut self, event: &str, extra: u64) -> bool {
        self.store.as_mut().is_some_and(|s| s.log(event, extra).is_ok())
    }

    /// Destroy everything. The platform deletes the Secure Enclave key and Keychain items first.
    /// Returns the number of files that could not be erased.
    pub fn panic_wipe(&mut self) -> usize {
        self.tags = None;
        self.courier = None;
        self.courier_out.clear();
        self.view = None;
        self.audit_cache = None;
        self.reauth_ok = false;
        self.reauth_session = false;
        self.config_ok = false;
        self.pepper_hash = None;
        self.sess = None;
        self.store = None;
        self.pending = None;
        self.recover_mk = None;
        self.clear_all();
        self.vault.destroy_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn tmpdir(n: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("scytale-ios-ctl-{n}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    const PW: &str = "correct horse battery staple";

    /// Full setup through the controller, with a fake Secure Enclave (wrap = identity marker).
    fn set_up(n: &str) -> (Core, PathBuf, Vec<u8>, Zeroizing<Vec<u8>>, String) {
        let d = tmpdir(n);
        let mut c = Core::new(Vault::new(d.join("vault")));
        assert_eq!(c.start(None).0, StartNote::NeedsSetup);
        assert_eq!(c.phase(), Phase::Setup);

        c.push(Field::Pw1, "short");
        c.push(Field::Pw2, "short");
        assert_eq!(c.setup_begin(false), Err(PwErr::Weak));
        c.push(Field::Pw1, "aaaaaaaaaaaaaaaaaaaa");
        c.push(Field::Pw2, "aaaaaaaaaaaaaaaaaaaa");
        assert_eq!(c.setup_begin(false), Err(PwErr::Weak), "needs variety");
        c.push(Field::Pw1, PW);
        c.push(Field::Pw2, "correct horse battery stapleX");
        assert_eq!(c.setup_begin(false), Err(PwErr::Mismatch));
        c.push(Field::Pw1, PW);
        c.push(Field::Pw2, PW);
        assert_eq!(c.setup_begin(false), Ok(()));

        let (w, mods) = c.setup_qr().unwrap();
        assert_eq!(mods.len(), w * w);
        let secret_txt = c.setup_secret_text().unwrap().to_string();
        let totp = Zeroizing::new(BASE32_NOPAD.decode(secret_txt.replace(' ', "").as_bytes()).unwrap());

        let pepper = c.setup_pepper().unwrap().to_vec();
        assert!(!c.setup_pepper_verify(&[0u8; 32]));
        assert_eq!(c.setup_commit(b"wrapped", Some(Secret32::random())), Err(CommitErr::NotReady));
        assert!(c.setup_pepper_verify(&pepper));

        let now = unix_now();
        c.push(Field::Code, &format!("{:06}", crypto::totp_code(&totp, now / 30 + 100)));
        assert!(!c.setup_code(now), "a code from a different time window is rejected");
        c.push(Field::Code, &format!("{:06}", crypto::totp_code(&totp, now / 30)));
        assert!(c.setup_code(now));
        let audit_key = Secret32::from_slice(&[3; 32]);
        c.setup_commit(b"wrapped", Some(audit_key)).unwrap();
        assert_eq!(c.phase(), Phase::Unlocked);
        let rk = c.setup_recovery_text().unwrap().to_string();
        assert_eq!(rk.replace(' ', "").len(), 52);
        c.setup_finish();
        assert!(c.setup_recovery_text().is_none());
        (c, d, pepper, totp, rk)
    }

    fn code_at(totp: &[u8], t: u64) -> String {
        format!("{:06}", crypto::totp_code(totp, t / 30))
    }

    #[test]
    fn setup_login_lockout_and_lock() {
        let (mut c, d, pepper, totp, _) = set_up("login");
        assert_eq!(c.vault.wrapped_pepper().unwrap(), b"wrapped");
        c.lock(LockReason::Background);
        assert_eq!(c.phase(), Phase::Login);

        // restart: the note says why the last session ended
        let mut c = Core::new(Vault::new(d.join("vault")));
        assert_eq!(c.start(Some(Secret32::from_slice(&[3; 32]))).0, StartNote::PrevBackground);

        let p = || Some(Secret32::from_slice(&pepper));
        let t0 = unix_now() + 300;
        assert_eq!(c.login(p(), t0), LoginOutcome::Incomplete);

        // wrong password, Face ID refused, wrong code: each costs an attempt
        c.push(Field::Pw1, "wrong password!!");
        c.push(Field::Code, &code_at(&totp, t0));
        assert_eq!(c.login(p(), t0), LoginOutcome::Failed { attempts_left: 2 });
        c.push(Field::Pw1, PW);
        c.push(Field::Code, &code_at(&totp, t0));
        assert_eq!(c.login(None, t0), LoginOutcome::Failed { attempts_left: 1 });
        c.push(Field::Pw1, PW);
        c.push(Field::Code, "123456");
        assert_eq!(c.login(p(), t0), LoginOutcome::FailedLocked { secs: 30 });
        c.push(Field::Pw1, PW);
        c.push(Field::Code, &code_at(&totp, t0));
        assert_eq!(c.login(p(), t0 + 5), LoginOutcome::Locked { secs: 25 });

        // after the lockout: correct password + code + pepper
        let t1 = t0 + 60;
        c.push(Field::Pw1, PW);
        c.push(Field::Code, &code_at(&totp, t1));
        assert_eq!(c.login(p(), t1), LoginOutcome::Ok);
        assert_eq!(c.phase(), Phase::Unlocked);
        assert_eq!(c.summary.fails_since, 3);
        assert_eq!(c.summary.chain, 0);

        // the same code cannot be used twice
        c.lock(LockReason::Logout);
        c.push(Field::Pw1, PW);
        c.push(Field::Code, &code_at(&totp, t1));
        assert_eq!(c.login(p(), t1), LoginOutcome::Failed { attempts_left: 2 });
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn inputs_are_filtered_and_wiped() {
        let d = tmpdir("input");
        let mut c = Core::new(Vault::new(d.join("vault")));
        assert!(!c.push(Field::Code, "12a"));
        assert_eq!(c.count(Field::Code), 2);
        c.push(Field::Code, "34567");
        assert_eq!(c.count(Field::Code), 6, "code is capped at 6 digits");
        c.push(Field::Pw1, "pässwörd\u{7}");
        assert_eq!(c.count(Field::Pw1), 8, "control characters dropped, unicode counted by char");
        c.backspace(Field::Pw1);
        assert_eq!(c.count(Field::Pw1), 7);
        c.lock(LockReason::Logout);
        assert_eq!(c.count(Field::Pw1) + c.count(Field::Code), 0);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn recovery_rekeys_everything() {
        let (mut c, d, old_pepper, old_totp, rk) = set_up("recover");
        c.lock(LockReason::Logout);
        let mut c = Core::new(Vault::new(d.join("vault")));
        // audit key lost: login is impossible, recovery still works
        assert_eq!(c.start(None).0, StartNote::AuditKeyMissing);
        c.push(Field::Pw1, PW);
        c.push(Field::Code, "123456");
        assert_eq!(c.login(Some(Secret32::from_slice(&old_pepper)), unix_now()), LoginOutcome::AuditUnavailable);

        c.push(Field::Rk, "AAAA BBBB");
        assert!(!c.recover_check());
        assert_eq!(c.setup_begin(true), Err(PwErr::WrongState));
        c.push(Field::Rk, &rk.to_lowercase());
        assert!(c.recover_check(), "recovery key is case- and space-insensitive");

        let new_pw = "a completely different passphrase";
        c.push(Field::Pw1, new_pw);
        c.push(Field::Pw2, new_pw);
        c.setup_begin(true).unwrap();
        let new_totp =
            Zeroizing::new(BASE32_NOPAD.decode(c.setup_secret_text().unwrap().replace(' ', "").as_bytes()).unwrap());
        assert_ne!(&new_totp[..], &old_totp[..]);
        let new_pepper = c.setup_pepper().unwrap().to_vec();
        assert!(c.setup_pepper_verify(&new_pepper));
        let now = unix_now();
        c.push(Field::Code, &code_at(&new_totp, now));
        assert!(c.setup_code(now));
        c.setup_commit(b"wrapped-2", Some(Secret32::from_slice(&[4; 32]))).unwrap();
        let new_rk = c.setup_recovery_text().unwrap().to_string();
        assert_ne!(new_rk, rk);
        c.setup_finish();
        c.lock(LockReason::Logout);

        // old credentials are dead, new ones work
        let mut c = Core::new(Vault::new(d.join("vault")));
        assert_eq!(c.start(Some(Secret32::from_slice(&[4; 32]))).0, StartNote::None);
        let t = now + 120;
        c.push(Field::Pw1, PW);
        c.push(Field::Code, &code_at(&new_totp, t));
        assert!(matches!(c.login(Some(Secret32::from_slice(&old_pepper)), t), LoginOutcome::Failed { .. }));
        c.push(Field::Pw1, new_pw);
        c.push(Field::Code, &code_at(&new_totp, t + 30));
        assert_eq!(c.login(Some(Secret32::from_slice(&new_pepper)), t + 30), LoginOutcome::Ok);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn import_reauth_view_purge() {
        let (mut c, d, pepper, _, _) = set_up("contents");
        // camera / photo bytes and a file from "Files"
        let photo: Vec<u8> = (0..300_000u32).map(|i| (i * 13 % 251) as u8).collect();
        let p = c.import_bytes("Camera 2026-11-20.heic", &photo, true).unwrap();
        let src = d.join("report.pdf");
        fs::write(&src, b"%PDF-1.7 test").unwrap();
        let f = c.import_file(&src).unwrap();
        assert!(src.exists(), "original is left for the platform to delete");
        assert_eq!(c.items().len(), 2);

        // viewing needs a fresh re-authentication each time
        assert_eq!(c.view_open(&p.id), Err(ViewErr::NotAuthorised));
        assert_eq!(c.reauth(Some(&pepper), unix_now()), ReauthOutcome::Ok);
        assert_eq!(c.view_open(&p.id), Ok(photo.len()));
        assert_eq!(c.view_bytes().unwrap(), &photo[..]);
        c.view_close();
        assert!(c.view_bytes().is_none());
        assert_eq!(c.view_open(&f.id), Err(ViewErr::NotAuthorised), "one reauth = one decrypt");

        // wrong pepper (Face ID mismatch) counts; the third failure ends the session
        let t = unix_now();
        assert_eq!(c.reauth(Some(&[0u8; 32]), t), ReauthOutcome::Bad { attempts_left: 2 });
        assert_eq!(c.reauth(None, t), ReauthOutcome::Bad { attempts_left: 1 });
        assert_eq!(c.reauth(Some(&pepper), t), ReauthOutcome::Ok);
        assert_eq!(c.view_open(&f.id), Ok(13));
        assert_eq!(c.view_bytes().unwrap(), b"%PDF-1.7 test");

        // locking wipes the open file
        assert!(c.purge(&p.id));
        assert_eq!(c.items().len(), 1);
        assert!(!c.purge(&p.id), "already gone");
        c.lock(LockReason::Background);
        assert!(c.view_bytes().is_none());
        assert!(c.items().is_empty());
        assert_eq!(c.reauth(Some(&pepper), t), ReauthOutcome::NoSession);
        let _ = fs::remove_dir_all(&d);
    }

    /// Fresh Core after a lock, as at app start, with lockouts expired by moving time forward.
    fn restart(d: &PathBuf) -> Core {
        let mut c = Core::new(Vault::new(d.join("vault")));
        c.start(Some(Secret32::from_slice(&[3; 32])));
        c
    }

    #[test]
    fn termination_after_15_wrong_passwords_code_and_face_exempt() {
        let (mut c, d, pepper, totp, _) = set_up("terminate");
        c.lock(LockReason::Logout);
        let mut c = restart(&d);
        let p = || Some(Secret32::from_slice(&pepper));
        // far apart in time so every lockout has expired (same boot)
        let mut t = unix_now() + 10_000;
        let mut attempt = |c: &mut Core, pw: &str, code: String, pepper: Option<Secret32>| {
            t += 4_000;
            c.push(Field::Pw1, pw);
            c.push(Field::Code, &code);
            c.login(pepper, t)
        };

        // wrong codes and Face ID mismatches never count toward termination
        for _ in 0..6 {
            let o = attempt(&mut c, PW, "000000".into(), p());
            assert!(matches!(o, LoginOutcome::Failed { .. } | LoginOutcome::FailedLocked { .. }));
            let o = attempt(&mut c, "wrong password!!", code_at(&totp, 0), None);
            assert!(matches!(o, LoginOutcome::Failed { .. } | LoginOutcome::FailedLocked { .. }));
        }
        assert_eq!(c.termination_level(), 0);

        // wrong passwords (Face ID matched) count: warnings at 5 and 10, destruction at 15
        for n in 1..=14u32 {
            let o = attempt(&mut c, "wrong password!!", "123456".into(), p());
            assert_ne!(o, LoginOutcome::Terminated);
            let want = if n >= 10 { 2 } else if n >= 5 { 1 } else { 0 };
            assert_eq!(c.termination_level(), want, "after {n} wrong passwords");
        }
        // the counter survives a restart
        let mut c = restart(&d);
        assert_eq!(c.termination_level(), 2);
        assert_eq!(attempt(&mut c, "wrong password!!", "123456".into(), p()), LoginOutcome::Terminated);
        assert!(!d.join("vault").exists(), "vault destroyed");
        assert_eq!(c.phase(), Phase::Setup);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn successful_login_resets_termination_counter() {
        let (mut c, d, pepper, totp, _) = set_up("term-reset");
        c.lock(LockReason::Logout);
        let mut c = restart(&d);
        let mut t = unix_now() + 10_000;
        for _ in 0..7 {
            t += 4_000;
            c.push(Field::Pw1, "wrong password!!");
            c.push(Field::Code, "123456");
            c.login(Some(Secret32::from_slice(&pepper)), t);
        }
        assert_eq!(c.termination_level(), 1);
        t += 4_000;
        c.push(Field::Pw1, PW);
        c.push(Field::Code, &code_at(&totp, t));
        assert_eq!(c.login(Some(Secret32::from_slice(&pepper)), t), LoginOutcome::Ok);
        assert_eq!(c.termination_level(), 0);
        // the log records which factor failed
        assert!(c.audit_load() > 0);
        let fails: Vec<u64> = (0..)
            .map_while(|i| c.audit_entry(i).cloned())
            .filter(|e| e.ev == ev::LOGIN_FAIL)
            .map(|e| e.extra)
            .collect();
        assert_eq!(fails, vec![1; 7]);
        assert_eq!(c.audit_chain().0, 0);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn messages_are_single_read() {
        let (mut c, d, pepper, _, _) = set_up("messages");
        assert!(c.msg_seal("the code is 4417".as_bytes()));
        let id = c.items().iter().find(|i| i.kind == crate::vault::Kind::Msg).unwrap().id;
        assert_eq!(c.msg_open(&id), Err(ViewErr::NotAuthorised));
        assert_eq!(c.reauth(Some(&pepper), unix_now()), ReauthOutcome::Ok);
        assert_eq!(c.msg_open(&id), Ok(16));
        assert_eq!(c.view_bytes().unwrap(), b"the code is 4417");
        assert!(c.items().is_empty(), "destroyed on open");
        assert_eq!(c.reauth(Some(&pepper), unix_now()), ReauthOutcome::Ok);
        assert_eq!(c.msg_open(&id), Err(ViewErr::NotFound));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn decrypt_refusal_and_reencrypt_are_logged() {
        let (mut c, d, pepper, _, _) = set_up("dec-log");
        let item = c.import_bytes("a.jpg", &[7u8; 5000], true).unwrap();
        // tamper with the stored blob
        let bp = d.join("vault").join("blobs").join(format!("{}.scy", data_encoding::HEXLOWER.encode(&item.id)));
        let mut b = fs::read(&bp).unwrap();
        let n = b.len() / 2;
        b[n] ^= 1;
        fs::write(&bp, b).unwrap();
        assert_eq!(c.reauth(Some(&pepper), unix_now()), ReauthOutcome::Ok);
        assert_eq!(c.view_open(&item.id), Err(ViewErr::Integrity));
        assert!(c.audit_extra(ev::FILE_REENC, 1));
        c.audit_load();
        let evs: Vec<(String, u64)> = (0..).map_while(|i| c.audit_entry(i).map(|e| (e.ev.clone(), e.extra))).collect();
        assert!(evs.iter().any(|(e, _)| e == ev::PHOTO_ENC));
        assert!(evs.iter().any(|(e, _)| e == ev::FILE_DEC_FAIL));
        assert!(evs.iter().any(|(e, x)| e == ev::FILE_REENC && *x == 1));
        assert!(!evs.iter().any(|(e, _)| e == ev::FILE_DEC), "a refused decrypt is not logged as a decrypt");
        let _ = fs::remove_dir_all(&d);
    }

    /// Two vaults (PC and iPhone) pair through the controller, exchange messages, and keep the
    /// courier state sealed across a lock/unlock.
    #[test]
    fn courier_between_two_vaults() {
        let (mut pc, d1, pepper1, totp1, _) = set_up("courier-pc");
        let (mut phone, d2, pepper2, _, _) = set_up("courier-phone");
        let take = |c: &Core| c.courier_out().to_vec();

        pc.courier_export_bundle().unwrap();
        let b_pc = take(&pc);
        phone.courier_export_bundle().unwrap();
        let b_phone = take(&phone);
        assert_eq!(phone.courier_import_bundle(&b_pc).unwrap(), pc.courier_import_bundle(&b_phone).unwrap());
        assert_eq!(pc.courier_send(b"hi", false, true), Err(crate::courier::Error::NotVerified as i32));
        assert!(pc.courier_verify() && phone.courier_verify());

        // PC -> phone, keep (stored in the phone's vault)
        pc.courier_send(b"keep this", false, true).unwrap();
        let env = take(&pc);
        assert_eq!(phone.courier_receive(&env), Err(-4), "needs re-authentication");
        assert_eq!(phone.reauth(Some(&pepper2), unix_now()), ReauthOutcome::Ok);
        assert_eq!(phone.courier_receive(&env), Ok(false));
        assert_eq!(phone.view_bytes().unwrap(), b"keep this");
        assert!(phone.items().iter().any(|i| i.name.starts_with("Received message ")));
        // phone -> PC, destroy on receipt (not stored), raw file form
        phone.courier_send(b"burn this", true, false).unwrap();
        let env2 = take(&phone);
        assert_eq!(pc.reauth(Some(&pepper1), unix_now()), ReauthOutcome::Ok);
        assert_eq!(pc.courier_receive(&env2), Ok(true));
        assert!(pc.items().is_empty(), "burn messages are never stored");

        // state survives lock + login (sealed on disk); replay still refused after reload
        pc.lock(LockReason::Logout);
        let mut pc = restart(&d1);
        let t = unix_now() + 120;
        pc.push(Field::Pw1, PW);
        pc.push(Field::Code, &code_at(&totp1, t));
        assert_eq!(pc.login(Some(Secret32::from_slice(&pepper1)), t), LoginOutcome::Ok);
        assert_eq!(pc.courier_status().unwrap(), (true, true, crate::courier::PREKEY_BATCH - 1, crate::courier::PREKEY_BATCH - 1));
        assert_eq!(pc.reauth(Some(&pepper1), unix_now()), ReauthOutcome::Ok);
        assert_eq!(pc.courier_receive(&env2), Err(crate::courier::Error::AlreadyOpened as i32));
        // the state file on disk is ciphertext
        let raw = fs::read(d1.join("vault").join("courier.scy")).unwrap();
        assert!(!raw.windows(5).any(|w| w == b"SCYC\x01"));
        assert!(pc.audit_load() > 0);
        let evs: Vec<String> = (0..).map_while(|i| pc.audit_entry(i).map(|e| e.ev.clone())).collect();
        for e in [ev::COURIER_BUNDLE, ev::COURIER_PAIR, ev::COURIER_VERIFY, ev::COURIER_SEND, ev::COURIER_RECV, ev::COURIER_REJECT] {
            assert!(evs.iter().any(|x| x == e), "{e} logged");
        }
        let _ = fs::remove_dir_all(&d1);
        let _ = fs::remove_dir_all(&d2);
    }

    #[test]
    fn configuration_is_guarded_persistent_and_enforced() {
        use crate::config::Config;
        let (mut c, d, pepper, totp, _) = set_up("config");
        assert_eq!(c.config(), Config::default());
        let relaxed = Config {
            custom: true,
            lock_on_leave: false,
            timeout_min: 30,
            require_totp: false,
            faceid_each_open: false,
            ..Config::default()
        };
        assert!(!c.set_config(relaxed), "needs the screen unlocked with Face ID");
        assert!(!c.config_begin(), "needs a fresh re-authentication");
        assert_eq!(c.reauth(Some(&pepper), unix_now()), ReauthOutcome::Ok);
        assert!(c.config_begin());
        assert!(!c.set_config(Config { timeout_min: 3, ..relaxed }), "invalid values refused");
        assert!(c.set_config(relaxed));
        c.config_end();

        // Face ID once per session: the earlier reauth now authorises later opens
        let item = c.import_bytes("a.txt", b"abc", false).unwrap();
        assert!(!c.reauth_required());
        assert_eq!(c.view_open(&item.id), Ok(3));
        assert_eq!(c.view_open(&item.id), Ok(3));

        // persists across lock + restart; login no longer needs the code
        c.lock(LockReason::Logout);
        let mut c = restart(&d);
        assert_eq!(c.config(), relaxed);
        let t = unix_now() + 120;
        c.push(Field::Pw1, PW);
        assert_eq!(c.login(Some(Secret32::from_slice(&pepper)), t), LoginOutcome::Ok, "password + Face ID only");
        assert!(c.reauth_required(), "a new session needs Face ID once again");

        // back to hardened: code required again, one reauth per open
        assert_eq!(c.reauth(Some(&pepper), unix_now()), ReauthOutcome::Ok);
        assert!(c.config_begin());
        assert!(c.set_config(Config { custom: false, ..relaxed }));
        assert_eq!(c.config(), Config::default());
        assert_eq!(c.config_stored().timeout_min, 30, "choices kept while hardened");
        c.lock(LockReason::Logout);
        let mut c = restart(&d);
        c.push(Field::Pw1, PW);
        assert_eq!(c.login(Some(Secret32::from_slice(&pepper)), t + 60), LoginOutcome::Incomplete, "code required again");
        // the typed password is kept on "incomplete"; only the code is added
        c.push(Field::Code, &code_at(&totp, t + 60));
        assert_eq!(c.login(Some(Secret32::from_slice(&pepper)), t + 60), LoginOutcome::Ok);

        // tampering with the state file reverts the configuration to hardened
        c.lock(LockReason::Logout);
        let st = d.join("vault").join("state.bin");
        let mut b = fs::read(&st).unwrap();
        b[96] ^= 0xff;
        fs::write(&st, b).unwrap();
        let c = restart(&d);
        assert_eq!(c.config(), Config::default());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn tags_are_sealed_persistent_and_follow_items() {
        let (mut c, d, pepper, totp, _) = set_up("tags");
        let a = c.import_bytes("vault export.csv", b"x", false).unwrap();
        let b = c.import_bytes("photo.heic", b"y", true).unwrap();
        let pw = c.tag_create("1password", 4).unwrap();
        let fin = c.tag_create("finance", 6).unwrap();
        assert_eq!(c.tag_create("1Password", 2).unwrap(), pw, "the saved tag is reused");
        c.tag_set(&a.id, pw, true).unwrap();
        c.tag_set(&a.id, fin, true).unwrap();
        c.tag_set(&b.id, fin, true).unwrap();
        assert_eq!(c.tag_set(&[0u8; 16], pw, true), Err(-5), "unknown item");
        // sealed on disk: the name never appears in clear
        let raw = fs::read(d.join("vault").join("tags.scy")).unwrap();
        assert!(!raw.windows(9).any(|w| w == b"1password"));
        // survives lock + login
        c.lock(LockReason::Logout);
        let mut c = restart(&d);
        let t = unix_now() + 120;
        c.push(Field::Pw1, PW);
        c.push(Field::Code, &code_at(&totp, t));
        assert_eq!(c.login(Some(Secret32::from_slice(&pepper)), t), LoginOutcome::Ok);
        let tags = crate::tags::Tags::from_bytes(&c.tags_bytes().unwrap()).unwrap();
        assert_eq!(tags.defs.iter().find(|x| x.id == pw).unwrap().color, 2);
        assert_eq!(tags.of(&a.id), &[pw, fin]);
        // destroying an item removes its tags; deleting a tag removes it everywhere
        assert!(c.purge(&a.id));
        let tags = crate::tags::Tags::from_bytes(&c.tags_bytes().unwrap()).unwrap();
        assert!(tags.of(&a.id).is_empty());
        c.tag_delete(fin).unwrap();
        let tags = crate::tags::Tags::from_bytes(&c.tags_bytes().unwrap()).unwrap();
        assert!(tags.of(&b.id).is_empty() && tags.defs.len() == 1);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn reauth_lockout_ends_session() {
        let (mut c, d, _, _, _) = set_up("reauth-lock");
        let t = unix_now();
        assert_eq!(c.reauth(None, t), ReauthOutcome::Bad { attempts_left: 2 });
        assert_eq!(c.reauth(None, t), ReauthOutcome::Bad { attempts_left: 1 });
        assert_eq!(c.reauth(None, t), ReauthOutcome::LockedOut);
        assert_eq!(c.phase(), Phase::Login);
        assert!(c.locked_remaining(t).is_some());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn tampered_state_locks_and_panic_wipe_destroys() {
        let (mut c, d, _, _, _) = set_up("wipe");
        c.lock(LockReason::Logout);
        let st = d.join("vault").join("state.bin");
        let mut b = fs::read(&st).unwrap();
        b[0] ^= 0xff;
        fs::write(&st, b).unwrap();
        let mut c = Core::new(Vault::new(d.join("vault")));
        assert_eq!(c.start(Some(Secret32::from_slice(&[3; 32]))).0, StartNote::StateReset);
        assert!(c.locked_remaining(crate::clock::now()).is_some());
        assert_eq!(c.panic_wipe(), 0);
        assert!(!d.join("vault").exists());
        assert_eq!(c.phase(), Phase::Setup);
        let _ = fs::remove_dir_all(&d);
    }
}
