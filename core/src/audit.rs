//! Audit log + login-lockout state. Ported from the Windows build; the HMAC key now comes from the
//! platform (an iOS Keychain item: this device only, never synced, never backed up) instead of a
//! DPAPI-protected file.
//!
//! The log records only an event code, a timestamp and (for logouts) a duration. Never names,
//! paths, sizes or content. Entries are chained with HMAC-SHA256, so edits, deletions and
//! truncation are detected.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use data_encoding::HEXLOWER;

use crate::{
    clock::Now,
    crypto::{self, hmac256},
    protect,
    secret::Secret32,
    util::{ioe, unix_now, write_atomic, Res},
};

pub const FREE_ATTEMPTS: u32 = 3;
const MAX_LOCK: u64 = 3600;

pub mod ev {
    pub const SETUP: &str = "SETUP";
    pub const LOGIN_OK: &str = "LOGIN_OK";
    pub const LOGIN_FAIL: &str = "LOGIN_FAIL";
    pub const LOCKOUT: &str = "LOCKOUT";
    pub const LOGOUT: &str = "LOGOUT";
    pub const TIMEOUT: &str = "TIMEOUT";
    pub const BACKGROUND: &str = "BACKGROUND";
    pub const DEVICE_LOCK: &str = "DEVICE_LOCK";
    pub const ABORTED: &str = "ABORTED";
    pub const REAUTH_FAIL: &str = "REAUTH_FAIL";
    pub const FILE_ENC: &str = "FILE_ENC";
    pub const PHOTO_ENC: &str = "PHOTO_ENC";
    pub const FILE_DEC: &str = "FILE_DEC";
    /// The decrypted copy was wiped (extra 0: Re-encrypt button, 1: automatic on lock).
    pub const FILE_REENC: &str = "FILE_REENC";
    /// Decryption refused: the blob failed authentication.
    pub const FILE_DEC_FAIL: &str = "FILE_DEC_FAIL";
    pub const FILE_PURGE: &str = "FILE_PURGE";
    pub const MSG_ENC: &str = "MSG_ENC";
    pub const MSG_DEC: &str = "MSG_DEC";
    pub const MSG_KILL: &str = "MSG_KILL";
    pub const MSG_EXPIRE: &str = "MSG_EXPIRE";
    pub const MSG_PURGE: &str = "MSG_PURGE";
    pub const PW_CHANGE: &str = "PW_CHANGE";
    pub const RECOVERY: &str = "RECOVERY";
    pub const RECOV_FAIL: &str = "RECOV_FAIL";
    pub const STATE_RESET: &str = "STATE_RESET";
    pub const SCREENSHOT: &str = "SCREENSHOT";
    pub const COURIER_BUNDLE: &str = "COURIER_BUNDLE";
    pub const COURIER_PAIR: &str = "COURIER_PAIR";
    pub const COURIER_VERIFY: &str = "COURIER_VERIFY";
    pub const COURIER_UNPAIR: &str = "COURIER_UNPAIR";
    pub const COURIER_SEND: &str = "COURIER_SEND";
    pub const COURIER_RECV: &str = "COURIER_RECV";
    pub const COURIER_REJECT: &str = "COURIER_REJECT";
    /// A vault file was decrypted and sealed for the paired device.
    pub const COURIER_SEND_FILE: &str = "COURIER_SEND_FILE";
    /// A file from the paired device was opened and encrypted into the vault.
    pub const COURIER_RECV_FILE: &str = "COURIER_RECV_FILE";
    pub const CAPTURE: &str = "CAPTURE";
    pub const CONFIG_CHANGE: &str = "CONFIG_CHANGE";
}

/// Wrong admin passwords (after Face ID matched) before the vault destroys itself.
pub const TERMINATE_AT: u32 = 15;
/// Value assumed for the termination counter when the state file is missing or tampered with.
const PW_FAILS_ON_RESET: u32 = 10;

#[derive(Clone, Copy, Default)]
pub struct State {
    pub fails: u32,
    pub locked_until: u64,
    pub last_step: u64,
    pub session_start: u64,
    pub seq: u64,
    pub mac: [u8; 32],
    // ---- v2
    /// Wrong admin passwords since the last successful login (authenticator codes are exempt).
    pub pw_fails: u32,
    /// Length of the current lockout (0 = none).
    pub lock_secs: u64,
    /// Lockout end on the monotonic clock of boot `boot_id`.
    pub lock_mono_until: u64,
    pub boot_id: u64,
    // ---- v3
    /// User configuration (see `Config`). Kept here so it is covered by the state HMAC: nobody can
    /// switch off a protection by editing a file.
    pub config: [u8; 8],
}

impl State {
    const LEN_V1: usize = 4 + 8 + 8 + 8 + 8 + 32;
    const LEN_V2: usize = Self::LEN_V1 + 4 + 8 + 8 + 8;
    const LEN: usize = Self::LEN_V2 + 8;

    fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(Self::LEN);
        v.extend_from_slice(&self.fails.to_le_bytes());
        v.extend_from_slice(&self.locked_until.to_le_bytes());
        v.extend_from_slice(&self.last_step.to_le_bytes());
        v.extend_from_slice(&self.session_start.to_le_bytes());
        v.extend_from_slice(&self.seq.to_le_bytes());
        v.extend_from_slice(&self.mac);
        v.extend_from_slice(&self.pw_fails.to_le_bytes());
        v.extend_from_slice(&self.lock_secs.to_le_bytes());
        v.extend_from_slice(&self.lock_mono_until.to_le_bytes());
        v.extend_from_slice(&self.boot_id.to_le_bytes());
        v.extend_from_slice(&self.config);
        v
    }

    /// Reads v2, and v1 from earlier builds (upgraded on the next save).
    fn from_bytes(b: &[u8]) -> Option<State> {
        if b.len() != Self::LEN && b.len() != Self::LEN_V2 && b.len() != Self::LEN_V1 {
            return None;
        }
        let u64_at = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&b[36..68]);
        let mut s = State {
            fails: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            locked_until: u64_at(4),
            last_step: u64_at(12),
            session_start: u64_at(20),
            seq: u64_at(28),
            mac,
            ..State::default()
        };
        if b.len() >= Self::LEN_V2 {
            s.pw_fails = u32::from_le_bytes(b[68..72].try_into().unwrap());
            s.lock_secs = u64_at(72);
            s.lock_mono_until = u64_at(80);
            s.boot_id = u64_at(88);
        }
        if b.len() == Self::LEN {
            s.config.copy_from_slice(&b[96..104]);
        }
        Some(s)
    }
}

#[derive(Clone)]
pub struct Entry {
    pub seq: u64,
    pub ts: u64,
    pub ev: String,
    pub extra: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Chain {
    Intact,
    Broken(u64),
    Truncated,
}

pub struct Store {
    dir: PathBuf,
    key: Secret32,
    pub st: State,
    /// The state file was missing or failed its integrity check at load.
    pub was_reset: bool,
}

fn chain_mac(key: &Secret32, prev: &[u8; 32], body: &str) -> [u8; 32] {
    hmac256(key.as_bytes(), &[b"log", prev, body.as_bytes()])
}

impl Store {
    fn p(dir: &Path, n: &str) -> PathBuf {
        dir.join(n)
    }

    /// First-time creation (called at setup) with a fresh random key held by the platform.
    pub fn create(dir: &Path, key: Secret32) -> Res<Store> {
        let s = Store { dir: dir.to_path_buf(), key, st: State::default(), was_reset: false };
        s.save_state()?;
        Ok(s)
    }

    /// The platform key is gone (or the log has no key): archive the old log, start a new chain.
    pub fn fresh(dir: &Path, key: Secret32) -> Res<Store> {
        for n in ["audit.log", "state.bin"] {
            let p = Self::p(dir, n);
            if p.exists() {
                let _ = fs::rename(&p, Self::p(dir, &format!("{n}.prev")));
            }
        }
        Self::create(dir, key)
    }

    pub fn load(dir: &Path, key: Secret32, now: impl Into<Now>) -> Res<Store> {
        let now = now.into();
        let mut s = Store { dir: dir.to_path_buf(), key, st: State::default(), was_reset: false };
        let loaded = fs::read(Self::p(dir, "state.bin")).ok().and_then(|b| {
            let body_len = match b.len() {
                n if n == State::LEN + 32 => State::LEN,
                n if n == State::LEN_V2 + 32 => State::LEN_V2,
                n if n == State::LEN_V1 + 32 => State::LEN_V1,
                _ => return None,
            };
            let (body, mac) = b.split_at(body_len);
            let want = hmac256(s.key.as_bytes(), &[b"state", body]);
            if crypto::ct_eq(&want, mac) {
                State::from_bytes(body)
            } else {
                None
            }
        });
        match loaded {
            Some(st) => s.st = st,
            None => {
                // Missing or tampered: assume the worst. Re-anchor to the log, start locked.
                s.was_reset = true;
                if let Ok((entries, _)) = s.read_all() {
                    if let Some(last) = entries.last() {
                        s.st.seq = last.seq;
                        s.st.mac = s.mac_for_seq(last.seq);
                    }
                }
                s.st.fails = FREE_ATTEMPTS + 3;
                s.st.pw_fails = PW_FAILS_ON_RESET;
                s.set_lock(900, now);
                s.save_state()?;
            }
        }
        Ok(s)
    }

    pub fn save_state(&self) -> Res<()> {
        let body = self.st.to_bytes();
        let mac = hmac256(self.key.as_bytes(), &[b"state", &body]);
        let mut out = body;
        out.extend_from_slice(&mac);
        write_atomic(&Self::p(&self.dir, "state.bin"), &out)
    }

    pub fn log(&mut self, ev: &str, extra: u64) -> Res<()> {
        let seq = self.st.seq + 1;
        let body = format!("{seq},{},{ev},{extra}", unix_now());
        let mac = chain_mac(&self.key, &self.st.mac, &body);
        let line = format!("{body},{}\n", HEXLOWER.encode(&mac));
        let path = Self::p(&self.dir, "audit.log");
        let new = !path.exists();
        let mut f = OpenOptions::new().create(true).append(true).open(&path).map_err(ioe)?;
        if new {
            protect::complete(&f)?;
        }
        f.write_all(line.as_bytes()).map_err(ioe)?;
        f.sync_all().map_err(ioe)?;
        self.st.seq = seq;
        self.st.mac = mac;
        self.save_state()
    }

    /// Parse and verify the whole log.
    fn read_all(&self) -> Res<(Vec<Entry>, Chain)> {
        let text = match fs::read_to_string(Self::p(&self.dir, "audit.log")) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(ioe(e)),
        };
        let mut prev = [0u8; 32];
        let mut entries = Vec::new();
        let mut status = Chain::Intact;
        for line in text.lines() {
            let Some((body, mac_hex)) = line.rsplit_once(',') else {
                status = Chain::Broken(entries.len() as u64 + 1);
                break;
            };
            let parts: Vec<&str> = body.split(',').collect();
            let parsed = (parts.len() == 4)
                .then(|| {
                    Some(Entry {
                        seq: parts[0].parse().ok()?,
                        ts: parts[1].parse().ok()?,
                        ev: parts[2].to_string(),
                        extra: parts[3].parse().ok()?,
                    })
                })
                .flatten();
            let want = chain_mac(&self.key, &prev, body);
            match parsed {
                Some(e)
                    if e.seq == entries.len() as u64 + 1
                        && crypto::ct_eq(HEXLOWER.encode(&want).as_bytes(), mac_hex.as_bytes()) =>
                {
                    prev = want;
                    entries.push(e);
                }
                _ => {
                    status = Chain::Broken(entries.len() as u64 + 1);
                    break;
                }
            }
        }
        if status == Chain::Intact {
            if self.st.seq > entries.len() as u64 {
                status = Chain::Truncated;
            } else if self.st.seq == entries.len() as u64
                && self.st.seq > 0
                && !crypto::ct_eq(&prev, &self.st.mac)
            {
                status = Chain::Broken(self.st.seq);
            }
        }
        Ok((entries, status))
    }

    fn mac_for_seq(&self, seq: u64) -> [u8; 32] {
        let text = fs::read_to_string(Self::p(&self.dir, "audit.log")).unwrap_or_default();
        let mut prev = [0u8; 32];
        for (i, line) in text.lines().enumerate() {
            if let Some((body, _)) = line.rsplit_once(',') {
                prev = chain_mac(&self.key, &prev, body);
            }
            if i as u64 + 1 == seq {
                break;
            }
        }
        prev
    }

    pub fn read(&self) -> Res<(Vec<Entry>, Chain)> {
        self.read_all()
    }

    // ---- lockout policy

    fn set_lock(&mut self, secs: u64, now: Now) {
        self.st.lock_secs = secs;
        self.st.locked_until = now.wall + secs;
        self.st.lock_mono_until = now.mono + secs;
        self.st.boot_id = now.boot;
    }

    /// Remaining lockout, measured on the monotonic clock. Changing the date and time does not
    /// shorten it. After a reboot the elapsed time cannot be proven, so the lockout counts as
    /// still fully in force (see `lock_check`, which restarts it).
    pub fn locked_remaining(&self, now: impl Into<Now>) -> Option<u64> {
        let now = now.into();
        if self.st.lock_secs == 0 {
            return None;
        }
        if now.boot != self.st.boot_id {
            return Some(self.st.lock_secs);
        }
        (self.st.lock_mono_until > now.mono).then(|| self.st.lock_mono_until - now.mono)
    }

    /// Like `locked_remaining`, and brings the stored lock up to date: clears an expired lock, and
    /// restarts a lock in full when the phone has been rebooted since it began.
    pub fn lock_check(&mut self, now: impl Into<Now>) -> Option<u64> {
        let now = now.into();
        if self.st.lock_secs == 0 {
            return None;
        }
        if now.boot != self.st.boot_id {
            self.set_lock(self.st.lock_secs, now);
            let _ = self.save_state();
            return Some(self.st.lock_secs);
        }
        match self.locked_remaining(now) {
            Some(r) => Some(r),
            None => {
                self.st.lock_secs = 0;
                self.st.locked_until = 0;
                let _ = self.save_state();
                None
            }
        }
    }

    /// Register a failed attempt. Returns the new lockout length in seconds, if one started.
    pub fn register_failure(&mut self, now: impl Into<Now>) -> Option<u64> {
        let now = now.into();
        self.st.fails = self.st.fails.saturating_add(1);
        if self.st.fails >= FREE_ATTEMPTS {
            let exp = (self.st.fails - FREE_ATTEMPTS).min(7);
            let secs = (30u64 << exp).min(MAX_LOCK);
            self.set_lock(secs, now);
            Some(secs)
        } else {
            None
        }
    }

    /// A wrong admin password (Face ID had matched). Returns the new count.
    pub fn register_pw_failure(&mut self) -> u32 {
        self.st.pw_fails = self.st.pw_fails.saturating_add(1);
        self.st.pw_fails
    }

    pub fn register_success(&mut self) {
        self.st.fails = 0;
        self.st.pw_fails = 0;
        self.st.locked_until = 0;
        self.st.lock_secs = 0;
        self.st.lock_mono_until = 0;
    }

    pub fn attempts_left(&self) -> u32 {
        FREE_ATTEMPTS.saturating_sub(self.st.fails)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(n: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("scytale-ios-test-{n}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn key() -> Secret32 {
        Secret32::from_slice(&[0x5a; 32])
    }

    #[test]
    fn chain_detects_edit_delete_truncate() {
        let d = tmpdir("audit");
        let mut s = Store::create(&d, key()).unwrap();
        for i in 0..5 {
            s.log(ev::LOGIN_OK, i).unwrap();
        }
        assert_eq!(s.read().unwrap().1, Chain::Intact);
        let log = d.join("audit.log");
        let orig = fs::read_to_string(&log).unwrap();

        fs::write(&log, orig.replacen("LOGIN_OK,2", "LOGIN_OK,9", 1)).unwrap();
        assert!(matches!(s.read().unwrap().1, Chain::Broken(_)));
        let lines: Vec<&str> = orig.lines().collect();
        fs::write(&log, [lines[0], lines[1], lines[3], lines[4]].join("\n") + "\n").unwrap();
        assert!(matches!(s.read().unwrap().1, Chain::Broken(_)));
        fs::write(&log, lines[..3].join("\n") + "\n").unwrap();
        assert_eq!(s.read().unwrap().1, Chain::Truncated);
        fs::write(&log, &orig).unwrap();
        assert_eq!(s.read().unwrap().1, Chain::Intact);

        // a different key (e.g. a forged log) does not verify
        let other = Store::load(&d, Secret32::from_slice(&[0x11; 32]), unix_now()).unwrap();
        assert!(matches!(other.read().unwrap().1, Chain::Broken(1)));

        assert!(orig.lines().all(|l| l.split(',').count() == 5));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn lockout_escalates_and_persists() {
        let d = tmpdir("lock");
        let mut s = Store::create(&d, key()).unwrap();
        assert_eq!(s.register_failure(1000), None);
        assert_eq!(s.register_failure(1000), None);
        assert_eq!(s.register_failure(1000), Some(30));
        assert_eq!(s.register_failure(1000), Some(60));
        for _ in 0..20 {
            s.register_failure(1000);
        }
        assert_eq!(s.register_failure(1000), Some(3600));
        s.save_state().unwrap();
        let again = Store::load(&d, key(), unix_now()).unwrap();
        assert!(!again.was_reset);
        assert_eq!(again.st.fails, s.st.fails);

        let p = d.join("state.bin");
        let mut b = fs::read(&p).unwrap();
        b[0] ^= 0xff;
        fs::write(&p, b).unwrap();
        let t = Store::load(&d, key(), unix_now()).unwrap();
        assert!(t.was_reset);
        assert!(t.locked_remaining(unix_now()).is_some());

        // deleting the state file is treated the same as tampering: locked, not a free pass
        fs::remove_file(&p).unwrap();
        let t = Store::load(&d, key(), unix_now()).unwrap();
        assert!(t.was_reset);
        assert!(t.locked_remaining(unix_now()).is_some());
        assert_eq!(t.st.pw_fails, PW_FAILS_ON_RESET, "termination counter not reset by deleting state");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn clock_changes_cannot_shorten_a_lockout() {
        let d = tmpdir("clock");
        let mut s = Store::create(&d, key()).unwrap();
        let at = |wall, mono, boot| Now { wall, mono, boot };
        for _ in 0..3 {
            s.register_failure(at(5_000, 1_000, 7));
        }
        // date set forward by days: ignored, the monotonic clock decides
        assert_eq!(s.locked_remaining(at(900_000, 1_010, 7)), Some(20));
        // date set backward: same
        assert_eq!(s.locked_remaining(at(10, 1_029, 7)), Some(1));
        assert_eq!(s.lock_check(at(10, 1_030, 7)), None, "expires on the monotonic clock");
        assert_eq!(s.st.lock_secs, 0);

        // a reboot during a lockout restarts it in full
        for _ in 0..2 {
            s.register_failure(at(6_000, 2_000, 7));
        }
        let secs = s.st.lock_secs;
        assert!(secs >= 60);
        assert_eq!(s.locked_remaining(at(6_000, 5, 8)), Some(secs));
        assert_eq!(s.lock_check(at(9_999_999, 5, 8)), Some(secs));
        assert_eq!(s.locked_remaining(at(0, 5 + secs - 1, 8)), Some(1));
        s.save_state().unwrap();
        let again = Store::load(&d, key(), at(0, 6, 8)).unwrap();
        assert!(!again.was_reset);
        assert_eq!(again.locked_remaining(at(0, 6, 8)), Some(secs - 1));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn v1_state_upgrades() {
        let d = tmpdir("v1");
        let s = Store::create(&d, key()).unwrap();
        // write a v1 state file (68-byte body) as earlier builds did
        let body = s.st.to_bytes()[..State::LEN_V1].to_vec();
        let mac = hmac256(&[0x5a; 32], &[b"state", &body]);
        fs::write(d.join("state.bin"), [body, mac.to_vec()].concat()).unwrap();
        let t = Store::load(&d, key(), unix_now()).unwrap();
        assert!(!t.was_reset, "a genuine v1 state file is accepted");
        assert_eq!(t.st.pw_fails, 0);
        let _ = fs::remove_dir_all(&d);
    }
}
