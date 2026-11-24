//! Audit log + login-lockout state.
//!
//! The log records only an event code, a timestamp and (for logouts) a duration. Never names,
//! paths, sizes or content. Entries are chained with HMAC-SHA256 under a DPAPI-protected key, so
//! edits, deletions and truncation are detected.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use data_encoding::HEXLOWER;

use crate::{
    crypto::{self, hmac256},
    dpapi,
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
    pub const WIN_LOCK: &str = "WIN_LOCK";
    pub const SUSPEND: &str = "SUSPEND";
    pub const SHUTDOWN: &str = "SHUTDOWN";
    pub const ABORTED: &str = "ABORTED";
    pub const REAUTH_FAIL: &str = "REAUTH_FAIL";
    pub const FILE_ENC: &str = "FILE_ENC";
    pub const FILE_DEC: &str = "FILE_DEC";
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
}

#[derive(Clone, Copy, Default)]
pub struct State {
    pub fails: u32,
    pub locked_until: u64,
    pub last_step: u64,
    pub session_start: u64,
    pub seq: u64,
    pub mac: [u8; 32],
}

impl State {
    const LEN: usize = 4 + 8 + 8 + 8 + 8 + 32;

    fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(Self::LEN);
        v.extend_from_slice(&self.fails.to_le_bytes());
        v.extend_from_slice(&self.locked_until.to_le_bytes());
        v.extend_from_slice(&self.last_step.to_le_bytes());
        v.extend_from_slice(&self.session_start.to_le_bytes());
        v.extend_from_slice(&self.seq.to_le_bytes());
        v.extend_from_slice(&self.mac);
        v
    }

    fn from_bytes(b: &[u8]) -> Option<State> {
        if b.len() != Self::LEN {
            return None;
        }
        let u64_at = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&b[36..68]);
        Some(State {
            fails: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            locked_until: u64_at(4),
            last_step: u64_at(12),
            session_start: u64_at(20),
            seq: u64_at(28),
            mac,
        })
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

    /// First-time creation (called at setup).
    pub fn create(dir: &Path) -> Res<Store> {
        let key = Secret32::random();
        let blob = dpapi::protect(key.as_bytes())?;
        write_atomic(&Self::p(dir, "audit.key"), &blob)?;
        let s = Store { dir: dir.to_path_buf(), key, st: State::default(), was_reset: false };
        s.save_state()?;
        Ok(s)
    }

    /// Recovery on a machine/account where the old audit key cannot be opened: archive the old
    /// log and start a new chain.
    pub fn fresh(dir: &Path) -> Res<Store> {
        for n in ["audit.key", "audit.log", "state.bin"] {
            let p = Self::p(dir, n);
            if p.exists() {
                let _ = fs::rename(&p, Self::p(dir, &format!("{n}.prev")));
            }
        }
        Self::create(dir)
    }

    pub fn load(dir: &Path) -> Res<Store> {
        let blob = fs::read(Self::p(dir, "audit.key")).map_err(ioe)?;
        let raw = dpapi::unprotect(&blob)?;
        if raw.len() != 32 {
            return Err("audit key invalid".into());
        }
        let key = Secret32::from_slice(&raw);
        let mut s = Store { dir: dir.to_path_buf(), key, st: State::default(), was_reset: false };
        let loaded = fs::read(Self::p(dir, "state.bin")).ok().and_then(|b| {
            if b.len() != State::LEN + 32 {
                return None;
            }
            let (body, mac) = b.split_at(State::LEN);
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
                s.st.locked_until = unix_now() + 900;
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
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(Self::p(&self.dir, "audit.log"))
            .map_err(ioe)?;
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

    pub fn locked_remaining(&self, now: u64) -> Option<u64> {
        (self.st.locked_until > now).then(|| self.st.locked_until - now)
    }

    /// Register a failed attempt. Returns the new lockout length in seconds, if one started.
    pub fn register_failure(&mut self, now: u64) -> Option<u64> {
        self.st.fails = self.st.fails.saturating_add(1);
        if self.st.fails >= FREE_ATTEMPTS {
            let exp = (self.st.fails - FREE_ATTEMPTS).min(7);
            let secs = (30u64 << exp).min(MAX_LOCK);
            self.st.locked_until = now + secs;
            Some(secs)
        } else {
            None
        }
    }

    pub fn register_success(&mut self) {
        self.st.fails = 0;
        self.st.locked_until = 0;
    }

    pub fn attempts_left(&self) -> u32 {
        FREE_ATTEMPTS.saturating_sub(self.st.fails)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(n: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("scytale-test-{n}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn chain_detects_edit_delete_truncate() {
        let d = tmpdir("audit");
        let mut s = Store::create(&d).unwrap();
        for i in 0..5 {
            s.log(ev::LOGIN_OK, i).unwrap();
        }
        assert_eq!(s.read().unwrap().1, Chain::Intact);
        let log = d.join("audit.log");
        let orig = fs::read_to_string(&log).unwrap();

        // edit a field
        fs::write(&log, orig.replacen("LOGIN_OK,2", "LOGIN_OK,9", 1)).unwrap();
        assert!(matches!(s.read().unwrap().1, Chain::Broken(_)));
        // delete a middle line
        let lines: Vec<&str> = orig.lines().collect();
        fs::write(&log, [lines[0], lines[1], lines[3], lines[4]].join("\n") + "\n").unwrap();
        assert!(matches!(s.read().unwrap().1, Chain::Broken(_)));
        // truncate the tail
        fs::write(&log, lines[..3].join("\n") + "\n").unwrap();
        assert_eq!(s.read().unwrap().1, Chain::Truncated);
        // restore
        fs::write(&log, &orig).unwrap();
        assert_eq!(s.read().unwrap().1, Chain::Intact);

        // contents carry nothing but codes and numbers
        assert!(orig.lines().all(|l| l.split(',').count() == 5));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn lockout_escalates_and_persists() {
        let d = tmpdir("lock");
        let mut s = Store::create(&d).unwrap();
        assert_eq!(s.register_failure(1000), None);
        assert_eq!(s.register_failure(1000), None);
        assert_eq!(s.register_failure(1000), Some(30));
        assert_eq!(s.register_failure(1000), Some(60));
        for _ in 0..20 {
            s.register_failure(1000);
        }
        assert_eq!(s.register_failure(1000), Some(3600));
        s.save_state().unwrap();
        let again = Store::load(&d).unwrap();
        assert!(!again.was_reset);
        assert_eq!(again.st.fails, s.st.fails);

        // tampering with the state file triggers a reset + lock, not a free pass
        let p = d.join("state.bin");
        let mut b = fs::read(&p).unwrap();
        b[0] ^= 0xff;
        fs::write(&p, b).unwrap();
        let t = Store::load(&d).unwrap();
        assert!(t.was_reset);
        assert!(t.locked_remaining(unix_now()).is_some());
        let _ = fs::remove_dir_all(&d);
    }
}
