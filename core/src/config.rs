//! User configuration, stored inside the HMAC-protected lockout state. All-zero bytes mean
//! "hardened defaults", which is also what a missing or tampered state file falls back to.

/// Allowed session timeouts in minutes.
pub const TIMEOUTS: [u8; 7] = [1, 2, 5, 10, 15, 30, 60];
/// Allowed message display times in minutes.
pub const MESSAGE_TIMES: [u8; 3] = [1, 5, 10];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// false = hardened defaults (the shipped behaviour); the fields below are then ignored.
    pub custom: bool,
    /// Lock the vault the moment the app is left.
    pub lock_on_leave: bool,
    /// Lock after this many minutes without a touch.
    pub timeout_min: u8,
    /// Ask for the authenticator code at every login.
    pub require_totp: bool,
    /// Ask for Face ID every time an item or message is opened (else once per session).
    pub faceid_each_open: bool,
    /// Local notification for every login outcome.
    pub notify: bool,
    /// A screenshot ends the session (else: recorded and reported only).
    pub screenshot_locks: bool,
    /// How long an opened message stays on screen, in minutes.
    pub message_min: u8,
    /// After an import: 0 ask, 1 always delete originals, 2 always keep originals.
    pub originals: u8,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            custom: false,
            lock_on_leave: true,
            timeout_min: 5,
            require_totp: true,
            faceid_each_open: true,
            notify: true,
            screenshot_locks: true,
            message_min: 5,
            originals: 0,
        }
    }
}

impl Config {
    /// The configuration actually in force.
    pub fn effective(self) -> Config {
        if self.custom {
            self
        } else {
            Config::default()
        }
    }

    pub fn to_bytes(self) -> [u8; 8] {
        let mut flags = 0u8;
        flags |= u8::from(self.custom);
        flags |= u8::from(!self.lock_on_leave) << 1;
        flags |= u8::from(!self.require_totp) << 2;
        flags |= u8::from(!self.faceid_each_open) << 3;
        flags |= u8::from(!self.notify) << 4;
        flags |= u8::from(!self.screenshot_locks) << 5;
        [flags, self.timeout_min, self.message_min, self.originals, 0, 0, 0, 0]
    }

    /// Decodes stored bytes; out-of-range values fall back to the hardened value.
    pub fn from_bytes(b: &[u8; 8]) -> Config {
        let f = b[0];
        let d = Config::default();
        Config {
            custom: f & 1 != 0,
            lock_on_leave: f & (1 << 1) == 0,
            require_totp: f & (1 << 2) == 0,
            faceid_each_open: f & (1 << 3) == 0,
            notify: f & (1 << 4) == 0,
            screenshot_locks: f & (1 << 5) == 0,
            timeout_min: if TIMEOUTS.contains(&b[1]) { b[1] } else { d.timeout_min },
            message_min: if MESSAGE_TIMES.contains(&b[2]) { b[2] } else { d.message_min },
            originals: if b[3] <= 2 { b[3] } else { 0 },
        }
    }

    /// Only valid values may be stored.
    pub fn valid(&self) -> bool {
        TIMEOUTS.contains(&self.timeout_min) && MESSAGE_TIMES.contains(&self.message_min) && self.originals <= 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_bytes_are_hardened_and_round_trip() {
        assert_eq!(Config::from_bytes(&[0; 8]), Config::default());
        let c = Config {
            custom: true,
            lock_on_leave: false,
            timeout_min: 30,
            require_totp: false,
            faceid_each_open: false,
            notify: false,
            screenshot_locks: false,
            message_min: 10,
            originals: 2,
        };
        assert_eq!(Config::from_bytes(&c.to_bytes()), c);
        // custom off: everything reverts to hardened, whatever else is stored
        let off = Config { custom: false, ..c };
        assert_eq!(Config::from_bytes(&off.to_bytes()).effective(), Config::default());
        // garbage values fall back to hardened ones
        let g = Config::from_bytes(&[1, 99, 77, 9, 0, 0, 0, 0]);
        assert_eq!((g.timeout_min, g.message_min, g.originals), (5, 5, 0));
        assert!(!Config { timeout_min: 3, ..Config::default() }.valid());
    }
}
