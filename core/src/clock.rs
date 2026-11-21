//! Time that the user cannot wind back. Lockouts are measured on the monotonic clock (which keeps
//! counting while the phone sleeps and ignores changes to the date and time); a reboot restarts the
//! lockout in full, because elapsed time across a reboot cannot be proven.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Now {
    /// Wall-clock seconds (for log timestamps and TOTP).
    pub wall: u64,
    /// Monotonic seconds since an arbitrary point in this boot.
    pub mono: u64,
    /// Identifies this boot.
    pub boot: u64,
}

/// Tests (and callers that only have wall time) get a single-boot clock where mono == wall.
impl From<u64> for Now {
    fn from(t: u64) -> Now {
        Now { wall: t, mono: t, boot: 1 }
    }
}

pub fn now() -> Now {
    Now { wall: crate::util::unix_now(), mono: mono_secs(), boot: boot_id() }
}

#[cfg(target_vendor = "apple")]
fn mono_secs() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid out-pointer; CLOCK_MONOTONIC on Darwin includes time asleep.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } == 0 {
        ts.tv_sec as u64
    } else {
        0
    }
}

#[cfg(target_vendor = "apple")]
fn boot_id() -> u64 {
    let mut buf = [0u8; 64];
    let mut len = buf.len();
    let name = b"kern.bootsessionuuid\0";
    // SAFETY: NUL-terminated name, valid buffer and length pointers.
    let r = unsafe {
        libc::sysctlbyname(name.as_ptr().cast(), buf.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0)
    };
    if r != 0 || len == 0 {
        return 0;
    }
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(&buf[..len.min(buf.len())]);
    u64::from_le_bytes(h[..8].try_into().unwrap()) | 1
}

#[cfg(not(target_vendor = "apple"))]
fn mono_secs() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs() + 1_000_000
}

#[cfg(not(target_vendor = "apple"))]
fn boot_id() -> u64 {
    1
}
