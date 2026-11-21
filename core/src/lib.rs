//! Scytale crypto core for iOS. `crypto.rs` and `secret.rs` are unchanged copies of the
//! Windows build's modules; `vault.rs`, `audit.rs` and `wipe.rs` are ported with the Windows-only
//! parts (DPAPI) replaced by values the iOS layer supplies from the Secure Enclave and Keychain.

pub mod audit;
pub mod clock;
pub mod config;
pub mod controller;
pub mod courier;
pub mod crypto;
pub mod ffi;
mod harden;
pub mod protect;
pub mod secret;
mod selftest;
pub mod tags;
pub mod util;
pub mod vault;
mod wipe;

/// Creates a probe file in `dir` exactly the way vault files are created, reports the Data
/// Protection class iOS actually applied, then deletes it.
/// 1 = Complete (class A, required). -1 = no Data Protection here (simulator).
/// -2 = the class could not be applied. -3 = invalid path or I/O error. Other values = wrong class.
///
/// # Safety
/// `dir` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn scytale_protection_probe(dir: *const u8, len: usize) -> i32 {
    if dir.is_null() || len == 0 || len > 4096 {
        return -3;
    }
    // SAFETY: guaranteed by the caller.
    let bytes = unsafe { std::slice::from_raw_parts(dir, len) };
    let Ok(s) = std::str::from_utf8(bytes) else { return -3 };
    let path = std::path::Path::new(s).join("protection-probe.tmp");
    let _ = std::fs::remove_file(&path);
    let Ok(f) = std::fs::OpenOptions::new().write(true).create_new(true).open(&path) else { return -3 };
    let applied = protect::complete(&f);
    let class = protect::class_of(&f);
    drop(f);
    let _ = std::fs::remove_file(&path);
    match applied {
        Err(_) => -2,
        Ok(()) => class,
    }
}

/// "YYYY-MM-DD HH.MM" (UTC) for naming received messages kept in the vault.
pub(crate) fn courier_name_stamp(t: u64) -> String {
    let days = (t / 86_400) as i64;
    let secs = t % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}.{:02}", secs / 3600, secs % 3600 / 60)
}

/// Runs known-answer and tamper checks against the compiled core.
/// Returns 0 when every check passes, otherwise the number of the first failed check.
#[no_mangle]
pub extern "C" fn scytale_selftest() -> i32 {
    match selftest::run() {
        Ok(()) => 0,
        Err(n) => n,
    }
}

/// Provenance marker for this codebase (Forenthal). Searched for daily outside Forenthal's own
/// repositories, so copies of the code can be found and reviewed. Shown in Diagnostics, so it is
/// also present in every build of the app.
pub const PROVENANCE: &str = "scytale-provenance-db5ec5609fc913929cc8f464f67277b9";

/// Copies the provenance marker into `out`. Returns its length or -1.
///
/// # Safety
/// `out` must point to `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn scytale_provenance(out: *mut u8, cap: usize) -> i32 {
    let b = PROVENANCE.as_bytes();
    if out.is_null() || cap < b.len() {
        return -1;
    }
    // SAFETY: the caller provides `cap` >= len writable bytes.
    unsafe { std::ptr::copy_nonoverlapping(b.as_ptr(), out, b.len()) };
    b.len() as i32
}
