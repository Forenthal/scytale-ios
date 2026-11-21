//! C interface for the iOS app. Every function takes the opaque `ScyCore` pointer returned by
//! `scy_core_new`; Swift serialises all calls on one queue. Nothing here returns a Rust string:
//! results are status codes, and the few values the screen must show are copied into
//! caller-provided buffers that the caller wipes.

use std::path::PathBuf;

use crate::{
    audit::ev,
    controller::{CommitErr, Core, Field, LockReason, LoginOutcome, Summary},
    secret::Secret32,
    util::unix_now,
    vault::Vault,
};

pub struct ScyCore(Core);

/// # Safety
/// `ptr` must point to `len` readable bytes (or be null with len 0).
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: guaranteed by the caller.
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// # Safety
/// `c` must be a live pointer from `scy_core_new`, not used concurrently.
unsafe fn core<'a>(c: *mut ScyCore) -> Option<&'a mut Core> {
    // SAFETY: guaranteed by the caller.
    unsafe { c.as_mut() }.map(|c| &mut c.0)
}

fn key32(b: Option<&[u8]>) -> Option<Secret32> {
    b.filter(|b| b.len() == 32).map(Secret32::from_slice)
}

/// Copy `src` into `out` if it fits; returns the length or -1.
unsafe fn copy_out(src: &[u8], out: *mut u8, cap: usize) -> i32 {
    if out.is_null() || src.len() > cap || src.len() > i32::MAX as usize {
        return -1;
    }
    // SAFETY: `out` has `cap` writable bytes (caller contract) and src.len() <= cap.
    unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), out, src.len()) };
    src.len() as i32
}

// ---------------------------------------------------------------- lifecycle

/// # Safety
/// `dir` must point to `len` bytes of UTF-8.
#[no_mangle]
pub unsafe extern "C" fn scy_core_new(dir: *const u8, len: usize) -> *mut ScyCore {
    // Never print panic details; release builds abort.
    std::panic::set_hook(Box::new(|_| {}));
    let Some(path) = (unsafe { bytes(dir, len) }).and_then(|b| std::str::from_utf8(b).ok()) else {
        return std::ptr::null_mut();
    };
    if path.is_empty() {
        return std::ptr::null_mut();
    }
    Box::into_raw(Box::new(ScyCore(Core::new(Vault::new(PathBuf::from(path))))))
}

/// Wipes and frees everything.
/// # Safety
/// `c` from `scy_core_new`, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn scy_core_free(c: *mut ScyCore) {
    if !c.is_null() {
        // SAFETY: allocated by Box::into_raw in scy_core_new.
        drop(unsafe { Box::from_raw(c) });
    }
}

/// Returns the start note (see header) and writes its timestamp.
/// # Safety
/// See module docs. `key` may be null (no audit key in the Keychain).
#[no_mangle]
pub unsafe extern "C" fn scy_core_start(c: *mut ScyCore, key: *const u8, key_len: usize, ts: *mut u64) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    let (note, t) = c.start(key32(unsafe { bytes(key, key_len) }));
    if let Some(ts) = unsafe { ts.as_mut() } {
        *ts = t;
    }
    note as i32
}

/// 0 setup, 1 login, 2 unlocked.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_phase(c: *mut ScyCore) -> i32 {
    unsafe { core(c) }.map_or(-1, |c| c.phase() as i32)
}

// ---------------------------------------------------------------- input

/// # Safety
/// See module docs; `utf8` must point to `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_input_push(c: *mut ScyCore, field: i32, utf8: *const u8, len: usize) -> i32 {
    let (Some(c), Some(f)) = (unsafe { core(c) }, Field::from_i32(field)) else { return 0 };
    let Some(text) = (unsafe { bytes(utf8, len) }).and_then(|b| std::str::from_utf8(b).ok()) else { return 0 };
    i32::from(c.push(f, text))
}

/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_input_backspace(c: *mut ScyCore, field: i32) {
    if let (Some(c), Some(f)) = (unsafe { core(c) }, Field::from_i32(field)) {
        c.backspace(f);
    }
}

/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_input_clear(c: *mut ScyCore, field: i32) {
    if let (Some(c), Some(f)) = (unsafe { core(c) }, Field::from_i32(field)) {
        c.clear(f);
    }
}

/// Number of characters typed (for drawing dots).
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_input_count(c: *mut ScyCore, field: i32) -> i32 {
    match (unsafe { core(c) }, Field::from_i32(field)) {
        (Some(c), Some(f)) => c.count(f) as i32,
        _ => -1,
    }
}

// ---------------------------------------------------------------- setup / recovery

/// 0 ok, 1 weak, 2 mismatch, 3 wrong state.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_setup_begin(c: *mut ScyCore, recover: i32) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return 3 };
    match c.setup_begin(recover != 0) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

/// Writes width*width module bytes (1 = dark); returns width or -1.
/// # Safety
/// See module docs; `out` has `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_setup_qr(c: *mut ScyCore, out: *mut u8, cap: usize) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    let Some((w, mods)) = c.setup_qr() else { return -1 };
    if unsafe { copy_out(&mods, out, cap) } < 0 {
        return -1;
    }
    w as i32
}

/// # Safety
/// See module docs; `out` has `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_setup_secret(c: *mut ScyCore, out: *mut u8, cap: usize) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    c.setup_secret_text().map_or(-1, |t| unsafe { copy_out(t.as_bytes(), out, cap) })
}

/// The new device pepper (32 bytes) for Secure Enclave wrapping. The caller wipes `out`.
/// # Safety
/// See module docs; `out` has `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_setup_pepper(c: *mut ScyCore, out: *mut u8, cap: usize) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    c.setup_pepper().map_or(-1, |p| unsafe { copy_out(p, out, cap) })
}

/// 1 if the Face ID unwrap returned the same pepper.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_setup_pepper_verify(c: *mut ScyCore, p: *const u8, len: usize) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return 0 };
    unsafe { bytes(p, len) }.map_or(0, |b| i32::from(c.setup_pepper_verify(b)))
}

/// Checks the code typed into the code field. 1 ok.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_setup_code(c: *mut ScyCore) -> i32 {
    unsafe { core(c) }.map_or(0, |c| i32::from(c.setup_code(unix_now())))
}

/// 0 ok, 1 not ready, 2 vault error, 3 audit error, 4 index error.
/// # Safety
/// See module docs. `audit_key` may be null when recovering with the existing log.
#[no_mangle]
pub unsafe extern "C" fn scy_setup_commit(
    c: *mut ScyCore,
    wrapped: *const u8,
    wrapped_len: usize,
    audit_key: *const u8,
    key_len: usize,
) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return CommitErr::NotReady as i32 };
    let Some(w) = (unsafe { bytes(wrapped, wrapped_len) }) else { return CommitErr::NotReady as i32 };
    match c.setup_commit(w, key32(unsafe { bytes(audit_key, key_len) })) {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}

/// # Safety
/// See module docs; `out` has `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_setup_recovery_key(c: *mut ScyCore, out: *mut u8, cap: usize) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    c.setup_recovery_text().map_or(-1, |t| unsafe { copy_out(t.as_bytes(), out, cap) })
}

/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_setup_finish(c: *mut ScyCore) {
    if let Some(c) = unsafe { core(c) } {
        c.setup_finish();
    }
}

/// Checks the recovery key typed into the recovery field. 1 ok.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_recover_check(c: *mut ScyCore) -> i32 {
    unsafe { core(c) }.map_or(0, |c| i32::from(c.recover_check()))
}

// ---------------------------------------------------------------- login

/// # Safety
/// See module docs; `out` has `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_wrapped_pepper(c: *mut ScyCore, out: *mut u8, cap: usize) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    c.wrapped_pepper().map_or(-1, |w| unsafe { copy_out(&w, out, cap) })
}

/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_locked_remaining(c: *mut ScyCore) -> u64 {
    unsafe { core(c) }.and_then(|c| c.locked_remaining(crate::clock::now())).unwrap_or(0)
}

/// Login with the typed password and code and the pepper from Face ID (null if Face ID failed).
/// 0 ok; 1 failed (aux = attempts left); 2 failed and now locked (aux = seconds);
/// 3 already locked (aux = seconds); 4 incomplete; 5 audit unavailable; 6 index failed integrity.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_login(c: *mut ScyCore, pepper: *const u8, len: usize, aux: *mut u64) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return 4 };
    let out = c.login(key32(unsafe { bytes(pepper, len) }), crate::clock::now());
    let (code, a) = match out {
        LoginOutcome::Ok => (0, 0),
        LoginOutcome::Failed { attempts_left } => (1, attempts_left as u64),
        LoginOutcome::FailedLocked { secs } => (2, secs),
        LoginOutcome::Locked { secs } => (3, secs),
        LoginOutcome::Incomplete => (4, 0),
        LoginOutcome::AuditUnavailable => (5, 0),
        LoginOutcome::IndexFailed => (6, 0),
        LoginOutcome::Terminated => (7, 0),
    };
    if let Some(aux) = unsafe { aux.as_mut() } {
        *aux = a;
    }
    code
}

#[repr(C)]
pub struct ScySummary {
    pub last_login: u64,
    pub fails_since: u32,
    pub chain: i32,
    pub chain_at: u64,
    pub dropped: u32,
    pub shredded: u32,
}

/// # Safety
/// See module docs; `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn scy_session_summary(c: *mut ScyCore, out: *mut ScySummary) {
    let (Some(c), Some(out)) = (unsafe { core(c) }, unsafe { out.as_mut() }) else { return };
    let s: Summary = c.summary;
    *out = ScySummary {
        last_login: s.last_login,
        fails_since: s.fails_since,
        chain: s.chain,
        chain_at: s.chain_at,
        dropped: s.dropped,
        shredded: s.shredded,
    };
}

// ---------------------------------------------------------------- vault contents

/// # Safety
/// `p` must be null or point to 16 bytes.
unsafe fn id16<'a>(p: *const u8) -> Option<&'a [u8; 16]> {
    (unsafe { bytes(p, 16) }).and_then(|b| b.try_into().ok())
}

/// # Safety
/// `out` null or 16 writable bytes.
unsafe fn write_id(out: *mut u8, id: &[u8; 16]) {
    if !out.is_null() {
        // SAFETY: caller provides 16 writable bytes.
        unsafe { std::ptr::copy_nonoverlapping(id.as_ptr(), out, 16) };
    }
}

/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_item_count(c: *mut ScyCore) -> i32 {
    unsafe { core(c) }.map_or(0, |c| c.items().len() as i32)
}

/// Item `idx` (oldest first). Writes id (16 bytes), kind (1 file, 2 message), created, size and
/// the name; returns the name length, or -1.
/// # Safety
/// See module docs; every out pointer must be valid (`name` has `cap` bytes).
#[no_mangle]
pub unsafe extern "C" fn scy_item_get(
    c: *mut ScyCore,
    idx: i32,
    id: *mut u8,
    kind: *mut i32,
    created: *mut u64,
    size: *mut u64,
    name: *mut u8,
    cap: usize,
) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    let Some(item) = usize::try_from(idx).ok().and_then(|i| c.items().get(i)) else { return -1 };
    unsafe {
        write_id(id, &item.id);
        if let Some(k) = kind.as_mut() {
            *k = item.kind as i32;
        }
        if let Some(t) = created.as_mut() {
            *t = item.created;
        }
        if let Some(s) = size.as_mut() {
            *s = item.size;
        }
        copy_out(item.name.as_bytes(), name, cap)
    }
}

/// Encrypt a file at `path` into the vault (the original is left in place). 0 ok, 1 locked,
/// 2 failed. Writes the new id.
/// # Safety
/// See module docs; `path` has `len` bytes of UTF-8; `out_id` has 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_import_file(c: *mut ScyCore, path: *const u8, len: usize, out_id: *mut u8) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return 1 };
    let Some(p) = (unsafe { bytes(path, len) }).and_then(|b| std::str::from_utf8(b).ok()) else { return 2 };
    if c.phase() != crate::controller::Phase::Unlocked {
        return 1;
    }
    match c.import_file(std::path::Path::new(p)) {
        Ok(item) => {
            unsafe { write_id(out_id, &item.id) };
            0
        }
        Err(_) => 2,
    }
}

/// Encrypt bytes into the vault under `name`. `photo` != 0 logs it as a photo. 0 ok, 1 locked,
/// 2 failed.
/// # Safety
/// See module docs; buffers as described.
#[no_mangle]
pub unsafe extern "C" fn scy_import_bytes(
    c: *mut ScyCore,
    name: *const u8,
    name_len: usize,
    data: *const u8,
    data_len: usize,
    photo: i32,
    out_id: *mut u8,
) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return 1 };
    if c.phase() != crate::controller::Phase::Unlocked {
        return 1;
    }
    let Some(n) = (unsafe { bytes(name, name_len) }).and_then(|b| std::str::from_utf8(b).ok()) else { return 2 };
    let d: &[u8] = if data_len == 0 { &[] } else {
        match unsafe { bytes(data, data_len) } {
            Some(d) => d,
            None => return 2,
        }
    };
    match c.import_bytes(n, d, photo != 0) {
        Ok(item) => {
            unsafe { write_id(out_id, &item.id) };
            0
        }
        Err(_) => 2,
    }
}

/// Re-authenticate before a decrypt with the pepper from Face ID (null = Face ID did not match).
/// 0 ok; 1 failed (aux = attempts left); 2 locked out, session ended; 3 no session.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_reauth(c: *mut ScyCore, pepper: *const u8, len: usize, aux: *mut u64) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return 3 };
    let r = c.reauth(unsafe { bytes(pepper, len) }, crate::clock::now());
    let (code, a) = match r {
        crate::controller::ReauthOutcome::Ok => (0, 0),
        crate::controller::ReauthOutcome::Bad { attempts_left } => (1, attempts_left as u64),
        crate::controller::ReauthOutcome::LockedOut => (2, 0),
        crate::controller::ReauthOutcome::NoSession => (3, 0),
    };
    if let Some(aux) = unsafe { aux.as_mut() } {
        *aux = a;
    }
    code
}

/// Decrypt item `id` into locked memory; writes its length. 0 ok, else ViewErr code.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_view_open(c: *mut ScyCore, id: *const u8, out_len: *mut usize) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return 5 };
    let Some(id) = (unsafe { id16(id) }) else { return 2 };
    match c.view_open(id) {
        Ok(n) => {
            if let Some(l) = unsafe { out_len.as_mut() } {
                *l = n;
            }
            0
        }
        Err(e) => e as i32,
    }
}

/// Copy the open file into the caller's buffer (which the caller locks and wipes).
/// # Safety
/// See module docs; `out` has `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_view_copy(c: *mut ScyCore, out: *mut u8, cap: usize) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    c.view_bytes().map_or(-1, |b| unsafe { copy_out(b, out, cap) })
}

/// Wipe the decrypted file held by the core.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_view_close(c: *mut ScyCore) {
    if let Some(c) = unsafe { core(c) } {
        c.view_close();
    }
}

/// Permanently destroy an item. 1 ok.
/// # Safety
/// See module docs; `id` has 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_purge(c: *mut ScyCore, id: *const u8) -> i32 {
    let (Some(c), Some(id)) = (unsafe { core(c) }, unsafe { id16(id) }) else { return 0 };
    i32::from(c.purge(id))
}

// ---------------------------------------------------------------- session end / events

/// 0 logout, 1 timeout, 2 background, 3 device lock, 4 screen capture.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_lock(c: *mut ScyCore, reason: i32) {
    if let Some(c) = unsafe { core(c) } {
        c.lock(LockReason::from_i32(reason));
    }
}

/// Logs a non-ending security event: 1 screenshot taken. Returns 1 if written.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_audit_event(c: *mut ScyCore, event: i32) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return 0 };
    match event {
        1 => i32::from(c.audit(ev::SCREENSHOT)),
        2 => i32::from(c.audit(ev::MSG_EXPIRE)),
        3 => i32::from(c.audit(ev::MSG_KILL)),
        4 => i32::from(c.audit_extra(ev::FILE_REENC, 0)),
        5 => i32::from(c.audit_extra(ev::FILE_REENC, 1)),
        _ => 0,
    }
}

/// Destroys the vault files. Returns files that could not be erased.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_panic_wipe(c: *mut ScyCore) -> i32 {
    unsafe { core(c) }.map_or(-1, |c| c.panic_wipe() as i32)
}

// ---------------------------------------------------------------- termination

/// 0 none; 1 = "VAULT TERMINATION IN 10 FAILED ATTEMPTS"; 2 = "... IN 5 ...".
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_termination_level(c: *mut ScyCore) -> i32 {
    unsafe { core(c) }.map_or(0, |c| c.termination_level() as i32)
}

// ---------------------------------------------------------------- messages

/// Seal a message. 1 ok.
/// # Safety
/// See module docs; `text` has `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_msg_seal(c: *mut ScyCore, text: *const u8, len: usize) -> i32 {
    let (Some(c), Some(t)) = (unsafe { core(c) }, unsafe { bytes(text, len) }) else { return 0 };
    i32::from(c.msg_seal(t))
}

/// Open a message once (after `scy_reauth`): destroyed on disk, text held like an open file
/// (read it with `scy_view_copy`, then `scy_view_close`). 0 ok, else a view error code.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_msg_open(c: *mut ScyCore, id: *const u8, out_len: *mut usize) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return 5 };
    let Some(id) = (unsafe { bytes(id, 16) }).and_then(|b| <&[u8; 16]>::try_from(b).ok()) else { return 2 };
    match c.msg_open(id) {
        Ok(n) => {
            if let Some(l) = unsafe { out_len.as_mut() } {
                *l = n;
            }
            0
        }
        Err(e) => e as i32,
    }
}

// ---------------------------------------------------------------- audit / login log

/// Load the audit log (vault must be open). Returns the entry count.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_audit_load(c: *mut ScyCore) -> i32 {
    unsafe { core(c) }.map_or(0, |c| c.audit_load() as i32)
}

/// Entry `i` (oldest first): sequence, UTC timestamp, extra (duration or failed factor) and the
/// event code text. Returns the event code length or -1.
/// # Safety
/// See module docs; out pointers valid, `ev` has `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_audit_entry(
    c: *mut ScyCore,
    i: i32,
    seq: *mut u64,
    ts: *mut u64,
    extra: *mut u64,
    ev: *mut u8,
    cap: usize,
) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    let Some(e) = usize::try_from(i).ok().and_then(|i| c.audit_entry(i)) else { return -1 };
    unsafe {
        if let Some(s) = seq.as_mut() {
            *s = e.seq;
        }
        if let Some(t) = ts.as_mut() {
            *t = e.ts;
        }
        if let Some(x) = extra.as_mut() {
            *x = e.extra;
        }
        copy_out(e.ev.as_bytes(), ev, cap)
    }
}

/// 0 intact, 1 broken at *at, 2 truncated, -1 not loaded.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_audit_chain(c: *mut ScyCore, at: *mut u64) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    let (code, n) = c.audit_chain();
    if let Some(a) = unsafe { at.as_mut() } {
        *a = n;
    }
    code
}

// ---------------------------------------------------------------- diagnostics

/// Milliseconds Argon2id takes on this device with the given parameters (0 if invalid).
#[no_mangle]
pub extern "C" fn scytale_kdf_benchmark(m_kib: u32, t: u32, p: u32) -> u64 {
    let k = crate::crypto::Kdf { m: m_kib, t, p };
    let start = std::time::Instant::now();
    match crate::crypto::argon2id(b"benchmark", &[7u8; 16], &k) {
        Ok(_) => start.elapsed().as_millis() as u64,
        Err(_) => 0,
    }
}

/// The parameters new and re-keyed vaults use (m KiB, t, p).
/// # Safety
/// out pointers valid.
#[no_mangle]
pub unsafe extern "C" fn scytale_kdf_default(m: *mut u32, t: *mut u32, p: *mut u32) {
    let k = crate::crypto::Kdf::DEFAULT;
    unsafe {
        if let Some(m) = m.as_mut() {
            *m = k.m;
        }
        if let Some(t) = t.as_mut() {
            *t = k.t;
        }
        if let Some(p) = p.as_mut() {
            *p = k.p;
        }
    }
}

// ---------------------------------------------------------------- courier

/// Courier status. Returns 0 ok, negative on error.
/// # Safety
/// See module docs; out pointers valid.
#[no_mangle]
pub unsafe extern "C" fn scy_courier_status(
    c: *mut ScyCore,
    paired: *mut i32,
    verified: *mut i32,
    peer_keys: *mut u32,
    own_keys: *mut u32,
) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    match c.courier_status() {
        Ok((p, v, a, b)) => {
            unsafe {
                if let Some(x) = paired.as_mut() {
                    *x = i32::from(p);
                }
                if let Some(x) = verified.as_mut() {
                    *x = i32::from(v);
                }
                if let Some(x) = peer_keys.as_mut() {
                    *x = a as u32;
                }
                if let Some(x) = own_keys.as_mut() {
                    *x = b as u32;
                }
            }
            0
        }
        Err(e) => e,
    }
}

/// Export the signed key bundle into the output buffer. Returns its length or a negative error.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_courier_export_bundle(c: *mut ScyCore) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    match c.courier_export_bundle() {
        Ok(n) => n as i32,
        Err(e) => e,
    }
}

/// Import the other device's bundle; writes the safety number. 0 ok, else the courier error code.
/// # Safety
/// See module docs; `out` has `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_courier_import_bundle(c: *mut ScyCore, data: *const u8, len: usize, out: *mut u8, cap: usize) -> i32 {
    let (Some(c), Some(d)) = (unsafe { core(c) }, unsafe { bytes(data, len) }) else { return -1 };
    match c.courier_import_bundle(d) {
        Ok(n) => {
            unsafe { copy_out(n.as_bytes(), out, cap) };
            0
        }
        Err(e) => e,
    }
}

/// The safety number for the current pairing. Length or -1.
/// # Safety
/// See module docs; `out` has `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_courier_safety(c: *mut ScyCore, out: *mut u8, cap: usize) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    c.courier_safety_number().map_or(-1, |n| unsafe { copy_out(n.as_bytes(), out, cap) })
}

/// The safety numbers matched on both screens. 1 ok.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_courier_verify(c: *mut ScyCore) -> i32 {
    unsafe { core(c) }.map_or(0, |c| i32::from(c.courier_verify()))
}

/// 1 ok.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_courier_unpair(c: *mut ScyCore) -> i32 {
    unsafe { core(c) }.map_or(0, |c| i32::from(c.courier_unpair()))
}

/// Seal a message for the paired device into the output buffer (armored text if `armored`,
/// otherwise raw .scy bytes). Returns the length, or a negative courier error code.
/// # Safety
/// See module docs; `text` has `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_courier_send(c: *mut ScyCore, text: *const u8, len: usize, burn: i32, armored: i32) -> i32 {
    let (Some(c), Some(t)) = (unsafe { core(c) }, unsafe { bytes(text, len) }) else { return -1 };
    match c.courier_send(t, burn != 0, armored != 0) {
        Ok(n) => n as i32,
        Err(e) => -e.abs(),
    }
}

/// Copy the output buffer (bundle or envelope; public data). Length or -1.
/// # Safety
/// See module docs; `out` has `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_courier_out_copy(c: *mut ScyCore, out: *mut u8, cap: usize) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    unsafe { copy_out(c.courier_out(), out, cap) }
}

/// Open a message (after scy_reauth). 0 ok (text in the view buffer: scy_view_copy, then
/// scy_view_close; *burn = sender's destroy flag), else an error code (negative = local error,
/// positive = courier error).
/// # Safety
/// See module docs; `data` has `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_courier_receive(c: *mut ScyCore, data: *const u8, len: usize, burn: *mut i32, out_len: *mut usize) -> i32 {
    let (Some(c), Some(d)) = (unsafe { core(c) }, unsafe { bytes(data, len) }) else { return -1 };
    match c.courier_receive(d) {
        Ok(b) => {
            unsafe {
                if let Some(x) = burn.as_mut() {
                    *x = i32::from(b);
                }
                if let Some(l) = out_len.as_mut() {
                    *l = c.view_bytes().map_or(0, |v| v.len());
                }
            }
            0
        }
        Err(e) => e,
    }
}

// ---------------------------------------------------------------- configuration

/// Writes the configuration (8 bytes, see config.rs). `stored` != 0: the stored choices, else
/// the configuration in force. Readable before login (the login screen needs it).
/// # Safety
/// See module docs; `out` has 8 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_config_get(c: *mut ScyCore, stored: i32, out: *mut u8) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    let cfg = if stored != 0 { c.config_stored() } else { c.config() };
    unsafe { copy_out(&cfg.to_bytes(), out, 8) }
}

/// Unlock the configuration screen with a fresh scy_reauth. 1 ok.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_config_begin(c: *mut ScyCore) -> i32 {
    unsafe { core(c) }.map_or(0, |c| i32::from(c.config_begin()))
}

/// Store a configuration (8 bytes). 1 ok.
/// # Safety
/// See module docs; `cfg` has 8 bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_config_set(c: *mut ScyCore, cfg: *const u8) -> i32 {
    let (Some(c), Some(b)) = (unsafe { core(c) }, unsafe { bytes(cfg, 8) }) else { return 0 };
    let Ok(arr) = <[u8; 8]>::try_from(b) else { return 0 };
    i32::from(c.set_config(crate::config::Config::from_bytes(&arr)))
}

/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_config_end(c: *mut ScyCore) {
    if let Some(c) = unsafe { core(c) } {
        c.config_end();
    }
}

/// 1 if opening an item needs Face ID now (0 with "Face ID once per session" after the first).
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_reauth_required(c: *mut ScyCore) -> i32 {
    unsafe { core(c) }.map_or(1, |c| i32::from(c.reauth_required()))
}

// ---------------------------------------------------------------- tags

/// The tag set (definitions + assignments, tags.rs format) into `out`. Length or negative error.
/// # Safety
/// See module docs; `out` has `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_tags_get(c: *mut ScyCore, out: *mut u8, cap: usize) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    match c.tags_bytes() {
        Ok(b) => unsafe { copy_out(&b, out, cap) },
        Err(e) => e,
    }
}

/// Create (or reuse by name) a tag. Returns its id (> 0) or a negative error.
/// # Safety
/// See module docs; `name` has `len` bytes of UTF-8.
#[no_mangle]
pub unsafe extern "C" fn scy_tag_create(c: *mut ScyCore, name: *const u8, len: usize, color: u8) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    let Some(n) = (unsafe { bytes(name, len) }).and_then(|b| std::str::from_utf8(b).ok()) else { return -1 };
    match c.tag_create(n, color) {
        Ok(id) => i32::from(id),
        Err(e) => -e.abs(),
    }
}

/// 0 ok, else an error code.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_tag_update(c: *mut ScyCore, id: u16, name: *const u8, len: usize, color: u8) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    let Some(n) = (unsafe { bytes(name, len) }).and_then(|b| std::str::from_utf8(b).ok()) else { return -1 };
    c.tag_update(id, n, color).map_or_else(|e| e, |_| 0)
}

/// 0 ok.
/// # Safety
/// See module docs.
#[no_mangle]
pub unsafe extern "C" fn scy_tag_delete(c: *mut ScyCore, id: u16) -> i32 {
    unsafe { core(c) }.map_or(-1, |c| c.tag_delete(id).map_or_else(|e| e, |_| 0))
}

/// Tag (on != 0) or untag an item. 0 ok.
/// # Safety
/// See module docs; `item` has 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn scy_tag_set(c: *mut ScyCore, item: *const u8, id: u16, on: i32) -> i32 {
    let Some(c) = (unsafe { core(c) }) else { return -1 };
    let Some(item) = (unsafe { bytes(item, 16) }).and_then(|b| <&[u8; 16]>::try_from(b).ok()) else { return -1 };
    c.tag_set(item, id, on != 0).map_or_else(|e| e, |_| 0)
}
