//! Best-effort memory locking. iOS never writes app memory to a swap file, so locking is a
//! second layer here, not the only one. Failure is harmless: secrets are still zeroized.

/// Pin pages in RAM. Best effort.
#[cfg(unix)]
pub fn lock(ptr: *const u8, len: usize) -> bool {
    // SAFETY: the caller passes a live allocation of at least `len` bytes.
    unsafe { libc::mlock(ptr.cast(), len) == 0 }
}

#[cfg(not(unix))]
pub fn lock(_ptr: *const u8, _len: usize) -> bool {
    false
}

/// Windows needs its working set raised before large locks; nothing to do on iOS.
pub fn working_set(_min: usize, _max: usize) -> bool {
    true
}

pub fn reset_working_set() {}
