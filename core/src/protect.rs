//! iOS Data Protection. Every file Scytale creates is put in class A ("Complete") before data is
//! written: its per-file key is evicted from memory whenever the phone is locked, so the file is
//! unreadable, even to Scytale, until the next unlock.
//!
//! On a real iPhone this fails closed: if the class cannot be set and read back, nothing is written.
//! The simulator and the Mac test host have no Data Protection, so there it is a no-op.

use std::fs::File;

use crate::util::Res;

#[cfg(all(target_os = "ios", not(target_abi = "sim")))]
pub fn complete(f: &File) -> Res<()> {
    use std::os::fd::AsRawFd;
    // xnu <sys/fcntl.h>
    const F_GETPROTECTIONCLASS: libc::c_int = 63;
    const F_SETPROTECTIONCLASS: libc::c_int = 64;
    const PROTECTION_CLASS_A: libc::c_int = 1;
    let fd = f.as_raw_fd();
    // SAFETY: fd is a live descriptor owned by `f`; both calls take plain integer arguments.
    let (set, get) = unsafe {
        (
            libc::fcntl(fd, F_SETPROTECTIONCLASS, PROTECTION_CLASS_A),
            libc::fcntl(fd, F_GETPROTECTIONCLASS),
        )
    };
    if set == 0 && get == PROTECTION_CLASS_A {
        Ok(())
    } else {
        Err("file protection could not be applied".into())
    }
}

#[cfg(not(all(target_os = "ios", not(target_abi = "sim"))))]
pub fn complete(_f: &File) -> Res<()> {
    Ok(())
}

/// Reports the class actually applied to a file (device only; -1 elsewhere). For diagnostics.
#[cfg(all(target_os = "ios", not(target_abi = "sim")))]
pub fn class_of(f: &File) -> i32 {
    use std::os::fd::AsRawFd;
    // SAFETY: as above.
    unsafe { libc::fcntl(f.as_raw_fd(), 63) }
}

#[cfg(not(all(target_os = "ios", not(target_abi = "sim"))))]
pub fn class_of(_f: &File) -> i32 {
    -1
}
