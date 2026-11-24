//! Process hardening: no crash dumps, no error dialogs, best-effort memory locking.

use windows_sys::Win32::System::Diagnostics::Debug::{
    SetErrorMode, SetUnhandledExceptionFilter, EXCEPTION_POINTERS, SEM_FAILCRITICALERRORS,
    SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX,
};
use windows_sys::Win32::System::ErrorReporting::WerSetFlags;
use windows_sys::Win32::System::Memory::VirtualLock;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetProcessWorkingSetSize};

const BASE_WS_MIN: usize = 32 << 20;
const BASE_WS_MAX: usize = 128 << 20;

/// EXCEPTION_EXECUTE_HANDLER: terminate silently, so no dump is produced.
unsafe extern "system" fn crash_filter(_: *const EXCEPTION_POINTERS) -> i32 {
    1
}

pub fn init() {
    // SAFETY: plain Win32 calls with valid constant arguments.
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
        // WER_FAULT_REPORTING_FLAG_NOHEAP (1) | WER_FAULT_REPORTING_NO_UI (32)
        WerSetFlags(1 | 32);
        SetUnhandledExceptionFilter(Some(crash_filter));
    }
    working_set(BASE_WS_MIN, BASE_WS_MAX);
}

pub fn working_set(min: usize, max: usize) -> bool {
    // SAFETY: current-process pseudo handle, plain sizes.
    unsafe { SetProcessWorkingSetSize(GetCurrentProcess(), min, max) != 0 }
}

pub fn reset_working_set() {
    working_set(BASE_WS_MIN, BASE_WS_MAX);
}

/// Pin pages in RAM so they are never written to the pagefile. Best effort.
pub fn lock(ptr: *const u8, len: usize) -> bool {
    // SAFETY: the caller passes a live allocation.
    unsafe { VirtualLock(ptr.cast(), len) != 0 }
}
