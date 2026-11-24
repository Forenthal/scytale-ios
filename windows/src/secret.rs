//! Secret holders: fixed-size, memory-locked, zeroized on drop. No reallocation, so no stray copies.

use std::io;

use zeroize::{Zeroize, Zeroizing};

use crate::{crypto, harden};

/// 32-byte key kept in locked, heap-pinned memory.
pub struct Secret32(Box<[u8; 32]>);

impl Secret32 {
    pub fn zeroed() -> Self {
        let b = Box::new([0u8; 32]);
        harden::lock(b.as_ptr(), 32);
        Secret32(b)
    }

    pub fn from_slice(s: &[u8]) -> Self {
        assert_eq!(s.len(), 32);
        let mut k = Self::zeroed();
        k.0.copy_from_slice(s);
        k
    }

    pub fn random() -> Self {
        let mut k = Self::zeroed();
        crypto::random_bytes(&mut k.0[..]);
        k
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_mut(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}

impl Drop for Secret32 {
    fn drop(&mut self) {
        (*self.0).zeroize();
        // Pages stay locked until exit: VirtualLock is not reference counted, so unlocking one
        // key could unlock a page that still holds another.
    }
}

/// Fixed-capacity text/byte buffer for passwords and messages. Never grows, so typing and
/// backspacing leave no copies behind. Wiped on drop.
pub struct SecretInput {
    buf: Zeroizing<Vec<u8>>,
    cap: usize,
}

impl SecretInput {
    pub fn new(cap: usize) -> Self {
        let v: Vec<u8> = Vec::with_capacity(cap);
        harden::lock(v.as_ptr(), cap);
        SecretInput {
            buf: Zeroizing::new(v),
            cap,
        }
    }

    pub fn push(&mut self, c: char) -> bool {
        let mut tmp = [0u8; 4];
        let b = c.encode_utf8(&mut tmp).as_bytes();
        let ok = self.buf.len() + b.len() <= self.cap;
        if ok {
            self.buf.extend_from_slice(b);
        }
        tmp.zeroize();
        ok
    }

    /// Remove the last character, wiping its bytes.
    pub fn pop(&mut self) {
        while let Some(&last) = self.buf.last() {
            let n = self.buf.len();
            let start = n - 1;
            // wipe in place before shrinking
            self.buf[start] = 0;
            self.buf.truncate(start);
            if last & 0xC0 != 0x80 {
                break;
            }
        }
    }

    pub fn clear(&mut self) {
        self.buf.zeroize();
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf).unwrap_or("")
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn chars(&self) -> usize {
        self.as_str().chars().count()
    }
}

impl io::Write for SecretInput {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.buf.len() + data.len() > self.cap {
            return Err(io::Error::new(io::ErrorKind::OutOfMemory, "capacity"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
