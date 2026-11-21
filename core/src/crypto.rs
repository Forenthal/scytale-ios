//! All cryptography. Only vetted RustCrypto primitives; nothing hand-rolled.
//! AES-256-GCM for data and key wrapping, Argon2id + HKDF-SHA256 for key derivation.

use std::io::{Read, Write};

use aes_gcm::{
    aead::{
        generic_array::GenericArray,
        stream::{DecryptorBE32, EncryptorBE32},
        Aead, KeyInit, Payload,
    },
    Aes256Gcm,
};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    harden,
    secret::Secret32,
    util::{ioe, Res},
};

/// Plaintext bytes per AES-GCM chunk in the streaming format.
pub const CHUNK: usize = 64 * 1024;
const TAG: usize = 16;

pub fn random_bytes(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("system RNG unavailable");
}

// ---------------------------------------------------------------- key derivation

#[derive(Clone, Copy)]
pub struct Kdf {
    pub m: u32, // KiB
    pub t: u32,
    pub p: u32,
}

impl Kdf {
    #[cfg(not(test))]
    pub const DEFAULT: Kdf = Kdf { m: 256 * 1024, t: 3, p: 4 };
    #[cfg(test)]
    pub const DEFAULT: Kdf = Kdf { m: 8 * 1024, t: 1, p: 1 };

    pub fn valid(&self) -> bool {
        (8 * 1024..=1024 * 1024).contains(&self.m)
            && (1..=20).contains(&self.t)
            && (1..=16).contains(&self.p)
    }
}

/// Argon2id with the working memory pinned in RAM (best effort) and wiped afterwards.
pub fn argon2id(password: &[u8], salt: &[u8], k: &Kdf) -> Res<Secret32> {
    if !k.valid() {
        return Err("invalid kdf parameters".into());
    }
    let params = Params::new(k.m, k.t, k.p, Some(32)).map_err(|_| "invalid kdf parameters")?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let n = argon.params().block_count();
    let bytes = n * std::mem::size_of::<Block>();

    let raised = harden::working_set(bytes + (64 << 20), bytes + (192 << 20));
    let mut blocks = vec![Block::default(); n];
    if raised {
        harden::lock(blocks.as_ptr().cast(), bytes);
    }

    let mut out = Secret32::zeroed();
    let r = argon.hash_password_into_with_memory(password, salt, out.as_mut(), &mut blocks[..]);
    blocks.zeroize();
    drop(blocks);
    harden::reset_working_set();
    r.map_err(|_| "key derivation failed".to_string())?;
    Ok(out)
}

pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> Secret32 {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut k = Secret32::zeroed();
    hk.expand(info, k.as_mut()).expect("hkdf length");
    k
}

// ---------------------------------------------------------------- small AEAD (key wrapping)

fn cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(GenericArray::from_slice(key))
}

/// nonce(12) || ciphertext || tag(16)
pub fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    random_bytes(&mut nonce);
    let ct = cipher(key)
        .encrypt(GenericArray::from_slice(&nonce), Payload { msg: plaintext, aad })
        .expect("aes-gcm encrypt");
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn open(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if blob.len() < 12 + TAG {
        return None;
    }
    let (nonce, ct) = blob.split_at(12);
    cipher(key)
        .decrypt(GenericArray::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
        .map(Zeroizing::new)
}

// ---------------------------------------------------------------- streaming AEAD (files, messages)

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Res<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(ioe(e)),
        }
    }
    Ok(n)
}

/// 7-byte random nonce prefix, then 64 KiB AES-256-GCM chunks. Chunk order and the final chunk
/// are authenticated, so reordering, dropping or truncating chunks is detected.
/// Returns the SHA-256 of the plaintext (used to verify a write before the original is erased).
pub fn encrypt_stream<R: Read, W: Write>(
    r: &mut R,
    w: &mut W,
    key: &[u8; 32],
    aad: &[u8],
) -> Res<[u8; 32]> {
    let mut prefix = [0u8; 7];
    random_bytes(&mut prefix);
    w.write_all(&prefix).map_err(ioe)?;
    let mut enc = EncryptorBE32::from_aead(cipher(key), GenericArray::from_slice(&prefix));
    let mut hasher = Sha256::new();
    let mut cur = Zeroizing::new(vec![0u8; CHUNK]);
    let mut nxt = Zeroizing::new(vec![0u8; CHUNK]);
    let mut n = read_full(r, &mut cur)?;
    loop {
        hasher.update(&cur[..n]);
        let m = read_full(r, &mut nxt)?;
        if m == 0 {
            let ct = enc
                .encrypt_last(Payload { msg: &cur[..n], aad })
                .map_err(|_| "encryption failed".to_string())?;
            w.write_all(&ct).map_err(ioe)?;
            break;
        }
        let ct = enc
            .encrypt_next(Payload { msg: &cur[..n], aad })
            .map_err(|_| "encryption failed".to_string())?;
        w.write_all(&ct).map_err(ioe)?;
        std::mem::swap(&mut cur, &mut nxt);
        n = m;
    }
    Ok(hasher.finalize().into())
}

pub fn decrypt_stream<R: Read, W: Write>(
    r: &mut R,
    w: &mut W,
    key: &[u8; 32],
    aad: &[u8],
) -> Res<[u8; 32]> {
    let mut prefix = [0u8; 7];
    r.read_exact(&mut prefix).map_err(|_| "corrupt data".to_string())?;
    let mut dec = DecryptorBE32::from_aead(cipher(key), GenericArray::from_slice(&prefix));
    let mut hasher = Sha256::new();
    let mut cur = vec![0u8; CHUNK + TAG];
    let mut nxt = vec![0u8; CHUNK + TAG];
    let mut n = read_full(r, &mut cur)?;
    if n < TAG {
        return Err("corrupt data".into());
    }
    loop {
        let m = read_full(r, &mut nxt)?;
        let auth = || "authentication failed: data is corrupt or was modified".to_string();
        if m == 0 {
            let pt = Zeroizing::new(dec.decrypt_last(Payload { msg: &cur[..n], aad }).map_err(|_| auth())?);
            hasher.update(&pt[..]);
            w.write_all(&pt).map_err(ioe)?;
            break;
        }
        let pt = Zeroizing::new(dec.decrypt_next(Payload { msg: &cur[..n], aad }).map_err(|_| auth())?);
        hasher.update(&pt[..]);
        w.write_all(&pt).map_err(ioe)?;
        std::mem::swap(&mut cur, &mut nxt);
        n = m;
        if n < TAG {
            return Err("corrupt data".into());
        }
    }
    Ok(hasher.finalize().into())
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

// ---------------------------------------------------------------- HMAC (audit chain / state)

pub fn hmac256(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

// ---------------------------------------------------------------- TOTP (RFC 6238, SHA-1, 6 digits, 30 s)

pub const TOTP_STEP: u64 = 30;

pub fn totp_code(secret: &[u8], step: u64) -> u32 {
    let mut m = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("hmac key");
    m.update(&step.to_be_bytes());
    let h = m.finalize().into_bytes();
    let o = (h[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]);
    bin % 1_000_000
}

/// Accepts the current step and one either side. Returns the matched step, which must be newer
/// than `last_step` (a code can be used only once).
pub fn totp_verify(secret: &[u8], now: u64, code: &str, last_step: u64) -> Option<u64> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let cur = now / TOTP_STEP;
    let mut hit = None;
    for step in cur.saturating_sub(1)..=cur + 1 {
        let want = format!("{:06}", totp_code(secret, step));
        if bool::from(want.as_bytes().ct_eq(code.as_bytes())) && step > last_step {
            hit = Some(step);
        }
    }
    hit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_rfc6238_vector() {
        // RFC 6238 appendix B, SHA-1, T = 59 s -> 94287082 (8 digits) => last 6 = 287082
        let secret = b"12345678901234567890";
        assert_eq!(totp_code(secret, 59 / 30), 287082);
    }

    #[test]
    fn stream_roundtrip_and_tamper() {
        let key = [7u8; 32];
        for size in [0usize, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 5] {
            let data: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
            let mut ct = Vec::new();
            let h1 = encrypt_stream(&mut &data[..], &mut ct, &key, b"id").unwrap();
            let mut pt = Vec::new();
            let h2 = decrypt_stream(&mut &ct[..], &mut pt, &key, b"id").unwrap();
            assert_eq!(pt, data, "size {size}");
            assert_eq!(h1, h2);
            // wrong aad / key
            assert!(decrypt_stream(&mut &ct[..], &mut Vec::new(), &key, b"xx").is_err());
            assert!(decrypt_stream(&mut &ct[..], &mut Vec::new(), &[8u8; 32], b"id").is_err());
            // bit flip
            let mut bad = ct.clone();
            let i = bad.len() / 2;
            bad[i] ^= 1;
            assert!(decrypt_stream(&mut &bad[..], &mut Vec::new(), &key, b"id").is_err());
            // truncation (drop the last chunk or part of it)
            if ct.len() > 7 + TAG {
                let cut = &ct[..ct.len() - 1];
                assert!(decrypt_stream(&mut &cut[..], &mut Vec::new(), &key, b"id").is_err());
            }
            if size > CHUNK {
                let cut = &ct[..7 + CHUNK + TAG];
                assert!(decrypt_stream(&mut &cut[..], &mut Vec::new(), &key, b"id").is_err());
            }
        }
    }

    /// cargo test --release -- --ignored kdf_timing --nocapture
    #[test]
    #[ignore]
    fn kdf_timing() {
        let k = Kdf { m: 256 * 1024, t: 3, p: 4 };
        let t = std::time::Instant::now();
        argon2id(b"password", &[0u8; 16], &k).unwrap();
        println!("argon2id 256 MiB t=3 p=4: {:?}", t.elapsed());
    }

    #[test]
    fn seal_open() {
        let k = [1u8; 32];
        let s = seal(&k, b"a", b"hello");
        assert_eq!(&open(&k, b"a", &s).unwrap()[..], b"hello");
        assert!(open(&k, b"b", &s).is_none());
    }
}
