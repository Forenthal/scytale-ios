//! Proves the core computes correctly on the target device: published test vectors for
//! AES-256-GCM, HKDF-SHA256 and TOTP, plus round-trip and tamper detection of the vault format.

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit, Payload},
    Aes256Gcm,
};

use crate::crypto::{self, Kdf, CHUNK};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn check(ok: bool, n: i32) -> Result<(), i32> {
    if ok {
        Ok(())
    } else {
        Err(n)
    }
}

pub fn run() -> Result<(), i32> {
    // 1. AES-256-GCM known answer (GCM spec test case 14: zero key, zero IV, 16 zero bytes).
    let c = Aes256Gcm::new(GenericArray::from_slice(&[0u8; 32]));
    let ct = c
        .encrypt(GenericArray::from_slice(&[0u8; 12]), Payload { msg: &[0u8; 16], aad: b"" })
        .map_err(|_| 1)?;
    check(
        ct == hex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"),
        1,
    )?;

    // 2. HKDF-SHA256 known answer (RFC 5869 test case 1, first 32 bytes of OKM).
    let k = crypto::hkdf(&[0x0b; 22], &hex("000102030405060708090a0b0c"), &hex("f0f1f2f3f4f5f6f7f8f9"));
    check(
        k.as_bytes()[..] == hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")[..],
        2,
    )?;

    // 3. TOTP known answer (RFC 6238 appendix B, T = 59 s).
    check(crypto::totp_code(b"12345678901234567890", 59 / 30) == 287082, 3)?;

    // 4. Key wrapping: round trip, wrong AAD rejected, wrong key rejected.
    let key = [9u8; 32];
    let sealed = crypto::seal(&key, b"a", b"hello");
    check(crypto::open(&key, b"a", &sealed).map(|p| &p[..] == b"hello") == Some(true), 4)?;
    check(crypto::open(&key, b"b", &sealed).is_none(), 4)?;
    check(crypto::open(&[8u8; 32], b"a", &sealed).is_none(), 4)?;

    // 5. Streaming format: round trip across chunk boundaries, then tampering of every kind.
    for size in [0usize, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 5] {
        let data: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
        let mut ct = Vec::new();
        let h1 = crypto::encrypt_stream(&mut &data[..], &mut ct, &key, b"id").map_err(|_| 5)?;
        let mut pt = Vec::new();
        let h2 = crypto::decrypt_stream(&mut &ct[..], &mut pt, &key, b"id").map_err(|_| 5)?;
        check(pt == data && h1 == h2, 5)?;

        let mut bad = ct.clone();
        let i = bad.len() / 2;
        bad[i] ^= 1;
        check(crypto::decrypt_stream(&mut &bad[..], &mut Vec::new(), &key, b"id").is_err(), 6)?;
        check(crypto::decrypt_stream(&mut &ct[..ct.len() - 1], &mut Vec::new(), &key, b"id").is_err(), 7)?;
        check(crypto::decrypt_stream(&mut &ct[..], &mut Vec::new(), &key, b"xx").is_err(), 8)?;
        if size > CHUNK {
            let cut = &ct[..7 + CHUNK + 16];
            check(crypto::decrypt_stream(&mut &cut[..], &mut Vec::new(), &key, b"id").is_err(), 9)?;
        }
    }

    // 6. Argon2id: deterministic, salt-sensitive, rejects out-of-range parameters.
    let small = Kdf { m: 8 * 1024, t: 1, p: 1 };
    let a = crypto::argon2id(b"pw", &[1u8; 16], &small).map_err(|_| 10)?;
    let b = crypto::argon2id(b"pw", &[1u8; 16], &small).map_err(|_| 10)?;
    let d = crypto::argon2id(b"pw", &[2u8; 16], &small).map_err(|_| 10)?;
    check(a.as_bytes() == b.as_bytes() && a.as_bytes() != d.as_bytes(), 10)?;
    check(crypto::argon2id(b"pw", &[1u8; 16], &Kdf { m: 1024, t: 1, p: 1 }).is_err(), 11)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn selftest_passes() {
        assert_eq!(super::run(), Ok(()));
    }
}
