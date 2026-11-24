# Reviewing Scytale

Scytale has not had a paid third-party audit. This guide is for anyone who wants to check it
themselves: where the security-critical code is, what it is supposed to guarantee, and how to test it.
If you review any part, please log it (see the end), whether you find something or not.

## What Scytale claims

1. **No network.** Neither app contains networking code. (iPhone: no `URLSession`, `Network` or
   sockets. Windows: no `WinHTTP`, `WinINet` or sockets.)
2. **Nothing decrypted touches disk.** Files are decrypted only into locked memory for viewing, and
   there is no export path.
3. **A copied vault is useless.** Keys are derived from the password via Argon2id *and* a device-bound
   secret (Secure Enclave on iPhone, DPAPI on Windows).
4. **Deleting an item destroys its key** (crypto-shredding), and a panic wipe destroys the master key.
5. **Courier messages** can't be read or forged unless an attacker breaks both the classical and the
   post-quantum half, and an old message left in email can't be decrypted once it has been opened.
6. **Tampering is detected** in the audit log and the lockout state.

A break of any of these is a vulnerability: report it through [SECURITY.md](../SECURITY.md).

## Where to look

| Area | iPhone | Windows |
|---|---|---|
| Cryptographic primitives and key wrapping | `core/src/crypto.rs` | `windows/src/crypto.rs` |
| Key derivation, master key, recovery key | `core/src/secret.rs`, `core/src/vault.rs` | `windows/src/secret.rs`, `windows/src/vault.rs` |
| Device-bound secret | `ios/Sources/Platform/DeviceKey.swift`, `KeychainSecret.swift` | `windows/src/dpapi.rs` |
| Courier protocol (same file in both) | `core/src/courier.rs` | `windows/src/courier.rs` |
| Audit log | `core/src/audit.rs` | `windows/src/audit.rs` |
| Secure deletion and panic wipe | `core/src/wipe.rs` | `windows/src/wipe.rs` |
| Memory protection | `ios/Sources/Core/SecureMemory.swift`, `core/src/harden.rs` | `windows/src/harden.rs` |
| Parsing untrusted files | (images via iOS) | `windows/src/docx.rs`, `windows/src/pdf.rs`, `windows/src/viewer.rs` |
| Anti-tamper | `ios/Sources/Platform/Integrity.swift` | none |

Good first questions: Is any nonce ever reused? Can a wrong password be told apart from a corrupt
file by timing? Does any path write plaintext or a key to disk, the clipboard or a log? Can a
crafted `.docx` or courier message crash, hang or confuse either app?

## Running the tests

```
cd core && cargo test --locked --release          # any OS
cd windows && cargo test --locked --release       # Windows only
```

The iPhone app's Swift tests need a Mac with Xcode; `.github/workflows/build.yml` shows the steps.
Every push runs all of them in public on GitHub Actions.

## Dependencies

Cryptography comes from the RustCrypto and dalek projects. "Audit" below means a published,
independent security audit stated by the crate itself. "cargo-vet" means a published code review of
the exact version in use, by Mozilla, Google, Bytecode Alliance, ISRG or Zcash, imported by `cargo vet`.

| Crate | Used for | Independent audit | cargo-vet review of this version |
|---|---|---|---|
| `aes-gcm` 0.10 | all encryption | yes, NCC Group | no |
| `argon2` 0.5 | password hashing | none stated | no |
| `hkdf` 0.12, `sha2` 0.10 | key derivation | none stated | no |
| `hmac` 0.12 | audit log, lockout state, TOTP | none stated | **yes** |
| `subtle` 2 | constant-time comparisons | none stated | **yes** |
| `zeroize` 1 | wiping secrets | none stated | **yes** |
| `x25519-dalek`, `ed25519-dalek` 3.0 | Courier (classical half) | none stated for this version | no |
| `ml-kem` 0.3, `ml-dsa` 0.1 | Courier (post-quantum half) | **never audited** (the crates say so) | no |
| `quick-xml` 0.42 | Windows `.docx` viewer | none stated | no |
| `image` 0.25 | Windows image viewer | none stated | no |

The full lists are in `core/supply-chain/config.toml` and `windows/supply-chain/config.toml`: every
crate under `[[exemptions]]` has no imported review yet. That is the honest current state, not a
claim that those crates are unsafe. Totals today: iPhone core 17 of 73 crates reviewed, Windows 33
of 191.

Because `ml-kem` and `ml-dsa` are unaudited, Courier never relies on them alone: the message key
comes from HKDF over *both* the X25519 and the ML-KEM shared secrets, and messages must pass *both*
signatures.

## Logging a review

If you've reviewed any part of Scytale, open an issue titled *Review: <what you looked at>* with:
the commit you reviewed, what you covered, how long it took, and what you found (or "nothing").
It goes into [REVIEWS.md](../REVIEWS.md) with your name or handle and a link to your public profile,
so readers can judge the reviewer as well as the review. Vulnerabilities go through
[SECURITY.md](../SECURITY.md) first.
