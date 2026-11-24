# Scytale

An encrypted vault for files, photos and burn-after-reading messages, for **iPhone** and **Windows**.
Everything is encrypted on your device. **Scytale has no account, no server and no network code.**
This repository holds the full source of both apps so you can check that claim instead of trusting it.

By [Forenthal](https://github.com/Forenthal). Source-available under the
[PolyForm Strict License 1.0.0](LICENSE.md): read it, audit it, build it for yourself; do not
redistribute, modify or sell it. See [MAINTENANCE.md](MAINTENANCE.md) for what happens to the licence
if Scytale is ever discontinued.

| Folder | What |
|---|---|
| [`core/`](core) | Rust core of the iPhone app (vault, crypto, courier) |
| [`ios/`](ios) | SwiftUI iPhone app |
| [`windows/`](windows) | Scytale for Windows, a separate Rust app ([its own README](windows/README.md)) |
| [`docs/REVIEW.md`](docs/REVIEW.md) | Guide for anyone reviewing the code, and the review status of every dependency |
| [`REVIEWS.md`](REVIEWS.md) | Public log of outside reviews and reported issues |

The two apps keep separate vaults; nothing is shared or synced between them. The only link is
**Courier**, which seals messages between a paired iPhone and PC for you to send by email.
`courier.rs` is the same file in both apps, and a CI check fails if they ever differ.

## Verify it yourself (iPhone)

1. **App Privacy Report (no tools needed).** On your iPhone, turn on
   *Settings › Privacy & Security › App Privacy Report*, use Scytale normally, then open the report.
   Every network contact an app makes is listed there by iOS. Scytale should show none.
2. **Read the code.** There is no networking anywhere in it: no `URLSession`, no `Network`
   framework, no sockets. Search the repository yourself.
3. **Entitlements.** Every release build prints the signed app's entitlements in its public build
   log and fails if iCloud, push notifications or app groups are present
   (`.github/workflows/testflight.yml`, step *Check signed entitlements*).
4. **Privacy manifest.** [`ios/Sources/PrivacyInfo.xcprivacy`](ios/Sources/PrivacyInfo.xcprivacy)
   declares no tracking and no collected data.
5. **Build it.** The Rust core builds and tests on any machine with Rust: `cd core && cargo test`.
   The iOS app builds with Xcode via `scripts/build-core.sh` and `xcodegen` (see
   `.github/workflows/build.yml` for the exact steps).

App Store downloads are encrypted by Apple, so they cannot be byte-compared with a build from
source. Steps 1 and 3 are how you check the build you actually installed.

## Windows

Scytale for Windows is source-only for now: there are no official downloads, so the copy you run is
one you built yourself from this repository (see [windows/README.md](windows/README.md#build)).
Every push is tested on a real Windows machine by `.github/workflows/windows.yml`.

## Security design (iPhone)

| Area | How |
|---|---|
| Encryption | AES-256-GCM in 64 KiB authenticated chunks; every item has its own key, stored only in that item's file |
| Unlock | Admin password (Argon2id) **and** a device secret released by the Secure Enclave only after Face ID, plus an optional authenticator code |
| Storage | iOS Data Protection *Complete* on every file; vault excluded from iCloud and computer backups; Keychain items this-device-only |
| Lockouts | 3 free attempts, then doubling lockouts to 1 h, measured on a clock that changing the date cannot shorten; 15 wrong passwords destroy the vault |
| Viewing | Decrypted only into locked memory, wiped on *Re-encrypt*; no export, copy or share out of the vault |
| Screen | Content excluded from screenshots and recordings; screen recording locks the vault |
| Audit | HMAC-chained log of security events (never names or content); tampering is detected |
| Courier | Messages and files (not photos, up to 12 MiB) between paired devices: X25519 + ML-KEM-768 (post-quantum) key agreement, Ed25519 + ML-DSA-65 signatures, AES-256-GCM; one-time keys deleted on opening, so copies left in email can never be decrypted; file names are sealed inside, sizes padded to five classes, and received files go straight into the vault |
| Integrity | Refuses to run with a debugger, on a jailbroken phone, with injected hooking code, or when re-signed by anyone but Forenthal |

The Windows design is in [windows/README.md](windows/README.md#security-design).

Cryptography comes from the RustCrypto and dalek libraries; nothing is hand-rolled. Not all of them
have been independently audited: `aes-gcm` has (NCC Group), but the post-quantum `ml-kem` and `ml-dsa`
crates state that they have not. That is one reason Courier is hybrid: to read or forge a message an
attacker must break **both** X25519 and ML-KEM-768, or **both** Ed25519 and ML-DSA-65. The review status
of every dependency is listed in [docs/REVIEW.md](docs/REVIEW.md#dependencies).

Dependencies are pinned and, on every push and weekly, checked against the RustSec advisory database
and against published dependency reviews from Mozilla, Google and others (`cargo vet`). This
repository's own practices are scored independently by
[OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/Forenthal/scytale).

## Limits

- Someone who controls your unlocked iPhone can read what you open.
- Screenshot blocking relies on undocumented iOS behaviour that Apple could change; screenshots are
  still detected and logged if it stops working.
- Importing a photo or file that exists only in iCloud makes **iOS** download it first (iOS's own
  Photos and Files services, not Scytale). Anything already in iCloud was there before Scytale.
- Lose the password and the recovery key, and the data is gone. That is by design.
- Scytale has not had a paid third-party security audit. What exists instead is listed in
  [REVIEWS.md](REVIEWS.md).

## Who makes Scytale

Forenthal is a pseudonym, and a deliberate one. You can't check who Forenthal is, but you can check
that every change comes from the same Forenthal:

- **Signed history.** Every commit and release tag since the Windows source was added is signed with
  Forenthal's signing key and shows as *Verified* on GitHub (the first two commits predate the key). The key's fingerprint is in [SECURITY.md](SECURITY.md#signing-key).
  A change signed by any other key is not from Forenthal.
- **Written commitments.** How vulnerabilities are handled and how fast: [SECURITY.md](SECURITY.md).
  How long Scytale is supported, and what happens if it stops: [MAINTENANCE.md](MAINTENANCE.md).
- **Public record.** Every fixed vulnerability gets a published advisory, and every outside review is
  logged in [REVIEWS.md](REVIEWS.md), including the ones that found problems.

## Genuine builds and copies

Genuine Scytale iPhone builds are signed by Forenthal (Apple team `RWX6R62WK4`) and show a provenance
marker under *Diagnostics › Build provenance*. A daily check
(`.github/workflows/provenance-watch.yml`) looks for that marker outside Forenthal's repositories.

## Reporting a vulnerability

Please report privately through this repository's **Security › Report a vulnerability** page, not
in a public issue. Details, scope and response times: [SECURITY.md](SECURITY.md).
