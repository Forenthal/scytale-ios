# Scytale for iPhone

An encrypted vault for files, photos and burn-after-reading messages. Everything is encrypted on the
iPhone. **Scytale has no account, no server and no network code.** This repository exists so you can
check that claim instead of trusting it.

By [Forenthal](https://github.com/Forenthal). Source-available under the
[PolyForm Strict License 1.0.0](LICENSE.md): read it, audit it, build it for yourself; do not
redistribute, modify or sell it.

## Verify it yourself

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

## Security design

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

Cryptography comes from audited RustCrypto and dalek libraries; nothing is hand-rolled.
Dependencies are pinned and checked against the RustSec advisory database on every build.

## Limits

- Someone who controls your unlocked iPhone can read what you open.
- Screenshot blocking relies on undocumented iOS behaviour that Apple could change; screenshots are
  still detected and logged if it stops working.
- Importing a photo or file that exists only in iCloud makes **iOS** download it first (iOS's own
  Photos and Files services, not Scytale). Anything already in iCloud was there before Scytale.
- Lose the password and the recovery key, and the data is gone. That is by design.

## Genuine builds and copies

Genuine Scytale builds are signed by Forenthal (Apple team `RWX6R62WK4`) and show a provenance
marker under *Diagnostics › Build provenance*. A daily check
(`.github/workflows/provenance-watch.yml`) looks for that marker outside Forenthal's repositories.

## Reporting a vulnerability

Please report privately through this repository's **Security › Report a vulnerability** page, not
in a public issue.
