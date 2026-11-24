# Scytale for Windows

By [Forenthal](https://github.com/Forenthal). Source-available under the [PolyForm Strict License 1.0.0](../LICENSE.md),
like the rest of this repository. There are no official Windows downloads yet: build it from this source
(see *Build* at the end). Security policy, maintenance commitments and the review guide are shared with the
iPhone app: [SECURITY.md](../SECURITY.md), [MAINTENANCE.md](../MAINTENANCE.md), [docs/REVIEW.md](../docs/REVIEW.md).

Local, single-admin vault for files and burn-after-reading messages. Terminal-style interface in its own
window, Windows 10 (2004+) / 11 only.

Run `Scytale.exe`. The first run walks you through setup: password, authenticator, recovery key.
Vault data lives in `%LOCALAPPDATA%\Scytale`. Decrypted data is never written to disk: files can be viewed inside
Scytale, but there is no way to export them.

## Commands

| command | what it does |
|---|---|
| `ls` | list vault contents |
| `enc <file>` | encrypt a file into the vault, verify it, then overwrite and delete the original. The full path, spaces allowed, quotes optional |
| `dec <id>` | view a file inside Scytale (password re-entry). It is decrypted into locked memory only, and closing the viewer wipes it. See the viewer section below. Limit 64 MiB |
| `msg` | write a message. Ctrl+D seals it |
| `read <id>` | open a message once (password re-entry). It is deleted from disk immediately and wiped from the screen after 5 minutes, or when you press K/Esc |
| `purge <id> yes` | permanently destroy a file or unread message |
| `audit [n]` | last n audit entries and an integrity verdict |
| `passwd` | change the password |
| `lock` / `exit` | lock / lock and quit |
| `wipe DESTROY` | **panic wipe**: destroys the entire vault (files, messages, keys, audit log). No undo, no recovery |
| `pair` | courier pairing status and safety number |
| `pair export <path>` / `pair import <path>` | write this PC's signed key bundle / import the other device's (by email) |
| `pair verify MATCH` | confirm the safety numbers match on both screens |
| `pair unpair yes` | forget the paired device |
| `send <yes\|no> [path\|text]` | seal a courier message for the paired device (yes = destroy when received). No path: a `.scy` file on the Desktop; a folder or file path: written there (`.txt` = pasteable text); `text`: encrypted text to the clipboard for an email body |
| `recv [path]` | open a courier message (password re-entry); its one-time key is destroyed on open. No path: the encrypted block pasted at the prompt (Ctrl+V), or else the clipboard |

**Courier** (shared with Scytale for iPhone): X25519 + ML-KEM-768 hybrid key agreement per message, HKDF-SHA-512,
AES-256-GCM, Ed25519 + ML-DSA-65 hybrid signatures; one one-time key per message, deleted by the recipient on
open, so copies left in email can never be decrypted. Sender rules and message id are sealed inside; replays are
refused; lengths are padded. State is sealed in the vault (`courier.scy`) under a key derived from the master key.

Keys: Ctrl+V pastes (e.g. a path from Explorer's "Copy as path"), Ctrl+Plus / Ctrl+Minus / Ctrl+0 change the text
size, and the mouse wheel scrolls in the viewer.

**Viewer (`dec`):**
- **Text files** (any encoding) show as scrollable text.
- **Images** (PNG, JPEG, GIF, BMP, WebP) show as real pixels.
- **PDFs** render page by page through the PDF engine built into Windows, fed from memory. Up/Down scrolls,
  PgUp/PgDn changes page, and F toggles fit-width / whole page.
- **Word `.docx`** files open in a reading view: headings, bold/italic/underline, bulleted and numbered lists, tables,
  embedded images and page breaks. Exact page layout (fonts, columns, positioning) is not reproduced.
- **Anything else** shows as hex. `H` toggles hex for any file.

**Auto-exit:** Scytale wipes everything from memory and exits after 5 minutes without a keypress (on any screen),
and immediately when Windows is locked, the user is switched, the PC sleeps or shuts down, or the window is closed.
Each of these is logged with the session length (`TIMEOUT`, `WIN_LOCK`, `SUSPEND`, `SHUTDOWN`, `LOGOUT`), and
the next start shows why the previous session ended.

## Security design

- **Crypto:** AES-256-GCM for everything. Files and messages are encrypted in 64 KiB authenticated chunks, so
  reordering, truncation or any bit flip is detected. RustCrypto crates only; nothing is hand-rolled.
- **Keys:** password → Argon2id (256 MiB, t=3) + a secret sealed by Windows DPAPI to your account → HKDF →
  key that unwraps the master key. A copied vault folder is useless without your Windows account and password.
  The recovery key is a separate wrap of the same master key.
- **Per-item keys:** each file or message has its own random key, wrapped by the master key and stored only in that
  item's blob. Shredding the blob destroys the key (crypto-shredding) as well as the ciphertext.
- **Login:** password + TOTP. Each code works once. 3 free attempts, then lockouts double from 30 s up
  to 1 h. The counter is persisted and HMAC-protected, so restarting the app or editing the state file does not reset it.
  Tampering triggers a 15-minute lock.
- **Re-authentication** is required for every decrypt, every message open and every password change.
- **Screen capture protection:** the window is excluded from screenshots, screen recording and screen sharing
  (`WDA_EXCLUDEFROMCAPTURE`). Captures show whatever is behind it. Because Scytale is not a console app, no other
  program can read its screen text through the console APIs either.
- **Audit log** (`audit.log`): sequence, UTC timestamp, event code and, for logouts, session length. No names,
  paths, sizes or content. Entries are HMAC-chained with a DPAPI-protected key: edits, deletions and truncation
  are reported at login and by `audit`. A session killed without logging out is recorded as `ABORTED` on the next start.
- **No other output:** no debug logs, no temp files, no plaintext on disk. Crash dumps and error-report dialogs are
  disabled, panics exit silently, and secrets are zeroized and kept in locked memory where Windows allows it.
- **Untrusted content:** every displayed string is stripped of control characters. Document parsing (ZIP/XML for
  `.docx`, image decoders) is memory-safe Rust with limits against decompression bombs.

## Limits

- **Secure deletion is best effort.** SSD wear-levelling, Volume Shadow Copies, backups and OneDrive/cloud-synced
  folders can keep old copies of an original file. Turn on BitLocker, and don't encrypt from synced folders.
- **Someone who controls your logged-in Windows session** (malware, or physical access while the vault is unlocked) can
  read what you open, log keystrokes, and tamper with the audit log and lockout state using the same DPAPI access.
  The log is tamper-evident against everyone else.
- **Screen capture protection** stops software capture, not a phone camera pointed at the screen.
- **Lockout uses the system clock**, so changing the clock can shorten a lockout. Argon2id still makes every guess slow.
- **Viewer memory:** the decrypted file buffer is locked and wiped. Windows' PDF engine keeps its own internal copies
  while a PDF is open: Scytale overwrites the stream it hands over and each rendered page, but cannot wipe the engine's
  private memory. Image-decoder scratch buffers and on-screen glyph caches are freed without wiping.
- **Unsupported:** password-protected PDFs, legacy `.doc` / `.xls` / `.ppt` (save them as `.docx` first), and
  Excel/PowerPoint files (they show as hex).
- **Lost password and lost recovery key** means the data is gone. That is by design.
- **Panic wipe** destroys the vault header first. That header holds the only wrapped copies of the master key, so the
  data cannot be decrypted afterwards even if file fragments survive on an SSD. Older header copies left in free disk
  space by past password changes are the remaining SSD caveat; BitLocker covers it.
- **Sleep detection:** on PCs with Modern Standby, Windows may not announce sleep beforehand. Scytale also exits
  on lock, which Windows normally triggers at standby, and on any wall-clock jump over 60 s.
  While a long operation is running (big file encryption, rendering a PDF page), these checks wait until it finishes.
- **Recovery key at setup:** auto-exit also applies on the setup screen that shows the recovery key. If you walk away
  before saving it, it is gone, and the vault is still usable with your password.

## Build

Needs Windows 10 (2004+) or 11 and a Rust toolchain (MSVC). From this folder:

```
cargo test --locked --release
cargo build --locked --release
```

The program is `target\release\scytale.exe`. `--locked` builds exactly the dependency versions in `Cargo.lock`,
which are the versions checked by the `supply-chain` workflow.
