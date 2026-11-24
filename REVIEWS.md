# Reviews and reported issues

Every outside review of Scytale is logged here, including ones that found nothing and ones that
found serious problems. Nothing is removed. How to add one: [docs/REVIEW.md](docs/REVIEW.md#logging-a-review).

Scytale has **not** had a paid third-party security audit.

## Outside reviews

None yet.

## Issues found and fixed

| Date | App | Found by | Issue | Fix |
|---|---|---|---|---|
| 2026-11-23 | Windows | `cargo audit` (RustSec) | `quick-xml` 0.37 used by the `.docx` viewer had two denial-of-service bugs ([RUSTSEC-2026-0194](https://rustsec.org/advisories/RUSTSEC-2026-0194), [RUSTSEC-2026-0195](https://rustsec.org/advisories/RUSTSEC-2026-0195)): a crafted Word file could hang the app or exhaust memory. No data exposure. | Upgraded to 0.42, with a test that a hostile start tag parses in bounded time |
| 2026-11-23 | Windows | `cargo audit` (RustSec) | `ratatui` 0.29 pulled in `lru` 0.12, flagged unsound ([RUSTSEC-2026-0002](https://rustsec.org/advisories/RUSTSEC-2026-0002), [RUSTSEC-2026-0253](https://rustsec.org/advisories/RUSTSEC-2026-0253)), and the unmaintained `paste` | Upgraded to `ratatui` 0.30 with unused features turned off |
| 2026-11-23 | Both | Forenthal | The README said all cryptography came from audited libraries. `ml-kem` and `ml-dsa` have never been audited. | Corrected, with the real status of each dependency in [docs/REVIEW.md](docs/REVIEW.md#dependencies) |
