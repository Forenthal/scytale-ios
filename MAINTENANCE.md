# Maintenance and support

Scytale is made by one person under the name Forenthal. This file says what you can rely on.

## What keeps working no matter what

Scytale has no server and no account. Your vault never depends on Forenthal being around: the app
on your device keeps working offline. The one outside risk is a future iOS or Windows update
breaking it, which is what security updates below are for.

## Supported versions

- **iPhone:** the latest App Store version. Security fixes are released for as long as Scytale is on
  the App Store, and for at least 12 months after it is removed.
- **Windows:** the latest commit on `main` (there are no official Windows releases yet).

Older versions do not get fixes; update to the latest.

## Support

Questions and bugs that aren't security problems: open an issue in this repository.
Security problems: see [SECURITY.md](SECURITY.md). Refunds for the iPhone app go through Apple
(*reportaproblem.apple.com*), as for any App Store purchase.

## If Scytale is discontinued

If Forenthal stops maintaining Scytale, the source does not stay locked away:

1. **Notice.** Discontinuation is announced in this repository at least **90 days** in advance.
2. **Relicensing.** On the announced date, the source is relicensed under the
   [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) or the
   [MIT License](https://opensource.org/license/mit) (your choice), so anyone may maintain, fix,
   fork and redistribute it.
3. **Automatic trigger.** If there is no signed commit to `main` for **24 consecutive months**, this
   counts as discontinuation without notice, and the relicensing in step 2 takes effect on the day
   after those 24 months end. Nobody has to ask Forenthal for permission, and Forenthal does not have
   to be reachable.

### Additional permission

Forenthal, as the copyright holder, grants the following in addition to the
[PolyForm Strict License 1.0.0](LICENSE.md):

> Each version of the software in this repository is also licensed to you under your choice of the
> Apache License 2.0 or the MIT License, effective from the earlier of (a) the discontinuation date
> announced in this repository, or (b) the day after 24 consecutive months pass with no signed
> commit to the `main` branch of this repository. This permission cannot be withdrawn for any
> version published while it was in this file.
