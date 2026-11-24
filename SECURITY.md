# Security policy

## Reporting a vulnerability

Report privately through this repository's **Security › Report a vulnerability** page
(GitHub private vulnerability reporting). Please don't open a public issue for a security problem.

Useful to include: which app (iPhone or Windows) and version, what an attacker can do, and the steps
or code to reproduce it. You don't need a working exploit.

## What happens next

| Step | Commitment |
|---|---|
| Acknowledgement | within 7 days |
| First assessment (valid or not, and severity) | within 14 days |
| Fix for a critical or high issue | released within 30 days of the assessment |
| Fix for a medium or low issue | in the next release |
| Public advisory | published on this repository's Security page once a fix is out, with a CVE for anything medium or above |

You will be kept informed throughout, and credited in the advisory and in [REVIEWS.md](REVIEWS.md)
unless you ask not to be. If a commitment is missed, the advisory will say so and why.

There is no paid bug bounty.

## Scope

In scope: anything in this repository. That covers the iPhone app (`core/`, `ios/`), the Windows app
(`windows/`), the courier protocol shared between them, and the build workflows.

Out of scope, because the design already lists them as limits (see the READMEs):
- An attacker who already controls your unlocked device or logged-in Windows session.
- Losing both the password and the recovery key.
- Photographing the screen with another device.

Reports showing that a listed limit is *worse* than described are in scope.

## Safe harbour

Good-faith research on your own devices and your own vaults is welcome. Forenthal will not take
action against research that stays within this policy, avoids other people's data, and gives a
reasonable time to fix before publishing.

## Signing key

From the commit that added the Windows source onward, every commit and release tag by Forenthal is
signed with this SSH key, and GitHub shows it as **Verified**:

```
SHA256:VlJZar6QA1ILhaewHlMQN7yo4GiFPcaklchOblEpI0w  (ED25519)
```

The full public key is in [`.github/allowed_signers`](.github/allowed_signers). It is also
registered as a signing key on the Forenthal GitHub account, which is what GitHub's *Verified* badge
checks against.

To check a clone yourself, without trusting GitHub:

```
git config gpg.ssh.allowedSignersFile .github/allowed_signers
git log --show-signature
```

Each signed commit shows `Good "git" signature for 296084948+Forenthal@users.noreply.github.com`.
If the key ever has to change, the new key is announced in a commit signed by the old one.

## Supported versions

See [MAINTENANCE.md](MAINTENANCE.md).
