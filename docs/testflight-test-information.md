# TestFlight Test Information (paste into App Store Connect)

## Beta App Description
Scytale is an encrypted vault for files, photos and burn-after-reading messages. Everything is encrypted on the
iPhone with AES-256-GCM, keys stay in the Secure Enclave and Keychain, and nothing is synced or backed up.

Please test:
- Setup: admin password, authenticator code, Face ID device key, recovery key.
- Adding items: Scytale's camera, Photos, Files. Opening an item (Decrypt, then Re-encrypt).
- Tags: press and hold a file.
- Messages and the Courier (sealed messages between paired devices).
- Configuration: auto-lock, timeout, 2FA requirement.

## What to Test (this build)
Tags with colours (press and hold a file), new app icon, configuration screen.

## Feedback Email
FEEDBACK_EMAIL_PLACEHOLDER

## Sign-In Information
Sign-in required: **No**. Scytale has no account. On first launch the tester creates a local vault.

## Review Notes (Beta App Review)
Scytale has no account and no server; it makes no network connections. To review:

1. Use an iPhone with a device passcode and Face ID set up. The vault key is created in the Secure Enclave and
   requires both, so setup cannot complete without them.
2. On first launch choose Begin, then create an admin password of at least 14 characters.
3. Add the shown key to any authenticator app (for example Google Authenticator with sync off, or any TOTP app),
   then enter its 6-digit code.
4. Tap Create device key and confirm with Face ID.
5. A recovery key is shown once. Type SAVED to continue.
6. The vault opens. Camera, Photos and Files add encrypted items; tap an item, then Decrypt (Face ID) to view it,
   and Re-encrypt to close it. Press and hold a file to tag it.

Expected behaviour:
- Scytale locks when the app is left, after inactivity, or when the screen is recorded.
- Screenshots are blocked inside Scytale and end the session.
- Camera, Face ID, Photos (only for deleting originals) and Notifications (local login alerts) permission prompts
  are expected.
- The app refuses to run on jailbroken devices or with a debugger attached.

## Privacy Policy URL
https://forenthal.github.io/scytale-privacy/
