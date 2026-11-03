# PassVault

An offline Android password manager written in Rust: master password + optional key file, system autofill and TOTP codes. No network permission.

## How it's built

| Part | Language | What it does |
|---|---|---|
| `core/` | Rust | Vault format, Argon2id, AES-256-GCM, key file, TOTP, autofill field detection and matching, session and idle lock. No Android code, fully unit-tested on a normal machine. |
| `app/` | Rust | The UI (Slint) and the JNI bridge. Builds to `libpassvault.so`. |
| `android/` | Java (about 450 lines, mostly comments and boilerplate) | The part Android makes mandatory: the `AutofillService` class, the document-picker result callback, clipboard, and handing an autofill result back. It holds no logic; it passes strings and bytes to Rust. |

## How the vault is protected

- Master password (and key file, if used) are hashed with SHA-256 and stretched with **Argon2id** (t=3, 64 MiB, p=4) into a 256-bit key.
- The vault is one file encrypted with **AES-256-GCM**. Every save uses a fresh random nonce, and the header (KDF settings and salt) is authenticated.
- A **key file** is any file you pick, or a random 64-byte one the app creates. It is mixed into the key, so the vault can't be opened without it. Keep a copy somewhere other than this phone. Lose the password or the key file and the vault is gone. The app remembers where the key file is, never its contents.
- Data stays in app-private storage. `allowBackup=false`, screenshots are blocked, the clipboard is flagged sensitive and cleared after 30 s. Keys and entries are zeroized when the vault locks.
- The vault locks after 5 idle minutes, when the screen turns off and when you leave the app with Back. Tune the KDF in `core/src/vault.rs` (`Kdf::default`) and the idle time in `core/src/session.rs`.
- **Back up** (list screen) saves the still-encrypted vault file. **Restore from backup** is on the create screen.

## Autofill

Tap **Turn on** in the app (or Settings > Passwords & autofill > Autofill service > PassVault). In Chrome also enable Settings > Autofill services > Autofill using another service.

A login is offered when its **Website or app** field matches the page: `https://example.com` for sites (subdomains match) or `androidapp://com.example.app` for apps. If the vault is locked the dropdown shows "Unlock PassVault", which opens a small unlock screen and returns the login to the app you were in.

## One-time passwords

Paste the Base32 setup key or the `otpauth://` link from a site's 2FA setup. TOTP with SHA-1/256/512, 6 to 8 digits, any period (RFC 6238, tested against the RFC vectors).

## Build

```
cargo test -p passvault-core                      # core tests, any machine

rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk
cargo ndk --platform 26 -t arm64-v8a -t x86_64 -o android/app/src/main/jniLibs build --release --package passvault
gradle -p android assembleDebug                   # JDK 17, Gradle 8.9, Android SDK + NDK installed
```

Slint's Android backend compiles a small Java helper while building, so `ANDROID_HOME` and a JDK must be set. Commit `Cargo.lock` after the first successful build.

## GitHub Actions (`.github/workflows/android.yml`)

| Trigger | What runs |
|---|---|
| Push to `main`, pull request, manual run | Core tests, then the Android build; the debug APK is uploaded as an artifact |
| Tag `v*` (for example `v1.0.0`) | Everything above, then a signed release APK + AAB attached to a GitHub Release |

Before tagging, add these repository secrets (Settings > Secrets and variables > Actions):

```
keytool -genkeypair -v -keystore release.jks -alias passvault -keyalg RSA -keysize 4096 -validity 10000
base64 -w0 release.jks        # paste the output as KEYSTORE_BASE64
```

`KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD`. Then `git tag v1.0.0 && git push --tags`. Back up `release.jks`: you can't update the app without it.

## Not included yet

QR scanning for OTP setup, HOTP, biometric quick unlock, saving new logins from other apps, KeePass import, an iOS app (needs a separate Swift credential-provider extension and a macOS runner).
