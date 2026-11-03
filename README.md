# PassVault

An offline Android password manager written in Rust: master password + optional key file, system autofill and TOTP codes. No network permission.

## How it's built

| Part | Language | What it does |
|---|---|---|
| `core/` | Rust | Vault format, Argon2id, AES-256-GCM, key file, TOTP, autofill field detection and matching, session and idle lock. No Android code, fully unit-tested on a normal machine. |
| `app/` | Rust | The UI (Slint) and the JNI bridge. Builds to `libpassvault.so`. |
| `browser-extension/` | JavaScript | A Brave/Chrome extension (Manifest V3) that opens a copy of your vault, fills logins and shows one-time codes. See below. |
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

## Screens

Four tabs along the bottom: **Logins**, **Codes**, **Generator** and **More**.

## Codes (built-in authenticator)

The **Codes** tab lists every login that has a one-time password, with a live code and countdown. Tap a row to copy its code, **Edit** to open the login, **Add** to set up a new authenticator from a Base32 setup key or an `otpauth://` link (it is saved as its own entry). TOTP with SHA-1/256/512, 6 to 8 digits, any period (RFC 6238, tested against the RFC vectors). There is no QR scanner yet: paste the setup key the site shows next to the QR code.

## Password generator

The **Generator** tab sets the length (8 to 64), which sets to use (a-z, A-Z, 0-9, symbols), whether to leave out look-alikes (`l I 1 O 0 o`) and whether new logins start with a generated password. Every selected set is guaranteed to appear. The choices are saved in `settings.json` in the app's private storage (nothing secret in it). The **Generate** link on the login form uses the same settings.

## Proton Pass import and export

**More > Import from Proton Pass** reads an *unencrypted* Proton Pass export: `.json` (or the `Data.json` inside the `.zip`) or `.csv`. Logins, notes, aliases and cards are brought over (cards and other non-login items become entries whose notes hold the fields). Items in Proton's trash are skipped, passkeys cannot be moved, and logins that already exist in the vault (same title, username, website and password) are skipped. Other CSVs with the usual columns (`name`, `url`, `username`, `password`, `note`, `totp`) also work, including Bitwarden's.

**More > Export for Proton Pass** writes CSV (Proton's own column layout) or JSON. These files are **not encrypted**; the app asks you to confirm and reminds you to delete the file after importing it. Encrypted (PGP) Proton exports are not supported: export again without encryption.

The JSON layout is reconstructed from Proton's documented export format, not from a file I could open on a real account. If Proton Pass refuses the JSON, use the CSV.

## Brave extension

`browser-extension/` is a Manifest V3 extension for Brave (and any Chromium browser). It is a read-only copy of your phone's vault:

1. In the app: **More > Back up vault**, move the `.pvlt` file to your computer.
2. Brave: `brave://extensions`, turn on Developer mode, **Load unpacked**, pick the `browser-extension` folder (or unzip the `passvault-brave-extension` artifact from CI).
3. Click the extension, choose the `.pvlt` file, enter the master password (and the key file if the vault uses one).

It opens the same file format (Argon2id + AES-256-GCM, with its own Argon2 in JavaScript; unlocking takes a few seconds), suggests logins for the current site, fills username and password into the page you are on when you click **Fill**, fills or copies one-time codes, and locks after 5 idle minutes. It asks before filling a login on a site that doesn't match the login's address. Permissions are only `storage`, `alarms`, `activeTab` and `scripting`: it can touch a page only when you click Fill. The encrypted file is kept in the extension's local storage; decrypted logins live in session storage, which the browser never writes to disk. It never edits the vault: to update the copy, back up again in the app and re-add the file. It does not clear the clipboard for you, and JavaScript can't reliably wipe memory.

`cd browser-extension && npm test` runs the tests (Argon2 against the RFC 9106 vectors, vault opening, RFC 6238 codes, site matching). Needs Node 18 or newer.

## Build

```
cargo test -p passvault-core                      # core tests, any machine
(cd browser-extension && npm test)                # extension tests, Node 18+

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

QR scanning for OTP setup, HOTP, passphrase generation, biometric quick unlock, saving new logins from other apps, KeePass import, editing the vault from the browser extension, an iOS app (needs a separate Swift credential-provider extension and a macOS runner).
