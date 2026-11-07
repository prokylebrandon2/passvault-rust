//! Silk core: vault file format, key derivation, TOTP and autofill matching.
//! Cloud architecture: `cloud` (unlock/save flow) -> `keyslot` (Argon2id key wraps the VEK) -> `archive`
//! (Kiln's `.skln`; `interim` stands in until it exists). `local` keeps the on-device copy of both
//! objects, `session` is the unlocked state the app holds, `backup` is the one-file backup.
//! No Android or UI code lives here, so everything is unit-tested on a normal machine.
#![forbid(unsafe_code)]

pub mod archive;
pub mod autofill;
pub mod backup;
pub mod cloud;
pub mod error;
pub mod generator;
pub mod interim;
pub mod keyslot;
pub mod local;
pub mod otp;
pub mod remote;
pub mod session;
pub mod settings;
pub mod transfer;
pub mod vault;

pub use error::Error;
pub use generator::{generate, GenOptions};
pub use settings::Settings;
pub use cloud::CloudVault;
pub use vault::{generate_password, new_id, random_bytes, Entry, Kdf, Vault};
