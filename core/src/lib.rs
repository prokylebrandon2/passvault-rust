//! PassVault core: vault file format, key derivation, TOTP and autofill matching.
//! No Android or UI code lives here, so everything is unit-tested on a normal machine.
#![forbid(unsafe_code)]

pub mod autofill;
pub mod error;
pub mod otp;
pub mod session;
pub mod vault;

pub use error::Error;
pub use vault::{generate_password, new_id, random_bytes, Entry, Kdf, Vault};
