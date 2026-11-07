//! The archive layer: what turns the entries into the encrypted vault file stored next to the key slot.
//!
//! The intended archive is Kiln's `.skln` (Kiln is a separate project; `.skln` is not in it yet).
//! Until it is, [`crate::interim`] stands in so the rest of the cloud flow can be built and
//! tested. Everything above this layer talks to [`Archiver`] only, so moving to Kiln is a new
//! `impl Archiver` and a one-line change to [`Current`].
//!
//! What the flow needs from an archiver:
//! - **A raw 32-byte key.** Silk runs Argon2id itself and hands over the VEK. A password-based
//!   envelope (Kiln's current scrypt lock) is not what is wanted here.
//! - **Bytes in, bytes out.** No temp files, no paths: the vault is a few hundred KB and lives in memory.
//! - **An authenticated revision counter** readable from the plain header, so a replayed old file can be noticed.
//! - **A small, lean build:** no CLI or multi-codec dependencies pulled into the Android library.
use crate::error::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// One named blob inside an archive. Wiped on drop.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Member {
    pub name: String,
    pub data: Vec<u8>,
}

impl Member {
    pub fn new(name: &str, data: Vec<u8>) -> Member {
        Member {
            name: name.to_owned(),
            data,
        }
    }
}

/// A decrypted archive.
#[derive(Debug)]
pub struct Opened {
    /// Increases by one on every save. Compare it with the last value seen to catch rollbacks.
    pub revision: u64,
    pub members: Vec<Member>,
}

impl Opened {
    pub fn get(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.name == name)
    }
}

pub trait Archiver {
    /// Name of the stored object, for example `vault.skln`.
    fn file_name(&self) -> &'static str;
    /// Archives `members` and encrypts them with the VEK. Every call uses a fresh nonce.
    fn seal(&self, vek: &[u8; 32], revision: u64, members: &[Member]) -> Result<Vec<u8>, Error>;
    /// Decrypts and unpacks. A wrong key, a changed header and a changed body all fail with `Corrupt`.
    fn open(&self, vek: &[u8; 32], file: &[u8]) -> Result<Opened, Error>;
    /// The revision from the plain header, without the key.
    fn revision(&self, file: &[u8]) -> Result<u64, Error>;
}

/// The archiver in use. Change this one line when Kiln's `.skln` is ready.
pub type Current = crate::interim::Interim;

pub fn current() -> Current {
    Current::default()
}
