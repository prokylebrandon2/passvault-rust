use crate::error::Error;
use crate::vault::{Entry, Vault};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

/// Holds the unlocked vault in memory and the path of the encrypted file. Locks itself after
/// `idle` without activity. Key derivation is slow, so callers do it *outside* this struct and
/// hand the opened vault to [`Session::install`].
pub struct Session {
    dir: Option<PathBuf>,
    vault: Option<Vault>,
    last_use: Option<Instant>,
    idle: Duration,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub const fn new() -> Self {
        Session { dir: None, vault: None, last_use: None, idle: Duration::from_secs(300) }
    }

    pub fn set_dir(&mut self, dir: PathBuf) {
        self.dir = Some(dir);
    }

    pub fn set_idle_limit(&mut self, idle: Duration) {
        self.idle = idle;
    }

    fn path(&self) -> Result<PathBuf, Error> {
        self.dir
            .as_ref()
            .map(|d| d.join("vault.pvlt"))
            .ok_or_else(|| Error::Io("no data directory".into()))
    }

    pub fn exists(&self) -> bool {
        self.path().map(|p| p.exists()).unwrap_or(false)
    }

    /// The encrypted vault file, as stored on disk.
    pub fn read_file(&self) -> Result<Vec<u8>, Error> {
        Ok(fs::read(self.path()?)?)
    }

    pub fn touch(&mut self) {
        self.last_use = Some(Instant::now());
    }

    pub fn check_idle(&mut self) {
        if self.vault.is_some() {
            if let Some(t) = self.last_use {
                if t.elapsed() > self.idle {
                    self.lock();
                }
            }
        }
    }

    pub fn is_unlocked(&mut self) -> bool {
        self.check_idle();
        self.vault.is_some()
    }

    /// Drops the vault, which wipes its key and entries.
    pub fn lock(&mut self) {
        self.vault = None;
    }

    /// Takes over an opened or freshly created vault. `persist` writes it to disk first (new vaults).
    pub fn install(&mut self, vault: Vault, persist: bool) -> Result<(), Error> {
        if persist {
            let bytes = vault.seal()?;
            self.write(&bytes)?;
        }
        self.vault = Some(vault);
        self.touch();
        Ok(())
    }

    /// The entries, or `None` while locked.
    pub fn entries(&mut self) -> Option<&[Entry]> {
        self.check_idle();
        self.vault.as_ref().map(|v| v.entries.as_slice())
    }

    pub fn upsert(&mut self, e: Entry) -> Result<(), Error> {
        self.check_idle();
        let bytes = {
            let v = self.vault.as_mut().ok_or(Error::Locked)?;
            v.upsert(e);
            v.seal()?
        };
        self.write(&bytes)?;
        self.touch();
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> Result<(), Error> {
        self.check_idle();
        let bytes = {
            let v = self.vault.as_mut().ok_or(Error::Locked)?;
            v.remove(id);
            v.seal()?
        };
        self.write(&bytes)?;
        self.touch();
        Ok(())
    }

    /// Adds imported logins in one save. A login already in the vault (same title, username, website
    /// and password) is skipped. Returns `(added, duplicates)`.
    pub fn merge_entries(&mut self, incoming: Vec<Entry>) -> Result<(usize, usize), Error> {
        self.check_idle();
        let (bytes, added, dups) = {
            let v = self.vault.as_mut().ok_or(Error::Locked)?;
            let (mut added, mut dups) = (0usize, 0usize);
            for mut e in incoming {
                if v.entries.iter().any(|x| same_login(x, &e)) {
                    e.zeroize();
                    dups += 1;
                } else {
                    v.upsert(e);
                    added += 1;
                }
            }
            let bytes = if added > 0 { Some(v.seal()?) } else { None };
            (bytes, added, dups)
        };
        if let Some(b) = bytes {
            self.write(&b)?;
        }
        self.touch();
        Ok((added, dups))
    }

    /// Replaces the stored vault with a backup file (which stays encrypted).
    pub fn import(&mut self, bytes: &[u8]) -> Result<(), Error> {
        Vault::validate(bytes)?;
        self.write(bytes)
    }

    fn write(&self, data: &[u8]) -> Result<(), Error> {
        let path = self.path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        Ok(())
    }
}

fn same_login(a: &Entry, b: &Entry) -> bool {
    a.title.trim().eq_ignore_ascii_case(b.title.trim())
        && a.username.trim().eq_ignore_ascii_case(b.username.trim())
        && a.url.trim().eq_ignore_ascii_case(b.url.trim())
        && a.password == b.password
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{new_id, Kdf};

    const FAST: Kdf = Kdf { t: 1, mem_kib: 64, p: 1 };

    fn temp_session() -> Session {
        let dir = std::env::temp_dir().join(format!("passvault-test-{}", new_id()));
        let mut s = Session::new();
        s.set_dir(dir);
        s
    }

    fn entry(id: &str) -> Entry {
        Entry {
            id: id.into(),
            title: "Site".into(),
            username: "me".into(),
            password: "pw".into(),
            url: String::new(),
            otp: String::new(),
            notes: String::new(),
        }
    }

    #[test]
    fn create_save_lock_and_reopen() {
        let mut s = temp_session();
        assert!(!s.exists());
        s.install(Vault::create("password1", None, FAST).unwrap(), true).unwrap();
        assert!(s.exists());
        s.upsert(entry("1")).unwrap();
        assert_eq!(s.entries().unwrap().len(), 1);

        s.lock();
        assert!(s.entries().is_none());
        assert_eq!(s.upsert(entry("2")).err(), Some(Error::Locked));

        let bytes = s.read_file().unwrap();
        s.install(Vault::open(&bytes, "password1", None).unwrap(), false).unwrap();
        assert_eq!(s.entries().unwrap()[0].id, "1");
        s.remove("1").unwrap();
        assert!(s.entries().unwrap().is_empty());
    }

    #[test]
    fn locks_itself_when_idle() {
        let mut s = temp_session();
        s.install(Vault::create("password1", None, FAST).unwrap(), true).unwrap();
        s.set_idle_limit(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(15));
        assert!(!s.is_unlocked());
    }

    #[test]
    fn import_accepts_backups_and_rejects_other_files() {
        let mut a = temp_session();
        a.install(Vault::create("password1", None, FAST).unwrap(), true).unwrap();
        let backup = a.read_file().unwrap();

        let mut b = temp_session();
        assert_eq!(b.import(b"hello").err(), Some(Error::NotAVault));
        b.import(&backup).unwrap();
        assert!(b.exists());
    }

    #[test]
    fn merge_skips_duplicates_and_saves_once() {
        let mut s = temp_session();
        s.install(Vault::create("password1", None, FAST).unwrap(), true).unwrap();
        s.upsert(entry("1")).unwrap();
        let mut same = entry("other-id");
        same.title = "SITE".into(); // case differs only
        let mut fresh = entry("2");
        fresh.title = "Fresh".into();
        assert_eq!(s.merge_entries(vec![same, fresh]).unwrap(), (1, 1));
        assert_eq!(s.entries().unwrap().len(), 2);
        // what was merged is on disk
        let bytes = s.read_file().unwrap();
        assert_eq!(Vault::open(&bytes, "password1", None).unwrap().entries.len(), 2);
        s.lock();
        assert_eq!(s.merge_entries(vec![entry("3")]).err(), Some(Error::Locked));
    }
}
