use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NotAVault,
    Corrupt,
    Locked,
    KeyFileRequired,
    KeyFileNotUsed,
    WrongCredentials,
    Crypto,
    Random,
    Io(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotAVault => f.write_str("This isn't a PassVault file."),
            Error::Corrupt => f.write_str("The vault file is damaged."),
            Error::Locked => f.write_str("The vault is locked. Unlock it and try again."),
            Error::KeyFileRequired => f.write_str("This vault needs its key file. Choose it and try again."),
            Error::KeyFileNotUsed => f.write_str("This vault doesn't use a key file. Clear the key file and try again."),
            Error::WrongCredentials => f.write_str("Wrong password or key file. Check both and try again."),
            Error::Crypto => f.write_str("Encryption failed on this device."),
            Error::Random => f.write_str("Couldn't get secure random numbers from the system."),
            Error::Io(e) => write!(f, "Couldn't read or write the vault: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}
