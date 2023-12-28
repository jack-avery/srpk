use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = core::result::Result<T, SrpkError>;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum SrpkError {
    /// Failed to connect SQLite
    #[error("sqlite error: {0}")]
    SQLiteError(#[from] sqlite::Error),

    /// BCrypt hash failed
    #[error("bcrypt error: {0}")]
    BCryptHash(#[from] bcrypt::BcryptError),

    /// AES256
    #[error("encrypt/decrypt failed (bad password?)")]
    AES256(#[from] aes_gcm_siv::Error),

    /// IOError
    #[error("io error: {0}")]
    IOError(#[from] std::io::Error),

    /// File path is taken
    #[error("path is occupied: {0}")]
    PathTaken(PathBuf),

    /// File path is empty
    #[error("file not found: {0}")]
    PathEmpty(PathBuf),

    /// UTF8Decode failed
    #[error("utf8 decode failed: {0}")]
    UTF8Decode(#[from] std::string::FromUtf8Error),

    // general
    /// Missing parameter
    #[error("missing parameter")]
    NoParam,

    /// No active vault
    #[error("no active vault (try srpk init?)")]
    NoVault,

    /// Duplicate key
    #[error("vault already has key {0}")]
    KeyDuplicate(String),

    /// Key does not exist
    #[error("vault has no key {0}")]
    KeyNonExist(String),

    /// Name is reserved
    #[error("cannot use reserved term {0}")]
    KeyReserved(String),

    /// No clue what went wrong
    #[error("unknown error")]
    Unknown,
}
