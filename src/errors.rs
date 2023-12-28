use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = core::result::Result<T, SrpkError>;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum SrpkError {
    // db
    /// Failed to create database
    #[error("failed to initialize database")]
    DBCreate,

    /// Failed to connect SQLite
    #[error("failed to connect sqlite")]
    DBSQLConn,

    // crypt
    /// BCrypt hash failed
    #[error("failed to create bcrypt hash")]
    BCryptHash,

    /// AES256 encrypt failed
    #[error("encrypt failed")]
    AES256Encrypt,

    /// AES256 decrypt failed
    #[error("decrypt failed (bad password?)")]
    AES256Decrypt,

    // file i/o
    /// File path is used
    #[error("path is occupied: {0}")]
    PathTaken(PathBuf),

    /// File path is empty
    #[error("file not found: {0}")]
    PathEmpty(PathBuf),

    /// Missing permissions
    #[error("missing permissions to modify file {0}")]
    FilePerms(PathBuf),

    /// UTF8Decode failed
    #[error("failed to decode utf-8")]
    UTF8Decode,

    // general
    /// Missing parameter
    #[error("missing parameter")]
    NoParam,

    /// No active vault
    #[error("no active vault")]
    NoVault,

    /// Duplicate key
    #[error("vault already has key {0}")]
    KeyDuplicate(String),

    /// Key does not exist
    #[error("vault has no key {0}")]
    KeyNonExist(String),

    /// No clue what went wrong
    #[error("unknown error")]
    Unknown,
}
