use thiserror::Error;

pub type Result<T> = core::result::Result<T, SrpkError>;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum SrpkError {
    // db
    /// Failed to create database
    DBCreateTable,

    /// Failed to connect SQLite
    DBSQLConn,

    // crypt
    /// BCrypt hash failed
    BCryptHash,

    /// AES256 encrypt failed
    AES256Encrypt,

    /// AES256 decrypt failed
    AES256Decrypt,

    // file i/o
    /// File path is used
    PathTaken,

    /// File path is empty
    PathEmpty,

    /// Missing permissions
    FilePerms,

    /// UTF8Decode failed
    UTF8Decode,

    // general
    /// Missing parameter
    NoParam,

    /// No active vault
    NoVault,

    /// Duplicate key
    KeyDuplicate,

    /// Key does not exist
    KeyNonExist,

    /// No clue what went wrong
    Unknown,
}

impl core::fmt::Display for SrpkError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            SrpkError::DBCreateTable => write!(f, "failed to initialize database"),
            SrpkError::DBSQLConn => write!(f, "failed to connect sqlite"),
            SrpkError::BCryptHash => write!(f, "password hashing failed"),
            SrpkError::AES256Encrypt => write!(f, "encrypt failed"),
            SrpkError::AES256Decrypt => write!(f, "decrypt failed (bad password?)"),
            SrpkError::PathTaken => write!(f, "path is occupied"),
            SrpkError::PathEmpty => write!(f, "file not found"),
            SrpkError::FilePerms => write!(f, "missing permissions"),
            SrpkError::UTF8Decode => write!(f, "failed to decode utf-8"),
            SrpkError::NoParam => write!(f, "missing parameter"),
            SrpkError::NoVault => write!(f, "no active vault (try `srpk init`?)"),
            SrpkError::KeyDuplicate => write!(f, "key with that name exists"),
            SrpkError::KeyNonExist => write!(f, "no key with that name exists"),
            SrpkError::Unknown => write!(f, "unknown error"),
        }
    }
}
