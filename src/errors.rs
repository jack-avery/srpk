pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
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

impl std::error::Error for Error {}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::DBCreateTable => write!(f, "failed to initialize database"),
            Error::DBSQLConn => write!(f, "failed to connect sqlite"),
            Error::BCryptHash => write!(f, "password hashing failed"),
            Error::AES256Encrypt => write!(f, "encrypt failed"),
            Error::AES256Decrypt => write!(f, "decrypt failed (bad password?)"),
            Error::PathTaken => write!(f, "path is occupied"),
            Error::PathEmpty => write!(f, "file not found"),
            Error::FilePerms => write!(f, "missing permissions"),
            Error::UTF8Decode => write!(f, "failed to decode utf-8"),
            Error::NoParam => write!(f, "missing parameter"),
            Error::NoVault => write!(f, "no active vault (try `srpk init`?)"),
            Error::KeyDuplicate => write!(f, "key with that name exists"),
            Error::KeyNonExist => write!(f, "no key with that name exists"),
            Error::Unknown => write!(f, "unknown error"),
        }
    }
}
