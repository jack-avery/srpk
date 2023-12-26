pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    // db
    /// Failed to create database
    DBCreateTable,

    /// Failed to encrypt database
    DBEncrypt,

    // crypt
    /// BCrypt hash failed
    BCryptHash,

    /// Base64 decode failed
    Base64Decode,

    /// AES256 encrypt failed
    AES256Encrypt,

    /// AES256 decrypt failed
    AES256Decrypt,

    /// UTF-8 decode failed
    UTF8Decode,

    // file i/o
    /// File path is used
    PathTaken,

    /// Missing permissions
    FilePerms,

    // general
    /// Missing parameter
    NoParam,
}

impl std::error::Error for Error {}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::DBCreateTable => write!(f, "failed to initialize database"),
            Error::DBEncrypt => write!(f, "failed to encrypt database"),
            Error::BCryptHash => write!(f, "password hashing failed"),
            Error::Base64Decode => write!(f, "base64decode failed"),
            Error::AES256Encrypt => write!(f, "encrypt failed"),
            Error::AES256Decrypt => write!(f, "decrypt failed (bad password?)"),
            Error::UTF8Decode => write!(f, "utf-8 decode failed"),
            Error::PathTaken => write!(f, "path is occupied"),
            Error::FilePerms => write!(f, "missing permissions"),
            Error::NoParam => write!(f, "missing parameter"),
        }
    }
}
