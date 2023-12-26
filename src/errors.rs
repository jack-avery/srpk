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

    /// Bad password
    BadPassword,
}

impl std::error::Error for Error {}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::DBCreateTable => write!(f, "failed to initialize database"),
            Error::DBEncrypt => write!(f, "failed to encrypt database"),
            Error::BCryptHash => write!(f, "password hashing failed"),
            Error::Base64Decode => write!(f, "base64decode failed"),
            Error::AES256Encrypt => write!(f, "aes256encrypt failed"),
            Error::AES256Decrypt => write!(f, "aes256decrypt failed"),
            Error::UTF8Decode => write!(f, "utf-8 decode failed"),
            Error::PathTaken => write!(f, "something already exists at that path"),
            Error::FilePerms => write!(f, "missing permissions to modify that path"),
            Error::NoParam => write!(f, "missing parameter"),
            Error::BadPassword => write!(f, "bad password"),
        }
    }
}
