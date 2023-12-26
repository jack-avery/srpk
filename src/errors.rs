pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    // db

    /// Cannot create database (a file already exists)
    NewDBPathTaken,

    /// Cannot create database (unknown error)
    NewDBPathUnavailable,

    /// Failed to create database (create table failed)
    NewDBTableFailed,

    /// Failed to create database (verification failed)
    NewDBFinalizeFailed,

    // crypt

    /// Base64 decode failed
    Base64Decode,

    /// AES256 encrypt failed
    AES256Encrypt,

    /// AES256 decrypt failed
    AES256Decrypt,

    /// UTF-8 decode failed
    UTF8Decode,

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
            Error::NewDBPathTaken => write!(f, "something already exists at that path"),
            Error::NewDBPathUnavailable => write!(f, "could not access path"),
            Error::NewDBTableFailed => write!(f, "failed to initialize database"),
            Error::NewDBFinalizeFailed => write!(f, "failed to finalize database"),
            Error::Base64Decode => write!(f, "base64decode failed"),
            Error::AES256Encrypt => write!(f, "aes256encrypt failed"),
            Error::AES256Decrypt => write!(f, "aes256decrypt failed"),
            Error::UTF8Decode => write!(f, "utf-8 decode failed"),
            Error::NoParam => write!(f, "missing parameter"),
            Error::BadPassword => write!(f, "bad password"),
        }
    }
}