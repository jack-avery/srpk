use std::{fs::remove_file, path::Path};

use crate::crypt::aes256_encrypt;
use crate::errors::{
    Error::{NewDBFinalizeFailed, NewDBPathTaken, NewDBPathUnavailable, NewDBTableFailed},
    Result,
};

const VERIFY_TEXT: &str = "srpk";

pub fn init(path: &str, pass: &str) -> Result<()> {
    let path: &Path = Path::new(path);
    if path.exists() {
        return Err(NewDBPathTaken);
    };
    let Ok(connection) = sqlite::open(path) else {
        return Err(NewDBPathUnavailable);
    };

    let created = connection.execute("CREATE TABLE srpk (key TEXT, value TEXT);");
    if created.is_err() {
        return Err(NewDBTableFailed);
    }

    let verify: &str = &aes256_encrypt(VERIFY_TEXT, pass)?;
    let verified = connection.execute(format!(
        "INSERT INTO srpk VALUES ('~VERIFY', '{}');",
        verify
    ));
    if verified.is_err() {
        return Err(NewDBFinalizeFailed);
    };

    Ok(())
}

mod tests {
    use std::panic;

    use super::*;

    const PATH: &str = "./test.db";

    #[test]
    fn test_create() {
        ensure_clean(|| {
            let pass: &str = "password";
            init(PATH, pass).unwrap();
        })
    }

    fn ensure_clean<T>(test: T)
    where
        T: FnOnce() + panic::UnwindSafe,
    {
        let path = Path::new(PATH);

        if path.exists() {
            remove_file(path).unwrap();
        }
        let result = panic::catch_unwind(|| test());
        if path.exists() {
            remove_file(path).unwrap();
        }

        assert!(result.is_ok())
    }
}
