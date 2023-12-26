use std::{fs::{read, write, remove_file}, path::Path};

use crate::crypt::aes256_encrypt;
use crate::errors::{
    Error::{PathTaken, FilePerms, DBCreateTable, DBEncrypt},
    Result,
};

/// Initialize a vault and encrypt it
pub fn init(path: &str, pass: &str) -> Result<()> {
    // verify clean slate
    let path: &Path = Path::new(path);
    if path.exists() {
        return Err(PathTaken);
    };

    // create the initial DB
    let Ok(connection) = sqlite::open(path) else {
        return Err(FilePerms);
    };
    let created = connection.execute("CREATE TABLE srpk (key TEXT, value TEXT);");
    if created.is_err() {
        return Err(DBCreateTable);
    }
    drop(connection);
    // file perms should be solid by this point: we can unwrap everything else from here

    // encrypt
    let db_raw: Vec<u8> = read(path).unwrap();
    let Ok(db_enc) = aes256_encrypt(&db_raw, pass) else {
        return Err(DBEncrypt)
    };

    // overwrite
    remove_file(path).unwrap();
    write(path, db_enc).unwrap();

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
        let result = panic::catch_unwind(test);
        if path.exists() {
            remove_file(path).unwrap();
        }

        assert!(result.is_ok())
    }
}
