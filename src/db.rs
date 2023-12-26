use std::{fs::{read, write, remove_file}, path::Path};

use crate::crypt::{aes256_encrypt, aes256_decrypt};
use crate::errors::{
    Error::{PathTaken, PathEmpty, FilePerms, DBCreateTable, DBSQLConn},
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
    let db_enc: Vec<u8> = aes256_encrypt(&db_raw, pass)?;

    // overwrite
    remove_file(path).unwrap();
    write(path, db_enc).unwrap();

    Ok(())
}

fn decrypt(path: &str, pass: &str) -> Result<sqlite::Connection> {
    // verify vault exists & temp path is available
    let mut path_temp_str: String = path.to_owned();
    path_temp_str.push_str(".temp");

    let path: &Path = Path::new(path);
    if !path.exists() {
        return Err(PathEmpty);
    };
    let path_temp: &Path = Path::new(&path_temp_str);
    if path_temp.exists() {
        return Err(PathTaken);
    };

    // decrypt
    let Ok(db_enc) = read(path) else {
        return Err(FilePerms);
    };
    let db_raw: Vec<u8> = aes256_decrypt(&db_enc, pass)?;

    // create temp and return a connection
    if write(path_temp, db_raw).is_err() {
        return Err(FilePerms);
    };
    match sqlite::open(path_temp) {
        Ok(conn) => Ok(conn),
        Err(_) => Err(DBSQLConn)
    }
}

mod tests {
    use super::*;

    const PASS: &str = "password";

    #[test]
    fn test_create() {
        std::fs::create_dir("db_test_create").unwrap();
        init("db_test_create/test.db", PASS).unwrap();
        std::fs::remove_dir_all("db_test_create").unwrap();
    }

    #[test]
    fn test_decrypt() {
        std::fs::create_dir("db_test_decrypt").unwrap();
        init("./db_test_decrypt/test.db", PASS).unwrap();
        decrypt("./db_test_decrypt/test.db", PASS).unwrap();
        std::fs::remove_dir_all("db_test_decrypt").unwrap();
    }
}
