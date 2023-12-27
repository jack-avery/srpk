use sqlite::{Connection, State, Value};
use std::{
    fs::{read, remove_file, write},
    path::Path,
};

use crate::crypt::{aes256_decrypt, aes256_encrypt};
use crate::errors::{
    Error::{DBCreateTable, DBSQLConn, FilePerms, KeyDuplicate, KeyNonExist, PathEmpty, PathTaken},
    Result,
};

const PASSWORD_NEW_SQL: &str = "INSERT INTO srpk VALUES (:key, :pass);";
const PASSWORD_GET_SQL: &str = "SELECT value FROM srpk WHERE key = ?;";
const PASSWORD_DEL_SQL: &str = "DELETE FROM srpk WHERE key = ?";
const PASSWORD_LS_SQL: &str = "SELECT key FROM srpk;";

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

/// Decrypt a vault to a temp file and return the connection
pub fn decrypt(path: &str, pass: &str) -> Result<Connection> {
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
        Err(_) => Err(DBSQLConn),
    }
}

/// Close the sqlite connection and remove. <br/>
/// If `changed`, encrypt contents of `path.db.temp` and apply to `path.db`.
pub fn finish(path: &str, pass: &str, changed: bool) -> Result<()> {
    let mut path_temp_str: String = path.to_owned();
    path_temp_str.push_str(".temp");
    let path_temp: &Path = Path::new(&path_temp_str);

    if changed {
        let path: &Path = Path::new(path);
        let Ok(db_raw) = read(path_temp) else {
            return Err(FilePerms);
        };
        let db_enc: Vec<u8> = aes256_encrypt(&db_raw, pass)?;
        remove_file(path).unwrap();
        write(path, db_enc).unwrap();
    }

    remove_file(path_temp).unwrap();
    Ok(())
}

/// Create a new password in a vault.
pub fn password_new(conn: &Connection, key: &str, pass: &str) -> Result<()> {
    if password_get(conn, key)?.is_some() {
        return Err(KeyDuplicate);
    };

    let Ok(mut statement) = conn.prepare(PASSWORD_NEW_SQL) else {
        return Err(DBSQLConn);
    };
    if statement
        .bind_iter::<_, (_, Value)>([(":key", key.into()), (":pass", pass.into())])
        .is_err()
    {
        return Err(DBSQLConn);
    };
    while let Ok(State::Row) = statement.next() {}
    Ok(())
}

/// Get a password from a vault. `None` if given key is missing.
pub fn password_get(conn: &Connection, key: &str) -> Result<Option<String>> {
    let Ok(mut statement) = conn.prepare(PASSWORD_GET_SQL) else {
        return Err(DBCreateTable);
    };
    if statement.bind((1, key)).is_err() {
        return Err(DBSQLConn);
    };
    if let Ok(State::Row) = statement.next() {
        return Ok(Some(statement.read::<String, _>("value").unwrap()));
    }
    Ok(None)
}

/// Delete a password from a vault.
pub fn password_del(conn: &Connection, key: &str) -> Result<()> {
    if password_get(conn, key)?.is_none() {
        return Err(KeyNonExist);
    };

    let Ok(mut statement) = conn.prepare(PASSWORD_DEL_SQL) else {
        return Err(DBCreateTable);
    };
    if statement.bind((1, key)).is_err() {
        return Err(DBSQLConn);
    };
    while let Ok(State::Row) = statement.next() {}
    Ok(())
}

pub fn password_ls(conn: &Connection) -> Result<Vec<String>> {
    let Ok(mut statement) = conn.prepare(PASSWORD_LS_SQL) else {
        return Err(DBCreateTable);
    };
    let mut keys: Vec<String> = Vec::new();
    while let Ok(State::Row) = statement.next() {
        keys.push(statement.read::<String, _>("key").unwrap());
    }
    Ok(keys)
}

mod tests {
    use super::*;

    const PASS: &str = "password";
    const KEY1: &str = "key1";
    const KEY2: &str = "key2";

    #[test]
    fn test_create() {
        std::fs::create_dir("db_test_decrypt").unwrap();
        init("./db_test_decrypt/test.db", PASS).unwrap();
        decrypt("./db_test_decrypt/test.db", PASS).unwrap();
        std::fs::remove_dir_all("db_test_decrypt").unwrap();
    }

    #[test]
    fn test_password() {
        std::fs::create_dir("db_test_password_new").unwrap();
        init("./db_test_password_new/test.db", PASS).unwrap();
        let conn: Connection = decrypt("./db_test_password_new/test.db", PASS).unwrap();

        password_new(&conn, KEY1, PASS).unwrap();
        let read: Option<String> = password_get(&conn, KEY1).unwrap();
        assert!(read.is_some());
        assert_eq!(read.unwrap(), PASS);

        drop(conn);
        std::fs::remove_dir_all("db_test_password_new").unwrap();
    }

    #[test]
    fn test_finish_unchanged() {
        std::fs::create_dir("db_test_finish_unchanged").unwrap();
        init("./db_test_finish_unchanged/test.db", PASS).unwrap();
        let before: Vec<u8> = std::fs::read("./db_test_finish_unchanged/test.db").unwrap();
        let conn: Connection = decrypt("./db_test_finish_unchanged/test.db", PASS).unwrap();

        password_new(&conn, KEY1, PASS).unwrap();
        finish("./db_test_finish_unchanged/test.db", PASS, false).unwrap();
        drop(conn);
        let after: Vec<u8> = std::fs::read("./db_test_finish_unchanged/test.db").unwrap();

        assert_eq!(before, after);
        std::fs::remove_dir_all("db_test_finish_unchanged").unwrap();
    }

    #[test]
    fn test_finish_changed() {
        std::fs::create_dir("db_test_finish_changed").unwrap();
        init("./db_test_finish_changed/test.db", PASS).unwrap();
        let before: Vec<u8> = std::fs::read("./db_test_finish_changed/test.db").unwrap();
        let conn: Connection = decrypt("./db_test_finish_changed/test.db", PASS).unwrap();

        password_new(&conn, KEY1, PASS).unwrap();
        finish("./db_test_finish_changed/test.db", PASS, true).unwrap();
        drop(conn);
        let after: Vec<u8> = std::fs::read("./db_test_finish_changed/test.db").unwrap();

        assert_ne!(before, after);
        std::fs::remove_dir_all("db_test_finish_changed").unwrap();
    }

    #[test]
    fn test_password_new_duplicate() {
        std::fs::create_dir("db_test_password_new_duplicate").unwrap();
        init("./db_test_password_new_duplicate/test.db", PASS).unwrap();
        let conn: Connection = decrypt("./db_test_password_new_duplicate/test.db", PASS).unwrap();

        password_new(&conn, KEY1, PASS).unwrap();
        assert!(password_new(&conn, KEY1, PASS).is_err());

        drop(conn);
        std::fs::remove_dir_all("db_test_password_new_duplicate").unwrap();
    }

    #[test]
    fn test_password_del() {
        std::fs::create_dir("db_test_password_del").unwrap();
        init("./db_test_password_del/test.db", PASS).unwrap();
        let conn: Connection = decrypt("./db_test_password_del/test.db", PASS).unwrap();

        password_new(&conn, KEY1, PASS).unwrap();
        password_del(&conn, KEY1).unwrap();

        drop(conn);
        std::fs::remove_dir_all("db_test_password_del").unwrap();
    }

    #[test]
    fn test_password_del_missing() {
        std::fs::create_dir("db_test_password_del_missing").unwrap();
        init("./db_test_password_del_missing/test.db", PASS).unwrap();
        let conn: Connection = decrypt("./db_test_password_del_missing/test.db", PASS).unwrap();

        assert!(password_del(&conn, KEY1).is_err());

        drop(conn);
        std::fs::remove_dir_all("db_test_password_del_missing").unwrap();
    }

    #[test]
    fn text_password_ls() {
        std::fs::create_dir("db_test_password_ls").unwrap();
        init("./db_test_password_ls/test.db", PASS).unwrap();
        let conn: Connection = decrypt("./db_test_password_ls/test.db", PASS).unwrap();

        password_new(&conn, KEY1, PASS).unwrap();
        let ls = password_ls(&conn).unwrap();
        assert_eq!(ls.len(), 1);
        password_new(&conn, KEY2, PASS).unwrap();
        let ls = password_ls(&conn).unwrap();
        assert_eq!(ls.len(), 2);

        drop(conn);
        std::fs::remove_dir_all("db_test_password_ls").unwrap();
    }
}
