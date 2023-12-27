use sqlite::{Connection, State, Value};
use std::{
    fs::{read, remove_file, write},
    path::{Path, PathBuf},
};

use crate::crypt::{CryptValue, aes256_decrypt, aes256_encrypt};
use crate::errors::{
    Result,
    SrpkError::{
        DBCreateTable, DBSQLConn, FilePerms, KeyDuplicate, KeyNonExist, PathEmpty, PathTaken,
    },
};

const PASSWORD_NEW_SQL: &str = "INSERT INTO srpk VALUES (:key, :pass);";
const PASSWORD_GET_SQL: &str = "SELECT value FROM srpk WHERE key = ?;";
const PASSWORD_DEL_SQL: &str = "DELETE FROM srpk WHERE key = ?";
const PASSWORD_LS_SQL: &str = "SELECT key FROM srpk;";

pub struct Vault {
    conn: Connection,
    pass: String,
    path: PathBuf,
    path_temp: PathBuf,
    cost: u8,
}

impl Vault {
    /// Open a vault at `path` using `pass`.
    pub fn new(path: &str, pass: &str) -> Result<Self> {
        let mut path_str: String = path.to_owned();
        let path: PathBuf = PathBuf::from(&path_str);
        path_str.push_str(".temp");
        let path_temp: PathBuf = PathBuf::from(&path_str);

        if !path.exists() {
            return Err(PathEmpty);
        };
        if path_temp.exists() {
            return Err(PathTaken);
        };

        // decrypt
        let Ok(db_enc) = read(&path) else {
            return Err(FilePerms);
        };
        let db_raw: CryptValue = aes256_decrypt(&db_enc, pass)?;

        // create temp and return a connection
        if write(&path_temp, db_raw.value).is_err() {
            return Err(FilePerms);
        };
        let Ok(conn) = sqlite::open(&path_temp) else {
            return Err(DBSQLConn);
        };

        Ok(Self{ conn, pass: pass.to_owned(), path, path_temp, cost: db_raw.cost })
    }

    /// Close the vault, applying changes if `changed`.
    pub fn finish(self, changed: bool) -> Result<()> {
        if changed {
            let path: &Path = Path::new(&self.path);
            let Ok(db_raw) = read(&self.path_temp) else {
                return Err(FilePerms);
            };
            let db_enc: Vec<u8> = aes256_encrypt(&db_raw, &self.pass, self.cost)?;
            write(path, db_enc).unwrap();
        }

        drop(self.conn);
        remove_file(&self.path_temp).unwrap();
        Ok(())
    }

    /// Create new password `key` of content `pass` in the vault.
    pub fn key_new(&self, key: &str, pass: &str) -> Result<()> {
        if self.key_get(key)?.is_some() {
            return Err(KeyDuplicate);
        };

        let Ok(mut statement) = self.conn.prepare(PASSWORD_NEW_SQL) else {
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

    /// Get password `key` from the vault. `None` if given key is missing.
    pub fn key_get(&self, key: &str) -> Result<Option<String>> {
        let Ok(mut statement) = self.conn.prepare(PASSWORD_GET_SQL) else {
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

    /// Delete password `key` from the vault.
    pub fn key_del(&self, key: &str) -> Result<()> {
        if self.key_get(key)?.is_none() {
            return Err(KeyNonExist);
        };

        let Ok(mut statement) = self.conn.prepare(PASSWORD_DEL_SQL) else {
            return Err(DBCreateTable);
        };
        if statement.bind((1, key)).is_err() {
            return Err(DBSQLConn);
        };
        while let Ok(State::Row) = statement.next() {}
        Ok(())
    }

    /// Get a `Vec<String>` containing the names of each key in the vault.
    pub fn key_ls(&self) -> Result<Vec<String>> {
        let Ok(mut statement) = self.conn.prepare(PASSWORD_LS_SQL) else {
            return Err(DBCreateTable);
        };
        let mut keys: Vec<String> = Vec::new();
        while let Ok(State::Row) = statement.next() {
            keys.push(statement.read::<String, _>("key").unwrap());
        }
        Ok(keys)
    }
}

/// Initialize a vault and encrypt it
pub fn init(path: &str, pass: &str, cost: u8) -> Result<()> {
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
    let db_enc: Vec<u8> = aes256_encrypt(&db_raw, pass, cost)?;

    // overwrite
    remove_file(path).unwrap();
    write(path, db_enc).unwrap();

    Ok(())
}


mod tests {
    use super::*;

    const PASS: &str = "password";
    const COST: u8 = 8u8;
    const KEY1: &str = "key1";
    const KEY2: &str = "key2";

    #[test]
    fn test_create() {
        std::fs::create_dir("db_test_decrypt").unwrap();
        init("./db_test_decrypt/test.db", PASS, COST).unwrap();
        Vault::new("./db_test_decrypt/test.db", PASS).unwrap();
        std::fs::remove_dir_all("db_test_decrypt").unwrap();
    }

    #[test]
    fn test_password() {
        std::fs::create_dir("db_test_password_new").unwrap();
        init("./db_test_password_new/test.db", PASS, COST).unwrap();
        let vault: Vault = Vault::new("./db_test_password_new/test.db", PASS).unwrap();

        vault.key_new(KEY1, PASS).unwrap();
        let read: Option<String> = vault.key_get(KEY1).unwrap();
        vault.finish(false).unwrap();

        assert!(read.is_some());
        assert_eq!(read.unwrap(), PASS);
        std::fs::remove_dir_all("db_test_password_new").unwrap();
    }

    #[test]
    fn test_finish_unchanged() {
        std::fs::create_dir("db_test_finish_unchanged").unwrap();
        init("./db_test_finish_unchanged/test.db", PASS, COST).unwrap();
        let before: Vec<u8> = std::fs::read("./db_test_finish_unchanged/test.db").unwrap();
        let vault: Vault = Vault::new("./db_test_finish_unchanged/test.db", PASS).unwrap();

        vault.key_new(KEY1, PASS).unwrap();
        vault.finish(false).unwrap();

        let after: Vec<u8> = std::fs::read("./db_test_finish_unchanged/test.db").unwrap();
        assert_eq!(before, after);
        std::fs::remove_dir_all("db_test_finish_unchanged").unwrap();
    }

    #[test]
    fn test_finish_changed() {
        std::fs::create_dir("db_test_finish_changed").unwrap();
        init("./db_test_finish_changed/test.db", PASS, COST).unwrap();
        let before: Vec<u8> = std::fs::read("./db_test_finish_changed/test.db").unwrap();
        let vault: Vault = Vault::new("./db_test_finish_changed/test.db", PASS).unwrap();

        vault.key_new(KEY1, PASS).unwrap();
        vault.finish(true).unwrap();

        let after: Vec<u8> = std::fs::read("./db_test_finish_changed/test.db").unwrap();
        assert_ne!(before, after);
        std::fs::remove_dir_all("db_test_finish_changed").unwrap();
    }

    #[test]
    fn test_password_new_duplicate() {
        std::fs::create_dir("db_test_password_new_duplicate").unwrap();
        init("./db_test_password_new_duplicate/test.db", PASS, COST).unwrap();
        let vault: Vault = Vault::new("./db_test_password_new_duplicate/test.db", PASS).unwrap();

        vault.key_new(KEY1, PASS).unwrap();
        assert!(vault.key_new(KEY1, PASS).is_err());
        vault.finish(false).unwrap();

        std::fs::remove_dir_all("db_test_password_new_duplicate").unwrap();
    }

    #[test]
    fn test_password_del() {
        std::fs::create_dir("db_test_password_del").unwrap();
        init("./db_test_password_del/test.db", PASS, COST).unwrap();
        let vault: Vault = Vault::new("./db_test_password_del/test.db", PASS).unwrap();

        vault.key_new(KEY1, PASS).unwrap();
        vault.key_del(KEY1).unwrap();
        vault.finish(false).unwrap();

        std::fs::remove_dir_all("db_test_password_del").unwrap();
    }

    #[test]
    fn test_password_del_missing() {
        std::fs::create_dir("db_test_password_del_missing").unwrap();
        init("./db_test_password_del_missing/test.db", PASS, COST).unwrap();
        let vault: Vault = Vault::new("./db_test_password_del_missing/test.db", PASS).unwrap();

        assert!(vault.key_del(KEY1).is_err());
        vault.finish(false).unwrap();

        std::fs::remove_dir_all("db_test_password_del_missing").unwrap();
    }

    #[test]
    fn text_password_ls() {
        std::fs::create_dir("db_test_password_ls").unwrap();
        init("./db_test_password_ls/test.db", PASS, COST).unwrap();
        let vault: Vault = Vault::new("./db_test_password_ls/test.db", PASS).unwrap();

        vault.key_new(KEY1, PASS).unwrap();
        let ls = vault.key_ls().unwrap();
        assert_eq!(ls.len(), 1);
        vault.key_new(KEY2, PASS).unwrap();
        let ls = vault.key_ls().unwrap();
        assert_eq!(ls.len(), 2);
        vault.finish(false).unwrap();

        std::fs::remove_dir_all("db_test_password_ls").unwrap();
    }
}
