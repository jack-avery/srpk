use sqlite::{Connection, State, Value};
use std::{
    fs::{read, remove_file, write},
    path::{Path, PathBuf},
};

use crate::crypt::{aes256_decrypt, aes256_encrypt, CryptValue};
use crate::errors::{
    Result,
    SrpkError::{KeyDuplicate, KeyNonExist},
};

const PASSWORD_NEW_SQL: &str = "INSERT INTO srpk VALUES (:key, :pass);";
const PASSWORD_GET_SQL: &str = "SELECT value FROM srpk WHERE key = ?;";
const PASSWORD_DEL_SQL: &str = "DELETE FROM srpk WHERE key = ?";
const PASSWORD_LS_SQL: &str = "SELECT key FROM srpk;";

/// Represents an opened srpk vault.
///
/// Create a vault:
/// ```
/// Vault::create("./myvault.db", "mypassword", 12u8)?;
/// ```
///
/// Open an existing vault and interact with it:
/// ```
/// let vault: Vault = Vault::open("./myvault.db", "mypassword")?;
/// vault.key_new("github", "password123!")?;
/// assert_eq!(vault.key_get("github")?, "password123!");
/// assert_eq!(vault.key_ls()?, vec!["github"]);
/// vault.key_del("github")?;
/// vault.close(false)?;
/// // or close, while applying any changes:
/// vault.close(true)?;
/// ```
pub struct Vault {
    conn: Connection,
    pass: String,
    path: PathBuf,
    path_temp: PathBuf,
    cost: u8,
}

impl Vault {
    /// Create a vault at `path` with password `pass` and encrypt it.
    ///
    /// `cost` is the bcrypt hashing cost.
    ///
    /// Example:
    /// ```
    /// Vault::create("./myvault.db", "mypassword", 12u8)?;
    /// ```
    pub fn create(path: &str, pass: &str, cost: u8) -> Result<()> {
        // verify clean slate
        let path: PathBuf = PathBuf::from(path);

        // create the initial DB
        let connection = sqlite::open(&path)?;
        connection.execute("CREATE TABLE srpk (key TEXT, value TEXT);")?;
        drop(connection);

        // encrypt & overwrite
        let db_raw: Vec<u8> = read(&path)?;
        let db_enc: Vec<u8> = aes256_encrypt(&db_raw, pass, cost)?;
        write(&path, db_enc)?;

        Ok(())
    }

    /// Open a vault at `path` using `pass`.
    ///
    /// Creates a temporary database for interfacing with at `path_temp`,
    /// which will be removed when `Vault.close()` is called.
    ///
    /// Example:
    /// ```
    /// Vault::create("./myvault.db", "mypassword", "8")?;
    /// let vault: Vault = Vault::open("./myvault.db", "mypassword")?;
    /// vault.close(false)?;
    /// ```
    pub fn open(path: &str, pass: &str) -> Result<Self> {
        let mut path_str: String = path.to_owned();
        let path: PathBuf = PathBuf::from(&path_str);
        path_str.push_str(".temp");
        let path_temp: PathBuf = PathBuf::from(&path_str);

        // decrypt
        let db_enc: Vec<u8> = read(&path)?;
        let db_raw: CryptValue = aes256_decrypt(&db_enc, pass)?;

        // create temp and return a connection
        write(&path_temp, db_raw.value)?;
        let conn = sqlite::open(&path_temp)?;

        Ok(Self {
            conn,
            pass: pass.to_owned(),
            path,
            path_temp,
            cost: db_raw.cost,
        })
    }

    /// Close the vault, applying changes if `changed`.
    ///
    /// Deletes the temporary database.
    /// If `changed` is `true`, the contents of temporary DB will be encrypted,
    /// and the encrypted data will replace the original DB.
    ///
    /// Example:
    /// ```
    /// Vault::create("./myvault.db", "mypassword", "8")?;
    /// let vault: Vault = Vault::open("./myvault.db", "mypassword")?;
    /// vault.key_new("github", "password123!")?;
    /// vault.close(true)?;
    /// ```
    pub fn close(self, changed: bool) -> Result<()> {
        if changed {
            let path: &Path = Path::new(&self.path);
            let db_raw: Vec<u8> = read(&self.path_temp)?;
            let db_enc: Vec<u8> = aes256_encrypt(&db_raw, &self.pass, self.cost)?;
            write(path, db_enc)?;
        }

        drop(self.conn);
        remove_file(&self.path_temp)?;
        Ok(())
    }

    /// Create new password `key` of content `pass` in the vault.
    ///
    /// Returns `Err(KeyDuplicate)` if `key` already exists in this vault.
    ///
    /// Example:
    /// ```
    /// Vault::create("./myvault.db", "mypassword", "8")?;
    /// let vault: Vault = Vault::open("./myvault.db", "mypassword")?;
    /// vault.key_new("github", "password123!")?;
    /// vault.close(true)?;
    /// ```
    pub fn key_new(&self, key: &str, pass: &str) -> Result<()> {
        if self.key_get(key)?.is_some() {
            return Err(KeyDuplicate(key.to_owned()));
        };

        let mut statement = self.conn.prepare(PASSWORD_NEW_SQL)?;
        statement.bind_iter::<_, (_, Value)>([(":key", key.into()), (":pass", pass.into())])?;
        while let Ok(State::Row) = statement.next() {}
        Ok(())
    }

    /// Get password `key` from the vault.
    ///
    /// Returns `None` if the search succeeded and there was no key.
    /// Returns `Err` if the search was unsuccessful due to an error.
    ///
    /// Example:
    /// ```
    /// Vault::create("./myvault.db", "mypassword", "8")?;
    /// let vault: Vault = Vault::open("./myvault.db", "mypassword")?;
    /// vault.key_new("github", "password123!")?;
    /// assert_eq!(vault.key_get("github")?, "password123!");
    /// vault.close(true)?;
    /// ```
    pub fn key_get(&self, key: &str) -> Result<Option<String>> {
        let mut statement = self.conn.prepare(PASSWORD_GET_SQL)?;
        statement.bind((1, key))?;
        if let Ok(State::Row) = statement.next() {
            return Ok(Some(statement.read::<String, _>("value")?));
        }
        Ok(None)
    }

    /// Delete password `key` from the vault.
    ///
    /// Returns `Err(KeyNonExist)` if the key does not exist in this vault.
    ///
    /// Example:
    /// ```
    /// Vault::create("./myvault.db", "mypassword", "8")?;
    /// let vault: Vault = Vault::open("./myvault.db", "mypassword")?;
    /// vault.key_new("github", "password123!")?;
    /// vault.key_del("github")?;
    /// vault.close(true)?;
    /// ```
    pub fn key_del(&self, key: &str) -> Result<()> {
        if self.key_get(key)?.is_none() {
            return Err(KeyNonExist(key.to_owned()));
        };

        let mut statement = self.conn.prepare(PASSWORD_DEL_SQL)?;
        statement.bind((1, key))?;
        while let Ok(State::Row) = statement.next() {}
        Ok(())
    }

    /// Get a `Vec<String>` containing the names of each key in the vault.
    ///
    /// Returns an empty `Vec<String>` if no keys are in the vault.
    ///
    /// Example:
    /// ```
    /// Vault::create("./myvault.db", "mypassword", "8")?;
    /// let vault: Vault = Vault::open("./myvault.db", "mypassword")?;
    /// vault.key_new("github", "password123!")?;
    /// assert_eq!(vault.key_ls()?, vec!["github"]);
    /// vault.close(true)?;
    /// ```
    pub fn key_ls(&self) -> Result<Vec<String>> {
        let mut statement = self.conn.prepare(PASSWORD_LS_SQL)?;
        let mut keys: Vec<String> = Vec::new();
        while let Ok(State::Row) = statement.next() {
            keys.push(statement.read::<String, _>("key")?);
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "password";
    const COST: u8 = 8u8;
    const KEY1: &str = "key1";
    const KEY2: &str = "key2";

    #[test]
    fn test_create() {
        std::fs::create_dir("vault_test_decrypt").unwrap();
        Vault::create("./vault_test_decrypt/test.db", PASS, COST).unwrap();
        Vault::open("./vault_test_decrypt/test.db", PASS).unwrap();
        std::fs::remove_dir_all("vault_test_decrypt").unwrap();
    }

    #[test]
    fn test_password() {
        std::fs::create_dir("vault_test_password_new").unwrap();
        Vault::create("./vault_test_password_new/test.db", PASS, COST).unwrap();
        let vault: Vault = Vault::open("./vault_test_password_new/test.db", PASS).unwrap();

        vault.key_new(KEY1, PASS).unwrap();
        let read: Option<String> = vault.key_get(KEY1).unwrap();
        vault.close(false).unwrap();

        assert!(read.is_some());
        assert_eq!(read.unwrap(), PASS);
        std::fs::remove_dir_all("vault_test_password_new").unwrap();
    }

    #[test]
    fn test_finish_unchanged() {
        std::fs::create_dir("vault_test_finish_unchanged").unwrap();
        Vault::create("./vault_test_finish_unchanged/test.db", PASS, COST).unwrap();
        let before: Vec<u8> = std::fs::read("./vault_test_finish_unchanged/test.db").unwrap();
        let vault: Vault = Vault::open("./vault_test_finish_unchanged/test.db", PASS).unwrap();

        vault.key_new(KEY1, PASS).unwrap();
        vault.close(false).unwrap();

        let after: Vec<u8> = std::fs::read("./vault_test_finish_unchanged/test.db").unwrap();
        assert_eq!(before, after);
        std::fs::remove_dir_all("vault_test_finish_unchanged").unwrap();
    }

    #[test]
    fn test_finish_changed() {
        std::fs::create_dir("vault_test_finish_changed").unwrap();
        Vault::create("./vault_test_finish_changed/test.db", PASS, COST).unwrap();
        let before: Vec<u8> = std::fs::read("./vault_test_finish_changed/test.db").unwrap();
        let vault: Vault = Vault::open("./vault_test_finish_changed/test.db", PASS).unwrap();

        vault.key_new(KEY1, PASS).unwrap();
        vault.close(true).unwrap();

        let after: Vec<u8> = std::fs::read("./vault_test_finish_changed/test.db").unwrap();
        assert_ne!(before, after);
        std::fs::remove_dir_all("vault_test_finish_changed").unwrap();
    }

    #[test]
    fn test_password_new_duplicate() {
        std::fs::create_dir("vault_test_password_new_duplicate").unwrap();
        Vault::create("./vault_test_password_new_duplicate/test.db", PASS, COST).unwrap();
        let vault: Vault =
            Vault::open("./vault_test_password_new_duplicate/test.db", PASS).unwrap();

        vault.key_new(KEY1, PASS).unwrap();
        assert!(vault.key_new(KEY1, PASS).is_err());
        vault.close(false).unwrap();

        std::fs::remove_dir_all("vault_test_password_new_duplicate").unwrap();
    }

    #[test]
    fn test_password_del() {
        std::fs::create_dir("vault_test_password_del").unwrap();
        Vault::create("./vault_test_password_del/test.db", PASS, COST).unwrap();
        let vault: Vault = Vault::open("./vault_test_password_del/test.db", PASS).unwrap();

        vault.key_new(KEY1, PASS).unwrap();
        vault.key_del(KEY1).unwrap();
        vault.close(false).unwrap();

        std::fs::remove_dir_all("vault_test_password_del").unwrap();
    }

    #[test]
    fn test_password_del_missing() {
        std::fs::create_dir("vault_test_password_del_missing").unwrap();
        Vault::create("./vault_test_password_del_missing/test.db", PASS, COST).unwrap();
        let vault: Vault = Vault::open("./vault_test_password_del_missing/test.db", PASS).unwrap();

        assert!(vault.key_del(KEY1).is_err());
        vault.close(false).unwrap();

        std::fs::remove_dir_all("vault_test_password_del_missing").unwrap();
    }

    #[test]
    fn text_password_ls() {
        std::fs::create_dir("vault_test_password_ls").unwrap();
        Vault::create("./vault_test_password_ls/test.db", PASS, COST).unwrap();
        let vault: Vault = Vault::open("./vault_test_password_ls/test.db", PASS).unwrap();

        vault.key_new(KEY1, PASS).unwrap();
        let ls = vault.key_ls().unwrap();
        assert_eq!(ls.len(), 1);
        vault.key_new(KEY2, PASS).unwrap();
        let ls = vault.key_ls().unwrap();
        assert_eq!(ls.len(), 2);
        vault.close(false).unwrap();

        std::fs::remove_dir_all("vault_test_password_ls").unwrap();
    }
}
