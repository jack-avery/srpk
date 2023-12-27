use dirs::config_dir;
use std::{
    env::current_dir,
    fs::{read, write},
    path::{Path, PathBuf},
};

use crate::errors::{
    Error::{FilePerms, PathEmpty, UTF8Decode, Unknown},
    Result,
};

fn cfg_path() -> Result<PathBuf> {
    match config_dir() {
        Some(mut buf) => {
            buf.push(".srpkvault");
            Ok(buf)
        }
        None => Err(Unknown),
    }
}

pub fn get_active_vault() -> Result<Option<PathBuf>> {
    let path: PathBuf = cfg_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let Ok(file_bytes) = read(path) else {
        return Err(FilePerms);
    };
    match String::from_utf8(file_bytes) {
        Ok(p) => {
            let active: PathBuf = PathBuf::from(p);
            Ok(Some(active))
        }
        Err(_) => Err(UTF8Decode),
    }
}

pub fn set_active_vault(vault: &Path) -> Result<()> {
    let path: PathBuf = cfg_path()?;

    // ensure it's a real file from root to prevent it from getting lost
    let mut new_vault: PathBuf = PathBuf::new();
    if !vault.has_root() {
        let Ok(cwd) = current_dir() else {
            return Err(Unknown);
        };
        new_vault.push(cwd)
    }
    new_vault.push(vault);
    if !new_vault.exists() {
        return Err(PathEmpty);
    }

    let new_vault_str: &str = new_vault.to_str().unwrap();
    if write(path, new_vault_str).is_err() {
        return Err(FilePerms);
    };
    Ok(())
}
