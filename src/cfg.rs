use std::{
    env::current_dir,
    fs::{read, write},
    path::{Path, PathBuf},
};

use crate::errors::{
    Result,
    SrpkError::{ConfigDir, PathEmpty},
};

fn cfg_path() -> Result<PathBuf> {
    if let Some(config_home) = dirs::config_dir() {
        return Ok(config_home);
    }
    if let Some(user_home) = dirs::home_dir() {
        return Ok(user_home);
    }
    Err(ConfigDir)
}

pub fn get_active_vault() -> Result<Option<PathBuf>> {
    let path: PathBuf = cfg_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let file_bytes: Vec<u8> = read(&path)?;
    let file: String = String::from_utf8(file_bytes)?;
    let active: PathBuf = PathBuf::from(file);
    match active.exists() {
        true => Ok(Some(active)),
        false => Err(PathEmpty(active)),
    }
}

pub fn set_active_vault(vault: &Path) -> Result<()> {
    let path: PathBuf = cfg_path()?;

    // ensure it's a real file from root to prevent it from getting lost
    let mut new_vault: PathBuf = PathBuf::new();
    if !vault.has_root() {
        let cwd: PathBuf = current_dir()?;
        new_vault.push(cwd)
    }
    new_vault.push(vault);
    if !new_vault.exists() {
        return Err(PathEmpty(path));
    }

    if let Some(new_vault_str) = new_vault.to_str() {
        write(&path, new_vault_str)?;
    }
    Ok(())
}
