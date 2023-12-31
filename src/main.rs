mod cfg;
mod crypt;
mod errors;
mod vault;

use arboard::Clipboard;
use rpassword::read_password;
use std::{
    env,
    io::{stdin, stdout, Write},
    path::{Path, PathBuf},
    thread::sleep,
    time::Duration,
};

use crate::{
    errors::{
        Result,
        SrpkError::{KeyReserved, NoParam, NoVault},
    },
    vault::Vault,
};

const RESERVED: [&str; 7] = ["help", "init", "use", "which", "mk", "rm", "ls"];

fn main() {
    let args: Vec<String> = env::args().collect();
    let action: &str = match args.get(1) {
        Some(action) => action,
        None => "help",
    };
    let param: Option<&String> = args.get(2);

    let out: Result<()> = match action {
        "help" => {
            help();
            Ok(())
        }
        "init" => vault_init(&param),
        "use" => vault_use(&param),
        "which" => vault_which(),
        "mk" => key_mk(&param),
        "rm" => key_rm(&param),
        "ls" => key_ls(),
        _ => all(action),
    };

    if out.is_err() {
        println!("error: {}", out.unwrap_err());
    }
}

fn get_cost() -> Result<u8> {
    let mut cost: String = String::new();
    loop {
        cost.clear();
        print!("crypt slowness (5-31, higher = slower, 12-13 is good): ");
        stdout().flush()?;
        stdin().read_line(&mut cost)?.to_string();
        let trim: &str = cost.trim();

        match trim.parse::<u8>() {
            Ok(u) => {
                if !(5..=31).contains(&u) {
                    println!("out of range");
                    continue;
                }
                return Ok(u);
            }
            Err(_) => {
                println!("not a valid number");
            }
        }
    }
}

fn get_password(prompt: &str) -> Result<String> {
    print!("{}: ", prompt);
    stdout().flush()?;
    Ok(read_password()?)
}

fn get_password_confirm(prompt: &str) -> Result<String> {
    loop {
        let pass: String = get_password(prompt)?;
        let pass_confirm: String = get_password("retype password")?;
        if pass == pass_confirm {
            return Ok(pass);
        }
        println!("passwords do not match")
    }
}

pub fn set_clipboard(text: &str) -> Result<()> {
    let mut clipboard = Clipboard::new()?;
    Ok(clipboard.set_text(text)?)
}

fn param_check(param: &Option<&String>) -> Result<()> {
    if param.is_none() {
        return Err(NoParam);
    }
    Ok(())
}

fn vault_check() -> Result<String> {
    match cfg::get_active_vault()? {
        Some(p) => Ok(p.to_str().unwrap().to_owned()),
        None => Err(NoVault),
    }
}

fn to_clipboard(pass: &str) -> Result<()> {
    set_clipboard(pass)?;
    println!("pass has been put into clipboard, and will be cleared in 10s");
    let wait_duration: Duration = Duration::from_secs(10);
    sleep(wait_duration);
    set_clipboard("")?;
    println!("clipboard cleared");
    Ok(())
}

fn all(param: &str) -> Result<()> {
    let vault: Option<PathBuf> = cfg::get_active_vault()?;
    match vault {
        Some(_) => key_get(param),
        None => {
            help();
            Ok(())
        }
    }
}

fn vault_init(param: &Option<&String>) -> Result<()> {
    param_check(param)?;
    let mut path: String = param.unwrap().to_owned();
    if !path.ends_with(".db") {
        path.push_str(".db");
    }
    let pass: String = get_password_confirm("password for the new vault")?;
    let cost: u8 = get_cost()?;
    Vault::create(&path, &pass, cost)?;
    println!("successfully created new vault at {}", path);

    if vault_check().is_err() {
        vault_use(&Some(&path))?;
    }

    Ok(())
}

fn vault_use(param: &Option<&String>) -> Result<()> {
    param_check(param)?;
    let vault: &Path = Path::new(param.unwrap());
    cfg::set_active_vault(vault)?;
    println!("active vault is now {}", vault.to_str().unwrap());
    Ok(())
}

fn vault_which() -> Result<()> {
    let vault: Option<PathBuf> = cfg::get_active_vault()?;
    match vault {
        Some(p) => {
            println!("{}", p.to_str().unwrap());
            Ok(())
        }
        None => {
            println!("no active vault");
            Ok(())
        }
    }
}

fn key_mk(param: &Option<&String>) -> Result<()> {
    param_check(param)?;
    let key: &str = param.unwrap();

    if RESERVED.contains(&key) {
        return Err(KeyReserved(key.to_string()));
    }

    let path: String = vault_check()?;
    let pass: String = get_password("password for active vault")?;
    let vault: Vault = Vault::open(&path, &pass)?;

    let new_pass: String = get_password("new password to add")?;
    vault.key_new(key, &new_pass)?;
    vault.close(true)?;

    println!("successfully added new key {}", key);
    Ok(())
}

fn key_rm(param: &Option<&String>) -> Result<()> {
    param_check(param)?;
    let key: &str = param.unwrap();

    let path: String = vault_check()?;
    let pass: String = get_password("password for active vault")?;
    let vault: Vault = Vault::open(&path, &pass)?;

    vault.key_del(key)?;
    vault.close(true)?;

    println!("successfully removed key {}", key);
    Ok(())
}

fn key_get(key: &str) -> Result<()> {
    let path: String = vault_check()?;
    let pass: String = get_password("password for active vault")?;
    let vault: Vault = Vault::open(&path, &pass)?;

    let found: Option<String> = vault.key_get(key)?;
    vault.close(false)?;

    match found {
        Some(p) => to_clipboard(&p),
        None => {
            println!("key {} not found", key);
            Ok(())
        }
    }
}

fn key_ls() -> Result<()> {
    let path: String = vault_check()?;
    let pass: String = get_password("password for active vault")?;
    let vault: Vault = Vault::open(&path, &pass)?;

    let keys: Vec<String> = vault.key_ls()?;
    vault.close(false)?;

    if keys.is_empty() {
        println!("vault is empty");
    } else {
        println!("keys in vault: {}", keys.join(", "))
    }

    Ok(())
}

fn help() {
    println!(
        "srpk v{} 

create or target srpk vault:
    init <vault>    create a new vault at directory <vault>
    use <vault>     set <vault> as active vault
    which           see which vault is currently active

work with the active vault:
    ls              see keys in vault
    mk <key>        create new password with name <key>
    rm <key>        remove existing password with name <key>
    <key>           get existing password with name <key>

srpk will clear your clipboard 10 seconds after use",
        env!("CARGO_PKG_VERSION")
    )
}
