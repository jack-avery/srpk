mod crypt;
mod db;
mod errors;

use rpassword::read_password;
use sqlite::Connection;
use std::{env, io::Write};

use crate::errors::{Error::NoParam, Result};

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
        },
        "init" => init(&param),
        "mk" => mk(&param),
        "rm" => rm(&param),
        _ => get(action)
    };

    if out.is_err() {
        println!("error: {}", out.unwrap_err());
    }
}

fn get_password(prompt: &str) -> String {
    print!("{}: ", prompt);
    std::io::stdout().flush().unwrap();
    read_password().unwrap()
}

fn param_check(param: &Option<&String>) -> Result<()> {
    if param.is_none() {
        return Err(NoParam);
    }
    Ok(())
}

fn get_vault(path: &str, pass: &str) -> Result<Connection> {
    db::decrypt(path, pass)
}

fn finish(conn: Connection, path: &str, pass: &str, changed: bool) -> Result<()> {
    drop(conn);
    db::finish(path, pass, changed)?;
    Ok(())
}

fn init(param: &Option<&String>) -> Result<()> {
    param_check(param)?;
    let mut path: String = param.unwrap().to_owned();
    if !path.ends_with(".db") {
        path.push_str(".db");
    }
    let pass: String = get_password("password for the new vault");
    db::init(&path, &pass)?;
    println!("successfully created new vault at {}", path);
    Ok(())
}

fn mk(param: &Option<&String>) -> Result<()> {
    param_check(param)?;
    let key: &str = param.unwrap();
    let pass: String = get_password("password for active vault");
    let path: &str = "test.db"; // TODO: TEMP
    let conn: Connection = get_vault(path, &pass)?;

    let new_pass: String = get_password("new password to add");
    db::password_new(&conn, key, &new_pass)?;
    finish(conn, path, &pass, true)?;

    println!("successfully added new key {}", key);
    Ok(())
}

fn rm(param: &Option<&String>) -> Result<()> {
    param_check(param)?;
    let key: &str = param.unwrap();
    let pass: String = get_password("password for active vault");
    let path: &str = "test.db"; // TODO: TEMP
    let conn: Connection = get_vault(path, &pass)?;

    db::password_del(&conn, key)?;
    finish(conn, path, &pass, true)?;

    println!("successfully removed key {}", key);
    Ok(())
}

fn get(key: &str) -> Result<()> {
    let pass: String = get_password("password for active vault");
    let path: &str = "test.db"; // TODO: TEMP
    let conn: Connection = get_vault(path, &pass)?;

    let found: Option<String> = db::password_get(&conn, key)?;
    finish(conn, path, &pass, false)?;

    if found.is_none() {
        println!("key {} not found", key);
        return Ok(())
    }
    
    println!("{}", found.unwrap());
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
