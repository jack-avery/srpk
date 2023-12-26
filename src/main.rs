mod crypt;
mod db;
mod errors;

use std::{env, io::Write};
use rpassword::read_password;

use crate::errors::{Result, Error::NoParam};

fn main() {
    let args: Vec<String> = env::args().collect();
    let action: &str = match args.get(1) {
        Some(action) => action,
        None => "help"
    };
    let param: Option<&String> = args.get(2);

    let out: Result<()> = match action {
        "init" => init(&param),
        _ => {
            help();
            Ok(())
        },
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

fn init(param: &Option<&String>) -> Result<()> {
    if param.is_none() {
        return Err(NoParam);
    }
    let mut path: String = param.unwrap().to_owned();
    if !path.ends_with(".db") {
        path.push_str(".db");
    }
    let pass: String = get_password("password for the new vault");
    if let Err(status) = db::init(&path, &pass) {
        Err(status)
    } else {
        println!("successfully created new vault at {}", path);
        Ok(())
    }
}

fn help() {
    println!("srpk v{} 

create or target srpk vault:
    init <vault>    create a new vault at directory <vault>
    use <vault>     set <vault> as active vault
    which           see which vault is currently active

work with the active vault:
    ls              see keys in vault
    mk <key>        create new password with name <key>
    rm <key>        remove existing password with name <key>
    <key>           get existing password with name <key>

srpk will clear your clipboard 10 seconds after use", env!("CARGO_PKG_VERSION"))
}