# srpk
> simple rust passkey

srpk is a **CLI password management tool**.

## ⚠️ Notice

**This is a learning project for Rust, and is not intended to be used ever!**<br/>
That said, code reviews are welcomed, and a list of issues I'm aware of is below:

- Encryption algorithm is not configurable (uses AES256)
- Database engine is not configurable (uses SQLite3)
- No padding is used in encrypted values

## Usage

```
create or target srpk vault:
    init <vault>    create a new vault at directory <vault>
    use <vault>     set <vault> as active vault
    which           see which vault is currently active

work with the active vault:
    ls              see keys in vault
    mk <key>        create new password with name <key>
    rm <key>        remove existing password with name <key>
    <key>           get existing password with name <key>

srpk will clear your clipboard 10 seconds after use
```

Sample usage:
```
$ srpk init my_vault
(prompts password and creates vault)

$ srpk mk my_password
(prompts vault password then for new my_password)

$ srpk my_password
(prompts vault password then shunts my_password into clipboard;
    clears your clipboard after 10s)
```

## TODO

- [x] encryption
- [x] vault init
- [x] vault use & which
- [x] key mk
- [x] key get
- [x] key rm
- [x] key ls
- [x] use clipboard

- [ ] improve error handling and message verbosity
- [ ] improve enc and make this actually usable
