use aes_gcm_siv::aead::rand_core::RngCore;
use aes::cipher::{generic_array::GenericArray, typenum::U32};
use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng},
    Aes256GcmSiv, Nonce
};
use base64::{Engine as _, engine::general_purpose};
use sha2::{Sha256, Digest};

use crate::errors::{Result, Error::{AES256Decrypt, AES256Encrypt, Base64Decode, UTF8Decode}};

fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn get_aes256gcmsiv(pass: &str) -> Aes256GcmSiv {
    let mut hasher = Sha256::new();
    hasher.update(pass.as_bytes());
    let hash: GenericArray<u8, U32> = hasher.finalize();
    Aes256GcmSiv::new(&hash)
}

pub fn aes256_decrypt(ciphertext: &str, pass: &str) -> Result<String> {
    let cipher: Aes256GcmSiv = get_aes256gcmsiv(pass);
    let Ok(full_u8) = general_purpose::STANDARD_NO_PAD.decode(ciphertext) else {
        return Err(Base64Decode);
    };
    let nonce_u8: [u8; 12] = full_u8[..12].try_into().unwrap(); // TODO: refactor this unwrap
    let ciphertext_u8: &[u8] = &full_u8[12..];
    let nonce: &Nonce = &Nonce::from(nonce_u8);
    let Ok(plaintext) = cipher.decrypt(nonce, ciphertext_u8.as_ref()) else {
        return Err(AES256Decrypt);
    };
    match String::from_utf8(plaintext) {
        Ok(d) => Ok(d),
        Err(_) => Err(UTF8Decode)
    }
}

pub fn aes256_encrypt(plaintext: &str, pass: &str) -> Result<String> {
    let nonce_u8: [u8; 12] = generate_nonce();
    aes256_encrypt_with_nonce(plaintext, pass, nonce_u8)
}

pub fn aes256_encrypt_with_nonce(plaintext: &str, pass: &str, nonce_u8: [u8; 12]) -> Result<String> {
    let cipher: Aes256GcmSiv = get_aes256gcmsiv(pass);
    let nonce: &Nonce = &Nonce::from(nonce_u8);
    let Ok(ciphertext) = cipher.encrypt(nonce, plaintext.as_ref()) else {
        return Err(AES256Encrypt);
    };
    let res: Vec<u8> = [nonce_u8.to_vec(), ciphertext].concat();
    Ok(general_purpose::STANDARD_NO_PAD.encode(res))
}

mod tests {
    use super::*;

    const PLAINTEXT: &str = "plaintext";
    const PASS: &str = "password";
    const NONCE_U8: [u8; 12] = *b"unique nonce";
    const EXPECTED: &str = "dW5pcXVlIG5vbmNlNCigDnwsd805vWSHHI98hAk9LVUsJ/ohcw";

    #[test]
    fn test_encrypt() {
        let Ok(cyphertext) = &aes256_encrypt(PLAINTEXT, PASS) else { panic!() };
        let Ok(decryptedtext) = aes256_decrypt(cyphertext, PASS) else { panic!() };
        assert_eq!(decryptedtext, PLAINTEXT);
    }

    #[test]
    fn test_encrypt_with_nonce() {
        let Ok(cyphertext) = &aes256_encrypt_with_nonce(PLAINTEXT, PASS, NONCE_U8) else { panic!() };
        let Ok(decryptedtext) = aes256_decrypt(cyphertext, PASS) else { panic!() };
        assert_eq!(cyphertext, EXPECTED);
        assert_eq!(decryptedtext, PLAINTEXT);
    }
}
