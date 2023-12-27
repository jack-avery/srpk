use aes::cipher::{generic_array::GenericArray, typenum::U32};
use aes_gcm_siv::aead::rand_core::RngCore;
use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng},
    Aes256GcmSiv, Nonce,
};
use sha2::{Digest, Sha256};

use crate::errors::{
    Result,
    SrpkError::{AES256Decrypt, AES256Encrypt, BCryptHash},
};

fn generate_nonce() -> [u8; 12] {
    let mut nonce: [u8; 12] = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn get_aes256gcmsiv(pass: &str) -> Result<Aes256GcmSiv> {
    // TODO: find a better way to do this salt?? or does it not matter?
    let Ok(bcrypt) = bcrypt::hash_with_salt(pass, 12u32, [0u8; 16]) else {
        return Err(BCryptHash);
    };
    let mut hasher = Sha256::new();
    hasher.update(bcrypt.to_string());
    let hash: GenericArray<u8, U32> = hasher.finalize();
    Ok(Aes256GcmSiv::new(&hash))
}

/// Returns the original bytes.
pub fn aes256_decrypt(bytes: &[u8], pass: &str) -> Result<Vec<u8>> {
    let nonce_u8: [u8; 12] = bytes[..12].try_into().unwrap(); // TODO: refactor this unwrap
    let ciphertext_u8: &[u8] = &bytes[12..];
    let nonce: &Nonce = &Nonce::from(nonce_u8);
    let cipher: Aes256GcmSiv = get_aes256gcmsiv(pass)?;
    match cipher.decrypt(nonce, ciphertext_u8.as_ref()) {
        Ok(v) => Ok(v),
        Err(_) => Err(AES256Decrypt),
    }
}

/// Turn a `Vec<u8>` into its' encrypted form using `pass`.
pub fn aes256_encrypt(plaintext: &Vec<u8>, pass: &str) -> Result<Vec<u8>> {
    let nonce_u8: [u8; 12] = generate_nonce();
    aes256_encrypt_with_nonce(plaintext, pass, nonce_u8)
}

/// Same as `aes256_encrypt`, except without a randomly generated `nonce`.
pub fn aes256_encrypt_with_nonce(
    plaintext: &Vec<u8>,
    pass: &str,
    nonce_u8: [u8; 12],
) -> Result<Vec<u8>> {
    let nonce: &Nonce = &Nonce::from(nonce_u8);
    let cipher: Aes256GcmSiv = get_aes256gcmsiv(pass)?;
    let Ok(ciphertext) = cipher.encrypt(nonce, plaintext.as_ref()) else {
        return Err(AES256Encrypt);
    };
    Ok([nonce_u8.to_vec(), ciphertext].concat())
}

mod tests {
    use super::*;

    const PLAINTEXT: &str = "plaintext";
    const PASS: &str = "password";
    const BAD_PASS: &str = "bad_password";
    const NONCE_U8: [u8; 12] = *b"unique nonce";
    const EXPECTED: [u8; 37] = [
        117, 110, 105, 113, 117, 101, 32, 110, 111, 110, 99, 101, 135, 148, 97, 7, 179, 222, 151,
        20, 219, 11, 169, 230, 150, 26, 97, 211, 33, 79, 25, 248, 196, 251, 176, 67, 70,
    ];

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext_bytes: Vec<u8> = PLAINTEXT.try_into().unwrap();
        let encrypted_bytes: Vec<u8> = aes256_encrypt(&plaintext_bytes, PASS).unwrap();
        let decrypted_bytes: Vec<u8> = aes256_decrypt(&encrypted_bytes, PASS).unwrap();
        assert_eq!(decrypted_bytes, plaintext_bytes);
    }

    #[test]
    fn test_decrypt_bad_pass() {
        let plaintext_bytes: Vec<u8> = PLAINTEXT.try_into().unwrap();
        let encrypted_bytes: Vec<u8> = aes256_encrypt(&plaintext_bytes, PASS).unwrap();
        assert!(aes256_decrypt(&encrypted_bytes, BAD_PASS).is_err());
    }

    #[test]
    fn test_encrypt_with_nonce() {
        let plaintext_bytes: Vec<u8> = PLAINTEXT.try_into().unwrap();
        let expected_bytes: Vec<u8> = EXPECTED.try_into().unwrap();
        let encrypted_bytes: Vec<u8> =
            aes256_encrypt_with_nonce(&plaintext_bytes, PASS, NONCE_U8).unwrap();
        let decrypted_bytes: Vec<u8> = aes256_decrypt(&encrypted_bytes, PASS).unwrap();
        assert_eq!(encrypted_bytes, expected_bytes);
        assert_eq!(decrypted_bytes, plaintext_bytes);
    }
}
