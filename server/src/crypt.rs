use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand_core::{RngCore, OsRng}; 
use base64::{encode as b64encode, decode as b64decode};
use rustls::{ServerConfig, Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
const NONCE_LEN: usize = 12;
pub fn encrypt_bytes(shared_key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let key = Key::<Aes256Gcm>::from_slice(shared_key);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("encryption failure!");

    // prepend nonce to ciphertext for transmission
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);
    combined
}

pub fn decrypt_bytes(shared_key: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if encrypted_data.len() < NONCE_LEN {
        return Err("data too short");
    }

    let key = Key::<Aes256Gcm>::from_slice(shared_key);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&encrypted_data[..NONCE_LEN]);
    let ciphertext = &encrypted_data[NONCE_LEN..];

    cipher.decrypt(nonce, ciphertext).map_err(|_| "decryption error")
}
pub fn encrypt_string(shared_key: &[u8], plaintext: &str) -> String {
    let key = Key::<Aes256Gcm>::from_slice(shared_key);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    let mut rng = OsRng;
    rng.fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::from_slice(&nonce_bytes);

    match cipher.encrypt(nonce, plaintext.as_bytes()) {
        Ok(ciphertext) => {
            let mut combined = nonce_bytes.to_vec();
            combined.extend_from_slice(&ciphertext);
            b64encode(&combined)
        },
        Err(_) => "encryption_error".to_string(),
    }
}


pub fn decrypt_string(shared_key: &[u8], encrypted_b64: &str) -> String {
    let key = Key::<Aes256Gcm>::from_slice(shared_key);
    let cipher = Aes256Gcm::new(key);

    let combined = match b64decode(encrypted_b64) {
        Ok(data) => data,
        Err(_) => return "base64_decode_error".into(),
    };
// if clear == "base64_decode_error" || clear == "invalid_data"  || clear == "decryption_error"{}
    if combined.len() < NONCE_LEN {
        return "invalid_data".into();
    }

    let nonce = Nonce::from_slice(&combined[..NONCE_LEN]);
    let ciphertext = &combined[NONCE_LEN..];

    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => String::from_utf8_lossy(&plaintext).to_string(),
        Err(_) => "decryption_error".into(),
    }
}
