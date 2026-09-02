use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use rand::RngCore;

pub fn algorithm() -> &'static str {
    "AES256_GCM"
}

pub fn generate_cek() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

pub fn encrypt(cek: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = generate_nonce();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(cek));

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|err| anyhow!("AES-GCM encryption failed: {}", err))?;

    let mut encrypted_payload = Vec::with_capacity(12 + ciphertext.len());
    encrypted_payload.extend_from_slice(&nonce);
    encrypted_payload.extend_from_slice(&ciphertext);

    Ok(encrypted_payload)
}

pub fn decrypt(cek: &[u8; 32], encrypted_payload: &[u8]) -> Result<Vec<u8>> {
    if encrypted_payload.len() < 12 {
        return Err(anyhow!("encrypted payload too short (nonce: minimum size 12)"));
    }

    let nonce = &encrypted_payload[..12];
    let ciphertext = &encrypted_payload[12..];
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(cek));

    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|err| anyhow!("AES-GCM decryption failed: {}", err))
}
