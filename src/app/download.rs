use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};
use tokio::fs;

use crate::{
    app::aes_gcm::decrypt, cloud::provider::CloudProvider, keystore::key_service::KeystoreService,
};

pub async fn download_file<C, K>(
    cloud: &C,
    key_service: &K,
    remote_path: &str,
    output_path: &str,
) -> Result<()>
where
    C: CloudProvider + Sync + ?Sized,
    K: KeystoreService + Sync + ?Sized,
{
    let (ciphertext, metadata) = cloud.get_encrypted_file(remote_path).await?;

    if metadata.encryption_algorithm != crate::app::aes_gcm::algorithm() {
        return Err(anyhow!(
            "Unsupported encryption algorithm: {}",
            metadata.encryption_algorithm
        ));
    }

    if metadata.key_wrap_algorithm != key_service.key_wrap_algorithm() {
        return Err(anyhow!(
            "Unsupported key wrap algorithm: {}",
            metadata.key_wrap_algorithm
        ));
    }

    if metadata.key_id != key_service.key_id() {
        return Err(anyhow!(
            "Wrong key id: expected {}, got {}",
            key_service.key_id(),
            metadata.key_id
        ));
    }

    let wrapped_key = general_purpose::STANDARD.decode(metadata.wrapped_key)?;

    let cek_vec = key_service.unwrap_cek(&wrapped_key).await?;

    let cek: [u8; 32] = cek_vec.try_into().map_err(|_| anyhow!("Invalid CEK"))?;

    let plaintext = decrypt(&cek, &ciphertext)?;

    fs::write(output_path, plaintext).await?;

    Ok(())
}
