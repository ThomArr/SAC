use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use tokio::fs;

use crate::{
    app::aes_gcm::{encrypt, generate_cek},
    cloud::{metadata::FileMetadata, provider::CloudProvider},
    keystore::key_service::KeystoreService,
};

pub async fn upload_file<C, K>(
    cloud: &C,
    key_service: &K,
    input_path: &str,
    remote_path: &str,
) -> Result<()>
where
    C: CloudProvider + Sync + ?Sized,
    K: KeystoreService + Sync + ?Sized,
{
    let plaintext = fs::read(input_path).await?;

    let cek = generate_cek();
    
    let ciphertext = encrypt(&cek, &plaintext)?;

    let wrapped_key = key_service.wrap_cek(&cek).await?;

    let metadata = FileMetadata {
        encryption_algorithm: crate::app::aes_gcm::algorithm().to_string(),
        key_id: key_service.key_id(),
        key_wrap_algorithm: key_service.key_wrap_algorithm().to_string(),
        wrapped_key: general_purpose::STANDARD.encode(wrapped_key),
    };

    cloud
        .put_encrypted_file(remote_path, &ciphertext, &metadata)
        .await?;

    Ok(())
}
