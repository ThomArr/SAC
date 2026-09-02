use anyhow::Result;

use crate::cloud::metadata::FileMetadata;

#[derive(Debug, Clone)]
pub enum CloudEntryKind {
    File,
    Directory,
}

#[derive(Debug, Clone)]
pub struct CloudEntry {
    pub name: String,
    pub path: String,
    pub kind: CloudEntryKind,
}

#[async_trait::async_trait]
pub trait CloudProvider {
    async fn ls(&self, path: &str) -> Result<Vec<CloudEntry>>;

    async fn put_encrypted_file(
        &self,
        path: &str,
        ciphertext: &[u8],
        metadata: &FileMetadata,
    ) -> Result<()>;

    async fn get_encrypted_file(&self, path: &str) -> Result<(Vec<u8>, FileMetadata)>;

    async fn delete_encrypted_file(&self, path: &str) -> Result<()>;

    async fn create_dir(&self, path: &str) -> Result<()>;

    async fn delete_dir(&self, path: &str) -> Result<()>;
}
