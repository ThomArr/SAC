use anyhow::Result;
use tokio::fs;

use crate::{
    cloud::metadata::FileMetadata,
    cloud::provider::{CloudEntry, CloudEntryKind, CloudProvider},
};

pub struct LocalCloudProvider {
    pub root: String,
}

impl LocalCloudProvider {
    pub fn new(root: impl Into<String>) -> Self {
        Self { root: root.into() }
    }

    fn full_path(&self, path: &str) -> String {
        format!("{}/{}", self.root.trim_end_matches('/'), path)
    }

    fn metadata_path(&self, path: &str) -> String {
        format!("{}.metadata.json", path)
    }
}

#[async_trait::async_trait]
impl CloudProvider for LocalCloudProvider {
    async fn ls(&self, path: &str) -> Result<Vec<CloudEntry>> {
        let full_path = self.full_path(path);

        if fs::metadata(&full_path).await.is_err() {
            return Ok(vec![]);
        }

        let mut entries = fs::read_dir(full_path).await?;
        let mut result = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let file_type = entry.file_type().await?;
            let name = entry.file_name().to_string_lossy().to_string();

            if name.ends_with(".metadata.json") {
                continue;
            }

            let entry_path = if path.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", path.trim_end_matches('/'), name)
            };

            let kind = if file_type.is_dir() {
                CloudEntryKind::Directory
            } else {
                CloudEntryKind::File
            };

            result.push(CloudEntry {
                name,
                path: entry_path,
                kind,
            });
        }

        result.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(result)
    }

    async fn put_encrypted_file(
        &self,
        path: &str,
        ciphertext: &[u8],
        metadata: &FileMetadata,
    ) -> Result<()> {
        let data_path = self.full_path(path);
        let metadata_path = self.full_path(&self.metadata_path(path));

        if let Some(parent) = std::path::Path::new(&data_path).parent() {
            fs::create_dir_all(parent).await?;
        }

        if let Some(parent) = std::path::Path::new(&metadata_path).parent() {
            fs::create_dir_all(parent).await?;
        }

        fs::write(data_path, ciphertext).await?;

        let metadata_bytes = serde_json::to_vec_pretty(&metadata.to_encryptiondata())?;
        fs::write(metadata_path, metadata_bytes).await?;

        Ok(())
    }

    async fn get_encrypted_file(&self, path: &str) -> Result<(Vec<u8>, FileMetadata)> {
        let ciphertext = fs::read(self.full_path(path)).await?;

        let metadata_bytes = fs::read(self.full_path(&self.metadata_path(path))).await?;

        let metadata_json: serde_json::Value = serde_json::from_slice(&metadata_bytes)?;
        let metadata = FileMetadata::from_encryptiondata(metadata_json)?;

        Ok((ciphertext, metadata))
    }

    async fn delete_encrypted_file(&self, path: &str) -> Result<()> {
        let data_path = self.full_path(path);
        let metadata_path = self.full_path(&self.metadata_path(path));

        if fs::metadata(&data_path).await.is_ok() {
            fs::remove_file(data_path).await?;
        }

        if fs::metadata(&metadata_path).await.is_ok() {
            fs::remove_file(metadata_path).await?;
        }

        Ok(())
    }

    async fn create_dir(&self, path: &str) -> Result<()> {
        let full_path = self.full_path(path);
        fs::create_dir_all(full_path).await?;
        Ok(())
    }

    async fn delete_dir(&self, path: &str) -> Result<()> {
        let full_path = self.full_path(path);

        if fs::metadata(&full_path).await.is_ok() {
            fs::remove_dir_all(full_path).await?;
        }

        Ok(())
    }
}
