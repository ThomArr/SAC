use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct FileMetadata {
    pub encryption_algorithm: String,
    pub key_id: String,
    pub key_wrap_algorithm: String,
    pub wrapped_key: String,
}

impl FileMetadata {
    pub fn to_encryptiondata(&self) -> serde_json::Value {
        serde_json::json!({
            "WrappedCEK": {
                "KeyId": self.key_id,
                "EncryptedKey": self.wrapped_key,
                "Algorithm": self.key_wrap_algorithm
            },
            "EncryptionData": {
                "EncryptionAlgorithm": self.encryption_algorithm
            }
        })
    }

    pub fn from_encryptiondata(value: serde_json::Value) -> Result<Self> {
        let wrapped = &value["WrappedCEK"];

        Ok(Self {
            encryption_algorithm: value["EncryptionData"]["EncryptionAlgorithm"]
                .as_str()
                .ok_or_else(|| anyhow!("missing EncryptionData.EncryptionAlgorithm"))?
                .to_string(),

            key_id: wrapped["KeyId"]
                .as_str()
                .map(|s| s.to_string())
                .unwrap_or_else(|| wrapped["KeyId"].to_string()),

            key_wrap_algorithm: wrapped["Algorithm"]
                .as_str()
                .ok_or_else(|| anyhow!("missing WrappedCEK.Algorithm"))?
                .to_string(),

            wrapped_key: wrapped["EncryptedKey"]
                .as_str()
                .ok_or_else(|| anyhow!("missing WrappedCEK.EncryptedKey"))?
                .to_string(),
        })
    }
}
