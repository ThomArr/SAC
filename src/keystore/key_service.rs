use anyhow::Result;

#[async_trait::async_trait]
pub trait KeystoreService {
    async fn wrap_cek(&self, cek: &[u8]) -> Result<Vec<u8>>;
    async fn unwrap_cek(&self, wrapped: &[u8]) -> Result<Vec<u8>>;

    fn key_id(&self) -> String;
    fn key_wrap_algorithm(&self) -> &'static str;
}
