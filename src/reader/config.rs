use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub cloud: CloudConfig,
    pub tlsse: Option<String>,
    pub keystore: KeystoreConfig,
}

#[derive(Debug, Deserialize)]
pub struct CloudConfig {
    pub provider: String,
    pub root: Option<String>,

    pub credentials_path: Option<String>,
    pub container: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KeystoreConfig {
    pub connection_mode: String,
    pub host: String,
    pub port: u16,
    pub sni: String,
    pub slot: u8,

    pub keystore_identity: String,
    pub keystore_psk: Option<String>,

    pub secure_element: Option<SecureElementConfig>,
}

#[derive(Debug, Deserialize)]
pub struct SecureElementConfig {
    pub host: String,
    pub port: u16,
    pub sni: String,
    pub se_identity: String,
    pub se_psk: String,
}

pub fn load_config() -> Result<Config> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config.yaml");

    let text = std::fs::read_to_string(path)?;
    Ok(serde_yaml::from_str(&text)?)
}
