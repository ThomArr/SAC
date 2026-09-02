use anyhow::{anyhow, Result};

use crate::{
    cloud::{local::LocalCloudProvider, provider::CloudProvider},
    reader::config::load_config,
};

pub fn build_cloud() -> Result<Box<dyn CloudProvider + Send + Sync>> {
    let cfg = load_config()?;

    match cfg.cloud.provider.as_str() {
        "local" => {
            let root = cfg.cloud.root.unwrap_or_else(|| "storage".to_string());

            Ok(Box::new(LocalCloudProvider::new(root)))
        }

        "azure" => {
            let credentials_path = cfg
                .cloud
                .credentials_path
                .ok_or_else(|| anyhow!("missing cloud.credentials_path"))?;

            let container = cfg
                .cloud
                .container
                .ok_or_else(|| anyhow!("missing cloud.container"))?;

            Ok(Box::new(crate::cloud::azure::AzureCloudProvider::new(
                credentials_path,
                container,
            )?))
        }

        "sharepoint" => {
            let credentials_path = cfg
                .cloud
                .credentials_path
                .ok_or_else(|| anyhow!("missing cloud.credentials_path"))?;

            Ok(Box::new(
                crate::cloud::sharepoint::SharePointCloudProvider::new(credentials_path)?,
            ))
        }

        other => Err(anyhow!("unsupported cloud provider: {}", other)),
    }
}
