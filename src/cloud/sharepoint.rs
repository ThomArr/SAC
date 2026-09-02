use anyhow::{anyhow, Result};
use reqwest::{Client, Method};
use serde::Deserialize;

use crate::{
    cloud::{
        metadata::FileMetadata,
        provider::{CloudEntry, CloudEntryKind, CloudProvider},
    },
    reader::credentials::read_key_value_file,
};

pub struct SharePointCloudProvider {
    tenant_id: String,
    client_id: String,
    client_secret: String,
    sharepoint_hostname: String,
    sharepoint_site_path: String,
    client: Client,
}

impl SharePointCloudProvider {
    pub fn new(credentials_path: impl AsRef<str>) -> Result<Self> {
        let values = read_key_value_file(credentials_path.as_ref())?;

        Ok(Self {
            tenant_id: get_value(&values, "tenant_id")?,
            client_id: get_value(&values, "client_id")?,
            client_secret: get_value(&values, "client_secret")?,
            sharepoint_hostname: get_value(&values, "sharepoint_hostname")?,
            sharepoint_site_path: get_value(&values, "sharepoint_site_path")?,
            client: Client::new(),
        })
    }

    async fn access_token(&self) -> Result<String> {
        let url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        );

        let response = self
            .client
            .post(url)
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("scope", "https://graph.microsoft.com/.default"),
                ("grant_type", "client_credentials"),
            ])
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "SharePoint token request failed: {}",
                response.text().await?
            ));
        }

        let token_response: TokenResponse = response.json().await?;
        Ok(token_response.access_token)
    }

    async fn site_id(&self, token: &str) -> Result<String> {
        let url = format!(
            "https://graph.microsoft.com/v1.0/sites/{}:/{}",
            self.sharepoint_hostname,
            self.sharepoint_site_path.trim_matches('/')
        );

        let response = self.client.get(url).bearer_auth(token).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "SharePoint site lookup failed: {}",
                response.text().await?
            ));
        }

        let site: SiteResponse = response.json().await?;
        Ok(site.id)
    }

    async fn drive_id(&self, token: &str, site_id: &str) -> Result<String> {
        let url = format!("https://graph.microsoft.com/v1.0/sites/{}/drive", site_id);

        let response = self.client.get(url).bearer_auth(token).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "SharePoint drive lookup failed: {}",
                response.text().await?
            ));
        }

        let drive: DriveResponse = response.json().await?;
        Ok(drive.id)
    }

    async fn graph_context(&self) -> Result<GraphContext> {
        let token = self.access_token().await?;
        let site_id = self.site_id(&token).await?;
        let drive_id = self.drive_id(&token, &site_id).await?;

        Ok(GraphContext { token, drive_id })
    }

    fn item_path(path: &str) -> String {
        path.trim_matches('/').to_string()
    }

    fn metadata_path(path: &str) -> String {
        format!("{}.metadata.json", path)
    }

    fn parent_path(path: &str) -> String {
        match path.trim_matches('/').rsplit_once('/') {
            Some((parent, _)) => parent.to_string(),
            None => String::new(),
        }
    }

    fn basename(path: &str) -> String {
        path.trim_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or(path)
            .to_string()
    }

    async fn ensure_parent_dirs(&self, ctx: &GraphContext, path: &str) -> Result<()> {
        let parent = Self::parent_path(path);

        if parent.is_empty() {
            return Ok(());
        }

        let mut current = String::new();

        for part in parent.split('/') {
            if part.is_empty() {
                continue;
            }

            let next = if current.is_empty() {
                part.to_string()
            } else {
                format!("{}/{}", current, part)
            };

            self.create_single_dir_with_context(ctx, &next).await?;

            current = next;
        }

        Ok(())
    }

    async fn put_file_with_context(
        &self,
        ctx: &GraphContext,
        path: &str,
        data: &[u8],
    ) -> Result<()> {
        self.ensure_parent_dirs(ctx, path).await?;

        let encoded_path = encode_path(&Self::item_path(path));

        let url = format!(
            "https://graph.microsoft.com/v1.0/drives/{}/root:/{}:/content",
            ctx.drive_id, encoded_path
        );

        let response = self
            .client
            .put(url)
            .bearer_auth(&ctx.token)
            .body(data.to_vec())
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "SharePoint upload failed: {}",
                response.text().await?
            ));
        }

        Ok(())
    }

    async fn get_file_with_context(&self, ctx: &GraphContext, path: &str) -> Result<Vec<u8>> {
        let encoded_path = encode_path(&Self::item_path(path));

        let url = format!(
            "https://graph.microsoft.com/v1.0/drives/{}/root:/{}:/content",
            ctx.drive_id, encoded_path
        );

        let response = self.client.get(url).bearer_auth(&ctx.token).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "SharePoint download failed: {}",
                response.text().await?
            ));
        }

        Ok(response.bytes().await?.to_vec())
    }

    async fn delete_item_with_context(&self, ctx: &GraphContext, path: &str) -> Result<()> {
        let encoded_path = encode_path(&Self::item_path(path));

        let url = format!(
            "https://graph.microsoft.com/v1.0/drives/{}/root:/{}",
            ctx.drive_id, encoded_path
        );

        let response = self
            .client
            .request(Method::DELETE, url)
            .bearer_auth(&ctx.token)
            .send()
            .await?;

        if response.status().is_success() || response.status().as_u16() == 404 {
            return Ok(());
        }

        Err(anyhow!(
            "SharePoint delete failed: {}",
            response.text().await?
        ))
    }

    async fn create_single_dir_with_context(&self, ctx: &GraphContext, path: &str) -> Result<()> {
        if path.trim().is_empty() {
            return Ok(());
        }

        if self.item_exists(ctx, path).await? {
            return Ok(());
        }

        let parent = Self::parent_path(path);
        let name = Self::basename(path);

        let url = if parent.is_empty() {
            format!(
                "https://graph.microsoft.com/v1.0/drives/{}/root/children",
                ctx.drive_id
            )
        } else {
            format!(
                "https://graph.microsoft.com/v1.0/drives/{}/root:/{}/:/children",
                ctx.drive_id,
                encode_path(&parent)
            )
        };

        let body = serde_json::json!({
            "name": name,
            "folder": {},
            "@microsoft.graph.conflictBehavior": "fail"
        });

        let response = self
            .client
            .post(url)
            .bearer_auth(&ctx.token)
            .json(&body)
            .send()
            .await?;

        if response.status().is_success() || response.status().as_u16() == 409 {
            return Ok(());
        }

        Err(anyhow!(
            "SharePoint create folder failed: {}",
            response.text().await?
        ))
    }

    async fn create_dir_with_context(&self, ctx: &GraphContext, path: &str) -> Result<()> {
        self.ensure_parent_dirs(ctx, path).await?;
        self.create_single_dir_with_context(ctx, path).await
    }

    async fn item_exists(&self, ctx: &GraphContext, path: &str) -> Result<bool> {
        let encoded_path = encode_path(&Self::item_path(path));

        let url = format!(
            "https://graph.microsoft.com/v1.0/drives/{}/root:/{}",
            ctx.drive_id, encoded_path
        );

        let response = self.client.get(url).bearer_auth(&ctx.token).send().await?;

        if response.status().is_success() {
            Ok(true)
        } else if response.status().as_u16() == 404 {
            Ok(false)
        } else {
            Err(anyhow!(
                "SharePoint item lookup failed: {}",
                response.text().await?
            ))
        }
    }

    async fn list_with_context(&self, ctx: &GraphContext, path: &str) -> Result<Vec<CloudEntry>> {
        let url = if path.trim().is_empty() {
            format!(
                "https://graph.microsoft.com/v1.0/drives/{}/root/children",
                ctx.drive_id
            )
        } else {
            format!(
                "https://graph.microsoft.com/v1.0/drives/{}/root:/{}/:/children",
                ctx.drive_id,
                encode_path(path.trim_matches('/'))
            )
        };

        let response = self.client.get(url).bearer_auth(&ctx.token).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "SharePoint list failed: {}",
                response.text().await?
            ));
        }

        let body: DriveChildrenResponse = response.json().await?;
        let mut entries = Vec::new();

        for item in body.value {
            if item.name.ends_with(".metadata.json") {
                continue;
            }

            let entry_path = if path.is_empty() {
                item.name.clone()
            } else {
                format!("{}/{}", path.trim_end_matches('/'), item.name)
            };

            let kind = if item.folder.is_some() {
                CloudEntryKind::Directory
            } else {
                CloudEntryKind::File
            };

            entries.push(CloudEntry {
                name: item.name,
                path: entry_path,
                kind,
            });
        }

        entries.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(entries)
    }
}

#[async_trait::async_trait]
impl CloudProvider for SharePointCloudProvider {
    async fn ls(&self, path: &str) -> Result<Vec<CloudEntry>> {
        let ctx = self.graph_context().await?;
        self.list_with_context(&ctx, path).await
    }

    async fn put_encrypted_file(
        &self,
        path: &str,
        ciphertext: &[u8],
        metadata: &FileMetadata,
    ) -> Result<()> {
        let ctx = self.graph_context().await?;
        let metadata_bytes = serde_json::to_vec_pretty(&metadata.to_encryptiondata())?;

        self.put_file_with_context(&ctx, path, ciphertext).await?;
        self.put_file_with_context(&ctx, &Self::metadata_path(path), &metadata_bytes)
            .await?;

        Ok(())
    }

    async fn get_encrypted_file(&self, path: &str) -> Result<(Vec<u8>, FileMetadata)> {
        let ctx = self.graph_context().await?;

        let ciphertext = self.get_file_with_context(&ctx, path).await?;
        let metadata_bytes = self
            .get_file_with_context(&ctx, &Self::metadata_path(path))
            .await?;

        let metadata_json: serde_json::Value = serde_json::from_slice(&metadata_bytes)?;
        let metadata = FileMetadata::from_encryptiondata(metadata_json)?;

        Ok((ciphertext, metadata))
    }

    async fn delete_encrypted_file(&self, path: &str) -> Result<()> {
        let ctx = self.graph_context().await?;

        self.delete_item_with_context(&ctx, path).await?;
        self.delete_item_with_context(&ctx, &Self::metadata_path(path))
            .await?;

        Ok(())
    }

    async fn create_dir(&self, path: &str) -> Result<()> {
        let ctx = self.graph_context().await?;
        self.create_dir_with_context(&ctx, path).await
    }

    async fn delete_dir(&self, path: &str) -> Result<()> {
        let ctx = self.graph_context().await?;
        self.delete_item_with_context(&ctx, path).await
    }
}

fn get_value(values: &std::collections::HashMap<String, String>, key: &str) -> Result<String> {
    values
        .get(key)
        .cloned()
        .ok_or_else(|| anyhow!("missing SharePoint credential: {}", key))
}

fn encode_path(path: &str) -> String {
    path.split('/')
        .map(urlencoding::encode)
        .collect::<Vec<_>>()
        .join("/")
}

struct GraphContext {
    token: String,
    drive_id: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct SiteResponse {
    id: String,
}

#[derive(Debug, Deserialize)]
struct DriveResponse {
    id: String,
}

#[derive(Debug, Deserialize)]
struct DriveChildrenResponse {
    value: Vec<DriveItem>,
}

#[derive(Debug, Deserialize)]
struct DriveItem {
    name: String,
    folder: Option<serde_json::Value>,
}
