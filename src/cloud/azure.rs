use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};
use chrono::Utc;
use hmac::{Hmac, Mac};
use quick_xml::de::from_str;
use reqwest::{Client, Method};
use serde::Deserialize;
use sha2::Sha256;

use crate::{
    cloud::{
        metadata::FileMetadata,
        provider::{CloudEntry, CloudEntryKind, CloudProvider},
    },
    reader::credentials::read_azure_connection_string,
};

type HmacSha256 = Hmac<Sha256>;

pub struct AzureCloudProvider {
    account_name: String,
    account_key: Vec<u8>,
    endpoint_suffix: String,
    container: String,
    client: Client,
}

impl AzureCloudProvider {
    pub fn new(credentials_path: impl AsRef<str>, container: impl Into<String>) -> Result<Self> {
        let connection_string = read_azure_connection_string(credentials_path.as_ref())?;

        let account_name = get_connection_value(&connection_string, "AccountName")?;
        let account_key_b64 = get_connection_value(&connection_string, "AccountKey")?;
        let endpoint_suffix = get_connection_value(&connection_string, "EndpointSuffix")?;

        let account_key = general_purpose::STANDARD.decode(account_key_b64)?;

        Ok(Self {
            account_name,
            account_key,
            endpoint_suffix,
            container: container.into(),
            client: Client::new(),
        })
    }

    fn blob_url(&self, path: &str) -> String {
        let encoded_path = encode_path(path);

        format!(
            "https://{}.blob.{}/{}/{}",
            self.account_name, self.endpoint_suffix, self.container, encoded_path
        )
    }

    fn container_url_with_query(&self, query: &str) -> String {
        format!(
            "https://{}.blob.{}/{}?{}",
            self.account_name, self.endpoint_suffix, self.container, query
        )
    }

    fn auth_header(
        &self,
        method: &str,
        resource_path: &str,
        content_length: Option<usize>,
        content_type: Option<&str>,
        canonicalized_query: Option<&str>,
        extra_headers: &[(&str, &str)],
    ) -> Result<(String, String)> {
        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();

        let content_length_string = match content_length {
            Some(0) | None => String::new(),
            Some(value) => value.to_string(),
        };

        let content_type = content_type.unwrap_or("");

        let mut x_ms_headers = vec![("x-ms-date", date.as_str()), ("x-ms-version", "2021-12-02")];

        for (k, v) in extra_headers {
            x_ms_headers.push((k, v));
        }

        x_ms_headers.sort_by(|a, b| a.0.cmp(b.0));

        let canonicalized_headers = x_ms_headers
            .iter()
            .map(|(k, v)| format!("{}:{}\n", k.to_lowercase(), v))
            .collect::<String>();

        let mut canonicalized_resource = if resource_path.is_empty() {
            format!("/{}/{}", self.account_name, self.container)
        } else {
            format!(
                "/{}/{}/{}",
                self.account_name, self.container, resource_path
            )
        };

        if let Some(query) = canonicalized_query {
            canonicalized_resource.push('\n');
            canonicalized_resource.push_str(query);
        }

        let string_to_sign = format!(
            "{method}\n\n\n{content_length}\n\n{content_type}\n\n\n\n\n\n\n{headers}{resource}",
            method = method,
            content_length = content_length_string,
            content_type = content_type,
            headers = canonicalized_headers,
            resource = canonicalized_resource,
        );

        let mut mac = HmacSha256::new_from_slice(&self.account_key)?;
        mac.update(string_to_sign.as_bytes());

        let signature = general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        let authorization = format!("SharedKey {}:{}", self.account_name, signature);

        Ok((date, authorization))
    }

    fn build_encryptiondata(metadata: &FileMetadata) -> Result<String> {
        Ok(metadata.to_encryptiondata().to_string())
    }

    async fn put_blob(
        &self,
        path: &str,
        data: &[u8],
        content_type: &str,
        metadata: Option<&FileMetadata>,
    ) -> Result<()> {
        let url = self.blob_url(path);

        let mut extra_headers = vec![("x-ms-blob-type", "BlockBlob")];

        let encryptiondata = if let Some(metadata) = metadata {
            Some(Self::build_encryptiondata(metadata)?)
        } else {
            None
        };

        if let Some(encryptiondata) = encryptiondata.as_ref() {
            extra_headers.push(("x-ms-meta-encryptiondata", encryptiondata.as_str()));
        }

        let (date, authorization) = self.auth_header(
            "PUT",
            path,
            Some(data.len()),
            Some(content_type),
            None,
            &extra_headers,
        )?;

        let mut request = self
            .client
            .request(Method::PUT, url)
            .header("x-ms-date", date)
            .header("x-ms-version", "2021-12-02")
            .header("x-ms-blob-type", "BlockBlob")
            .header("Authorization", authorization)
            .header("Content-Type", content_type);

        if let Some(encryptiondata) = encryptiondata {
            request = request.header("x-ms-meta-encryptiondata", encryptiondata);
        }

        let response = request.body(data.to_vec()).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Azure PUT failed: {}", response.text().await?));
        }

        Ok(())
    }

    async fn get_blob_with_metadata(&self, path: &str) -> Result<(Vec<u8>, FileMetadata)> {
        let url = self.blob_url(path);

        let (date, authorization) = self.auth_header("GET", path, None, None, None, &[])?;

        let response = self
            .client
            .request(Method::GET, url)
            .header("x-ms-date", date)
            .header("x-ms-version", "2021-12-02")
            .header("Authorization", authorization)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("Azure GET failed: {}", response.text().await?));
        }

        let headers = response.headers().clone();

        let encryptiondata = headers
            .get("x-ms-meta-encryptiondata")
            .ok_or_else(|| anyhow!("missing Azure metadata: encryptiondata"))?
            .to_str()?;

        let value: serde_json::Value = serde_json::from_str(encryptiondata)?;
        let metadata = FileMetadata::from_encryptiondata(value)?;

        let ciphertext = response.bytes().await?.to_vec();

        Ok((ciphertext, metadata))
    }

    async fn delete_blob(&self, path: &str) -> Result<()> {
        let url = self.blob_url(path);

        let (date, authorization) = self.auth_header("DELETE", path, None, None, None, &[])?;

        let response = self
            .client
            .request(Method::DELETE, url)
            .header("x-ms-date", date)
            .header("x-ms-version", "2021-12-02")
            .header("Authorization", authorization)
            .send()
            .await?;

        if response.status().is_success() || response.status().as_u16() == 404 {
            return Ok(());
        }

        Err(anyhow!("Azure DELETE failed: {}", response.text().await?))
    }

    async fn list_blobs(&self, path: &str) -> Result<Vec<CloudEntry>> {
        let prefix = if path.is_empty() {
            String::new()
        } else {
            format!("{}/", path.trim_end_matches('/'))
        };

        let query = format!(
            "restype=container&comp=list&delimiter=/&prefix={}",
            urlencoding::encode(&prefix)
        );

        let canonicalized_query = format!(
            "comp:list\ndelimiter:/\nprefix:{}\nrestype:container",
            prefix
        );

        let url = self.container_url_with_query(&query);

        let (date, authorization) =
            self.auth_header("GET", "", None, None, Some(&canonicalized_query), &[])?;

        let response = self
            .client
            .request(Method::GET, url)
            .header("x-ms-date", date)
            .header("x-ms-version", "2021-12-02")
            .header("Authorization", authorization)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("Azure LIST failed: {}", response.text().await?));
        }

        let body = response.text().await?;
        let parsed: EnumerationResults = from_str(&body)?;

        let mut entries = Vec::new();

        if let Some(prefixes) = parsed.blobs.blob_prefix {
            for item in prefixes {
                let full_path = item.name.trim_end_matches('/').to_string();

                if full_path.ends_with(".metadata.json") {
                    continue;
                }

                entries.push(CloudEntry {
                    name: basename(&full_path),
                    path: full_path,
                    kind: CloudEntryKind::Directory,
                });
            }
        }

        if let Some(blobs) = parsed.blobs.blob {
            for item in blobs {
                if item.name.ends_with(".metadata.json") {
                    continue;
                }

                entries.push(CloudEntry {
                    name: basename(&item.name),
                    path: item.name,
                    kind: CloudEntryKind::File,
                });
            }
        }

        entries.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(entries)
    }
}

#[async_trait::async_trait]
impl CloudProvider for AzureCloudProvider {
    async fn ls(&self, path: &str) -> Result<Vec<CloudEntry>> {
        self.list_blobs(path).await
    }

    async fn put_encrypted_file(
        &self,
        path: &str,
        ciphertext: &[u8],
        metadata: &FileMetadata,
    ) -> Result<()> {
        self.put_blob(path, ciphertext, "application/octet-stream", Some(metadata))
            .await
    }

    async fn get_encrypted_file(&self, path: &str) -> Result<(Vec<u8>, FileMetadata)> {
        self.get_blob_with_metadata(path).await
    }

    async fn delete_encrypted_file(&self, path: &str) -> Result<()> {
        self.delete_blob(path).await
    }

    async fn create_dir(&self, path: &str) -> Result<()> {
        let marker_path = format!("{}/.dir", path.trim_end_matches('/'));
        self.put_blob(&marker_path, b"", "application/octet-stream", None)
            .await
    }

    async fn delete_dir(&self, path: &str) -> Result<()> {
        let entries = self.list_blobs(path).await?;

        for entry in entries {
            match entry.kind {
                CloudEntryKind::File => {
                    self.delete_encrypted_file(&entry.path).await?;
                }
                CloudEntryKind::Directory => {
                    self.delete_dir(&entry.path).await?;
                }
            }
        }

        let marker_path = format!("{}/.dir", path.trim_end_matches('/'));
        self.delete_blob(&marker_path).await?;

        Ok(())
    }
}

fn get_connection_value(connection_string: &str, key: &str) -> Result<String> {
    for part in connection_string.split(';') {
        if let Some((k, v)) = part.split_once('=') {
            if k == key {
                return Ok(v.to_string());
            }
        }
    }

    Err(anyhow!("missing Azure connection string value: {}", key))
}

fn encode_path(path: &str) -> String {
    path.split('/')
        .map(urlencoding::encode)
        .collect::<Vec<_>>()
        .join("/")
}

fn basename(path: &str) -> String {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .to_string()
}

#[derive(Debug, Deserialize)]
struct EnumerationResults {
    #[serde(rename = "Blobs")]
    blobs: Blobs,
}

#[derive(Debug, Deserialize)]
struct Blobs {
    #[serde(rename = "Blob", default)]
    blob: Option<Vec<BlobItem>>,

    #[serde(rename = "BlobPrefix", default)]
    blob_prefix: Option<Vec<BlobPrefix>>,
}

#[derive(Debug, Deserialize)]
struct BlobItem {
    #[serde(rename = "Name")]
    name: String,
}

#[derive(Debug, Deserialize)]
struct BlobPrefix {
    #[serde(rename = "Name")]
    name: String,
}
