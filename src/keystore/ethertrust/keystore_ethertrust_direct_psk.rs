use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};

use anyhow::{anyhow, Result};
use openssl::ssl::{SslConnector, SslMethod, SslOptions, SslStream, SslVerifyMode, SslVersion};
use std::time::Duration;

use crate::keystore::key_service::KeystoreService;

pub struct KeystoreEthertrust {
    host: String,
    port: u16,
    sni: String,
    slot: u8,
    identity: String,
    psk: Vec<u8>,
}

impl KeystoreEthertrust {
    pub fn new(
        host: impl Into<String>,
        port: u16,
        sni: impl Into<String>,
        slot: u8,
        identity: impl Into<String>,
        psk_hex: &str,
    ) -> Result<Self> {
        Ok(Self {
            host: host.into(),
            port,
            sni: sni.into(),
            slot,
            identity: identity.into(),
            psk: hex::decode(psk_hex)?,
        })
    }

    fn connect(&self) -> Result<SslStream<TcpStream>> {
        let mut builder = SslConnector::builder(SslMethod::tls_client())?;

        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_ciphersuites("TLS_AES_128_CCM_SHA256")?;
        builder.set_groups_list("P-256")?;
        builder.set_options(SslOptions::NO_TICKET);
        builder.set_verify(SslVerifyMode::NONE);

        let identity = self.identity.clone().into_bytes();
        let psk = self.psk.clone();

        builder.set_psk_client_callback(move |_ssl, _hint, identity_buf, psk_buf| {
            if identity.len() > identity_buf.len() || psk.len() > psk_buf.len() {
                return Err(openssl::error::ErrorStack::get());
            }

            identity_buf[..identity.len()].copy_from_slice(&identity);
            psk_buf[..psk.len()].copy_from_slice(&psk);

            Ok(psk.len())
        });

        let connector = builder.build();

        let addr = (self.host.as_str(), self.port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("unable to resolve host"))?;

        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(5)))?;

        Ok(connector.connect(&self.sni, tcp)?)
    }

    fn check_slot(&self) -> Result<()> {
        if self.slot > 3 {
            return Err(anyhow!("slot must be in [0, 3]"));
        }

        Ok(())
    }

    fn send_aes_command(
        &self,
        tls: &mut SslStream<TcpStream>,
        block: &[u8; 16],
    ) -> Result<[u8; 16]> {
        self.check_slot()?;

        let command = format!("A4{:x}{}\r\n", self.slot, hex::encode_upper(block));

        tls.write_all(command.as_bytes())?;
        tls.flush()?;

        let mut buf = [0u8; 4096];
        let n = tls.read(&mut buf)?;

        if n == 0 {
            return Err(anyhow!("HSM closed connection"));
        }

        let response = std::str::from_utf8(&buf[..n])?.trim();
        let decoded = hex::decode(response)?;

        let block: [u8; 16] = decoded
            .try_into()
            .map_err(|_| anyhow!("Invalid AES block length returned by HSM"))?;

        Ok(block)
    }

    fn wrap_ctr_with_tls(&self, key: &[u8]) -> Result<Vec<u8>> {
        use rand::RngCore;

        let mut tls = self.connect()?;

        let mut counter = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut counter[..12]);
        counter[12..].copy_from_slice(&0u32.to_be_bytes());

        let mut output = Vec::with_capacity(12 + key.len());
        output.extend_from_slice(&counter[..12]);

        for chunk in key.chunks(16) {
            let keystream = self.send_aes_command(&mut tls, &counter)?;

            for i in 0..chunk.len() {
                output.push(chunk[i] ^ keystream[i]);
            }

            increment_counter(&mut counter);
        }

        Ok(output)
    }

    fn unwrap_ctr_with_tls(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
        if wrapped.len() < 12 {
            return Err(anyhow!("wrapped key too short"));
        }

        let mut tls = self.connect()?;

        let nonce = &wrapped[..12];
        let ciphertext = &wrapped[12..];

        let mut counter = [0u8; 16];
        counter[..12].copy_from_slice(nonce);
        counter[12..].copy_from_slice(&0u32.to_be_bytes());

        let mut output = Vec::with_capacity(ciphertext.len());

        for chunk in ciphertext.chunks(16) {
            let keystream = self.send_aes_command(&mut tls, &counter)?;

            for i in 0..chunk.len() {
                output.push(chunk[i] ^ keystream[i]);
            }

            increment_counter(&mut counter);
        }

        Ok(output)
    }
}

#[async_trait::async_trait]
impl KeystoreService for KeystoreEthertrust {
    async fn wrap_cek(&self, cek: &[u8]) -> Result<Vec<u8>> {
        if cek.len() != 32 {
            return Err(anyhow!("CEK must be 32 bytes for AES-256-GCM"));
        }
        self.wrap_ctr_with_tls(cek)
    }

    async fn unwrap_cek(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
        if wrapped.len() != 44 {
            return Err(anyhow!("wrapped CEK must be 44 bytes"));
        }

        self.unwrap_ctr_with_tls(wrapped)
    }

    fn key_id(&self) -> String {
        self.slot.to_string()
    }

    fn key_wrap_algorithm(&self) -> &'static str {
        "AES128_CTR"
    }
}

fn increment_counter(counter: &mut [u8; 16]) {
    let mut n = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]);

    n += 1;

    counter[12..].copy_from_slice(&n.to_be_bytes());
}
