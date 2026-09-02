use anyhow::{anyhow, Result};
use std::process::Command;

use crate::keystore::key_service::KeystoreService;

const CEK_LEN: usize = 32;
const WRAPPED_CEK_LEN: usize = 12 + CEK_LEN;

pub struct TlsseWifiKeystore {
    tlsse_path: String,

    hsm_host: String,
    hsm_port: u16,
    hsm_sni: String,
    slot: u8,
    keystore_identity: String,

    se_host: String,
    se_port: u16,
    se_sni: String,
    se_identity: String,
    se_psk: String,
}

impl TlsseWifiKeystore {
    pub fn new(
        tlsse_path: impl Into<String>,
        hsm_host: impl Into<String>,
        hsm_port: u16,
        hsm_sni: impl Into<String>,
        slot: u8,
        keystore_identity: impl Into<String>,
        se_host: impl Into<String>,
        se_port: u16,
        se_sni: impl Into<String>,
        se_identity: impl Into<String>,
        se_psk: impl Into<String>,
    ) -> Self {
        Self {
            tlsse_path: tlsse_path.into(),
            hsm_host: hsm_host.into(),
            hsm_port,
            hsm_sni: hsm_sni.into(),
            slot,
            keystore_identity: keystore_identity.into(),
            se_host: se_host.into(),
            se_port,
            se_sni: se_sni.into(),
            se_identity: se_identity.into(),
            se_psk: se_psk.into(),
        }
    }

    fn check_slot(&self) -> Result<()> {
        if self.slot > 3 {
            return Err(anyhow!("slot must be in [0, 3]"));
        }

        Ok(())
    }

    fn run_tlsse_aes_many(&self, blocks: &[[u8; 16]]) -> Result<Vec<[u8; 16]>> {
        self.check_slot()?;

        let mut command = Command::new(&self.tlsse_path);

        command
            .arg("-c")
            .arg("-h")
            .arg(&self.hsm_host)
            .arg("-p")
            .arg(self.hsm_port.to_string())
            .arg("-S")
            .arg(&self.hsm_sni)
            .arg("-H")
            .arg(format!("identity{}", self.keystore_identity))
            .arg("-H")
            .arg(format!("rh{}", self.se_host))
            .arg("-H")
            .arg(format!("rp{}", self.se_port))
            .arg("-H")
            .arg(format!("rS{}", self.se_sni))
            .arg("-H")
            .arg(format!("ridentity{}", self.se_identity))
            .arg("-H")
            .arg(format!("rpsk{}", self.se_psk))
            .arg("-H")
            .arg("rimask");

        for block in blocks {
            let command_payload = format!("A4{:x}{}", self.slot, hex::encode_upper(block));

            command.arg("-H").arg(format!("*{}", command_payload));
        }

        let output = command.output()?;

        if !output.status.success() {
            return Err(anyhow!(
                "tlsse failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        extract_hex_blocks(&stdout, blocks.len())
    }

    fn wrap_ctr_batched(&self, key: &[u8]) -> Result<Vec<u8>> {
        use rand::RngCore;

        let mut counter = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut counter[..12]);
        counter[12..].copy_from_slice(&0u32.to_be_bytes());

        let nonce = counter[..12].to_vec();

        let mut counters = Vec::new();

        for _ in key.chunks(16) {
            counters.push(counter);
            increment_counter(&mut counter);
        }

        let keystreams = self.run_tlsse_aes_many(&counters)?;

        let mut output = Vec::with_capacity(12 + key.len());
        output.extend_from_slice(&nonce);

        for (chunk, keystream) in key.chunks(16).zip(keystreams.iter()) {
            for i in 0..chunk.len() {
                output.push(chunk[i] ^ keystream[i]);
            }
        }

        Ok(output)
    }

    fn unwrap_ctr_batched(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
        if wrapped.len() < 12 {
            return Err(anyhow!("wrapped key too short"));
        }

        let nonce = &wrapped[..12];
        let ciphertext = &wrapped[12..];

        let mut counter = [0u8; 16];
        counter[..12].copy_from_slice(nonce);
        counter[12..].copy_from_slice(&0u32.to_be_bytes());

        let mut counters = Vec::new();

        for _ in ciphertext.chunks(16) {
            counters.push(counter);
            increment_counter(&mut counter);
        }

        let keystreams = self.run_tlsse_aes_many(&counters)?;

        let mut output = Vec::with_capacity(ciphertext.len());

        for (chunk, keystream) in ciphertext.chunks(16).zip(keystreams.iter()) {
            for i in 0..chunk.len() {
                output.push(chunk[i] ^ keystream[i]);
            }
        }

        Ok(output)
    }
}

#[async_trait::async_trait]
impl KeystoreService for TlsseWifiKeystore {
    async fn wrap_cek(&self, cek: &[u8]) -> Result<Vec<u8>> {
        if cek.len() != CEK_LEN {
            return Err(anyhow!("CEK must be 32 bytes for AES-256-GCM"));
        }

        self.wrap_ctr_batched(cek)
    }

    async fn unwrap_cek(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
        if wrapped.len() != WRAPPED_CEK_LEN {
            return Err(anyhow!("wrapped CEK must be 44 bytes"));
        }

        self.unwrap_ctr_batched(wrapped)
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

fn extract_hex_blocks(stdout: &str, expected: usize) -> Result<Vec<[u8; 16]>> {
    let mut blocks = Vec::new();

    for token in stdout.split_whitespace() {
        if token.len() == 32 && token.chars().all(|c| c.is_ascii_hexdigit()) {
            let decoded = hex::decode(token)?;

            let block: [u8; 16] = decoded
                .try_into()
                .map_err(|_| anyhow!("Invalid AES block length returned by tlsse"))?;

            blocks.push(block);
        }
    }

    if blocks.len() < expected {
        return Err(anyhow!(
            "expected {} AES blocks from tlsse, got {}",
            expected,
            blocks.len()
        ));
    }

    Ok(blocks[blocks.len() - expected..].to_vec())
}
