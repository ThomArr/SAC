use anyhow::{anyhow, Result};

use crate::{
    keystore::{
        ethertrust::keystore_ethertrust_direct_psk::KeystoreEthertrust,
        ethertrust::keystore_ethertrust_tlsse_wifi::TlsseWifiKeystore,
        key_service::KeystoreService,
    },
    reader::config::load_config,
};

pub fn build_keystore() -> Result<Box<dyn KeystoreService + Send + Sync>> {
    let cfg = load_config()?;

    match cfg.keystore.connection_mode.as_str() {
        "direct_psk" => {
            let psk = cfg
                .keystore
                .keystore_psk
                .ok_or_else(|| anyhow!("missing keystore.psk"))?;

            Ok(Box::new(KeystoreEthertrust::new(
                cfg.keystore.host,
                cfg.keystore.port,
                cfg.keystore.sni,
                cfg.keystore.slot,
                cfg.keystore.keystore_identity,
                &psk,
            )?))
        }

        "se_wifi" => {
            let tlsse_path = cfg.tlsse.ok_or_else(|| anyhow!("missing tlsse path"))?;

            let se = cfg
                .keystore
                .secure_element
                .ok_or_else(|| anyhow!("missing keystore.secure_element"))?;

            Ok(Box::new(TlsseWifiKeystore::new(
                tlsse_path,
                cfg.keystore.host,
                cfg.keystore.port,
                cfg.keystore.sni,
                cfg.keystore.slot,
                cfg.keystore.keystore_identity,
                se.host,
                se.port,
                se.sni,
                se.se_identity,
                se.se_psk,
            )))
        }

        other => Err(anyhow!("unsupported keystore type: {}", other)),
    }
}
