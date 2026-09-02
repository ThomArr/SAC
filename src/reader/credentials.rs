use anyhow::{anyhow, Result};
use std::{collections::HashMap, fs};

pub fn read_key_value_file(path: &str) -> Result<HashMap<String, String>> {
    let content = fs::read_to_string(path)?;
    let mut values = HashMap::new();

    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(anyhow!("Invalid credentials line: {}", line));
        };

        values.insert(key.trim().to_string(), value.trim().to_string());
    }

    Ok(values)
}

pub fn read_azure_connection_string(path: &str) -> Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_string())
}
