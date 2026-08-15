//! Binary on-disk format.
//!
//! ```text
//! magic   : u32 LE   // 0x53555346 ("SUSF")
//! version : u32 LE   // currently 1
//! count   : u32 LE   // number of (key, value) pairs
//! for each record:
//!     key_len   : u32 LE
//!     key_data  : [u8; key_len]
//!     value_len : u32 LE
//!     value_data: [u8; value_len]
//! ```

use anyhow::{Context, Result, bail};
use const_format::concatcp;
use std::collections::HashMap;
use std::path::Path;

const SUSFS_CONFIG_MAGIC: u32 = 0x5355_5346; // "SUSF"
const SUSFS_CONFIG_VERSION: u32 = 1;
pub const SUSFS_CONFIG_FILE: &str = concatcp!(crate::defs::WORKING_DIR, "susfs_config");

pub fn config_path() -> &'static Path {
    Path::new(SUSFS_CONFIG_FILE)
}

pub fn write_binary(config: &HashMap<String, String>) -> Vec<u8> {
    let mut buf = Vec::new();

    // Header: magic (4) + version (4) + count (4)
    buf.extend_from_slice(&SUSFS_CONFIG_MAGIC.to_le_bytes());
    buf.extend_from_slice(&SUSFS_CONFIG_VERSION.to_le_bytes());
    buf.extend_from_slice(&(config.len() as u32).to_le_bytes());

    for (key, value) in config {
        // key length + data
        buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
        buf.extend_from_slice(key.as_bytes());

        // value length + data
        buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
        buf.extend_from_slice(value.as_bytes());
    }

    buf
}

pub fn read_binary(data: &[u8]) -> Result<HashMap<String, String>> {
    let mut r = data;
    let mut config = HashMap::new();

    // Magic
    if r.len() < 4 {
        bail!("Truncated header");
    }
    let magic = u32::from_le_bytes([r[0], r[1], r[2], r[3]]);
    r = &r[4..];
    if magic != SUSFS_CONFIG_MAGIC {
        bail!("Invalid magic: expected 0x{SUSFS_CONFIG_MAGIC:08x}, got 0x{magic:08x}");
    }

    // Version
    if r.len() < 4 {
        bail!("Truncated version");
    }
    let version = u32::from_le_bytes([r[0], r[1], r[2], r[3]]);
    r = &r[4..];
    if version != SUSFS_CONFIG_VERSION {
        bail!("Unsupported version: expected {SUSFS_CONFIG_VERSION}, got {version}");
    }

    // Count
    if r.len() < 4 {
        bail!("Truncated count");
    }
    let count = u32::from_le_bytes([r[0], r[1], r[2], r[3]]);
    r = &r[4..];

    for _ in 0..count {
        // key
        if r.len() < 4 {
            bail!("Truncated key length");
        }
        let key_len = u32::from_le_bytes([r[0], r[1], r[2], r[3]]) as usize;
        r = &r[4..];
        if r.len() < key_len {
            bail!("Truncated key data");
        }
        let key = String::from_utf8(r[..key_len].to_vec()).context("Invalid UTF-8 in key")?;
        r = &r[key_len..];

        // value
        if r.len() < 4 {
            bail!("Truncated value length");
        }
        let value_len = u32::from_le_bytes([r[0], r[1], r[2], r[3]]) as usize;
        r = &r[4..];
        if r.len() < value_len {
            bail!("Truncated value data");
        }
        let value = String::from_utf8(r[..value_len].to_vec()).context("Invalid UTF-8 in value")?;
        r = &r[value_len..];

        config.insert(key, value);
    }

    Ok(config)
}
