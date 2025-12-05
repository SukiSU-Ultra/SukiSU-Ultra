use crate::{defs, ksucalls};
use anyhow::{Context, Result};
use log::{info, warn};
use std::fs;
use std::io::{BufReader, Read};
use std::path::Path;

// Magic number for umount config file
const UMOUNT_CONFIG_MAGIC: u32 = 0x4B53_554D; // KSUM

pub fn load_umount_config() -> Result<()> {
    let config_path = Path::new(defs::UMOUNT_CONFIG_PATH);

    if !config_path.exists() {
        info!("Umount config file does not exist, skipping");
        return Ok(());
    }

    let file = fs::File::open(config_path).context("Failed to open umount config file")?;
    let mut reader = BufReader::new(file);

    // Read and verify magic number
    let mut magic_buf = [0u8; 4];
    reader
        .read_exact(&mut magic_buf)
        .context("Failed to read magic number")?;
    let magic = u32::from_le_bytes(magic_buf);

    if magic != UMOUNT_CONFIG_MAGIC {
        warn!("Invalid magic number in umount config file, skipping");
        return Ok(());
    }

    // Wipe existing list first
    ksucalls::umount_list_wipe().context("Failed to wipe existing umount list")?;

    // Read entries
    let mut count = 0;
    loop {
        // Read path length
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let path_len = u32::from_le_bytes(len_buf) as usize;

        // Read path
        let mut path_buf = vec![0u8; path_len];
        reader
            .read_exact(&mut path_buf)
            .context("Failed to read path")?;
        let path = String::from_utf8(path_buf).context("Invalid UTF-8 in path")?;

        // Read flags
        let mut flags_buf = [0u8; 4];
        reader
            .read_exact(&mut flags_buf)
            .context("Failed to read flags")?;
        let flags = u32::from_le_bytes(flags_buf);

        // Add to kernel list
        ksucalls::umount_list_add(&path, flags)
            .with_context(|| format!("Failed to add umount path: {path}"))?;

        count += 1;
    }

    info!("Loaded {count} umount entries from config");
    Ok(())
}

pub fn apply_umount_config() -> Result<()> {
    load_umount_config()
}

pub fn clear_umount_config() -> Result<()> {
    let config_path = Path::new(defs::UMOUNT_CONFIG_PATH);

    // Wipe kernel list first
    ksucalls::umount_list_wipe().context("Failed to wipe kernel umount list")?;

    // Delete config file if it exists
    if config_path.exists() {
        fs::remove_file(config_path).context("Failed to remove umount config file")?;
        info!("Removed umount config file: {}", defs::UMOUNT_CONFIG_PATH);
    } else {
        info!("Umount config file does not exist, skipping removal");
    }

    Ok(())
}
