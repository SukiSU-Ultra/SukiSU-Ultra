use crate::{defs, ksucalls};
use anyhow::{Context, Result};
use log::{info, warn};
use std::fs;
use std::io::{BufReader, Read, Write};
use std::path::Path;

// Magic number for umount config file
const UMOUNT_CONFIG_MAGIC: u32 = 0x4B53_554D; // KSUM

// Magic number for umount exclusion config file
const UMOUNT_EXCLUSION_CONFIG_MAGIC: u32 = 0x4B53_5545; // KSUE
const UMOUNT_EXCLUSION_CONFIG_PATH: &str = concatcp!(defs::WORKING_DIR, ".umount_exclusion");

pub fn save_umount_config() -> Result<()> {
    let list_output =
        ksucalls::umount_list_list().context("Failed to get umount list from kernel")?;

    let config_path = Path::new(defs::UMOUNT_CONFIG_PATH);

    // Ensure directory exists
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).context("Failed to create config directory")?;
    }

    let mut file = fs::File::create(config_path).context("Failed to create umount config file")?;

    // Write magic number
    file.write_all(&UMOUNT_CONFIG_MAGIC.to_le_bytes())
        .context("Failed to write magic number")?;

    // Parse list output and write entries
    let lines: Vec<&str> = list_output.lines().collect();
    // Skip header lines (first 2 lines)
    for line in lines.iter().skip(2) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let path = parts[0];
            let flags = parts[1].parse::<u32>().unwrap_or(0);

            // Write path length (u32), path bytes, flags (u32)
            let path_bytes = path.as_bytes();
            file.write_all(&(path_bytes.len() as u32).to_le_bytes())?;
            file.write_all(path_bytes)?;
            file.write_all(&flags.to_le_bytes())?;
        }
    }

    info!("Saved umount config to {}", defs::UMOUNT_CONFIG_PATH);
    Ok(())
}

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

pub fn remove_umount_entry_from_config(target_path: &str) -> Result<()> {
    ksucalls::umount_list_del(target_path).context("Failed to delete umount entry from kernel")?;
    let config_path = Path::new(defs::UMOUNT_CONFIG_PATH);

    if !config_path.exists() {
        return Ok(());
    }

    let file = fs::File::open(config_path).context("Failed to open umount config file")?;
    let mut reader = BufReader::new(file);

    let mut magic_buf = [0u8; 4];
    reader
        .read_exact(&mut magic_buf)
        .context("Failed to read magic number")?;
    let magic = u32::from_le_bytes(magic_buf);
    if magic != UMOUNT_CONFIG_MAGIC {
        warn!("Invalid magic number in umount config file, skip removal");
        return Ok(());
    }

    let mut entries: Vec<(String, u32)> = Vec::new();
    loop {
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let path_len = u32::from_le_bytes(len_buf) as usize;

        let mut path_buf = vec![0u8; path_len];
        reader
            .read_exact(&mut path_buf)
            .context("Failed to read path")?;
        let path = String::from_utf8(path_buf).context("Invalid UTF-8 in path")?;

        let mut flags_buf = [0u8; 4];
        reader
            .read_exact(&mut flags_buf)
            .context("Failed to read flags")?;
        let flags = u32::from_le_bytes(flags_buf);

        entries.push((path, flags));
    }

    let original_len = entries.len();
    entries.retain(|(p, _)| p != target_path);

    if entries.len() == original_len {
        return Ok(());
    }

    if entries.is_empty() {
        fs::remove_file(config_path).context("Failed to remove empty umount config file")?;
        info!("Removed umount config file because list is now empty");
        return Ok(());
    }

    let mut file =
        fs::File::create(config_path).context("Failed to recreate umount config file")?;
    file.write_all(&UMOUNT_CONFIG_MAGIC.to_le_bytes())
        .context("Failed to write magic number")?;
    for (path, flags) in entries {
        let path_bytes = path.as_bytes();
        file.write_all(&(path_bytes.len() as u32).to_le_bytes())
            .context("Failed to write path length")?;
        file.write_all(path_bytes)
            .context("Failed to write path bytes")?;
        file.write_all(&flags.to_le_bytes())
            .context("Failed to write flags")?;
    }

    info!(
        "Removed umount entry '{}' from config {}",
        target_path,
        defs::UMOUNT_CONFIG_PATH
    );
    Ok(())
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

// ============ Umount Exclusion Config Functions ============

/// Save exclusion entries to config file
pub fn save_umount_exclusion_config() -> Result<()> {
    let list_output =
        ksucalls::umount_exclusion_list().context("Failed to get exclusion list from kernel")?;

    let config_path = Path::new(UMOUNT_EXCLUSION_CONFIG_PATH);

    // Ensure directory exists
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).context("Failed to create config directory")?;
    }

    let mut file =
        fs::File::create(config_path).context("Failed to create umount exclusion config file")?;

    // Write magic number
    file.write_all(&UMOUNT_EXCLUSION_CONFIG_MAGIC.to_le_bytes())
        .context("Failed to write magic number")?;

    // Parse list output and write entries (each line is a path prefix)
    for line in list_output.lines() {
        if line.is_empty() {
            continue;
        }

        let path_prefix = line.trim();
        let path_bytes = path_prefix.as_bytes();
        file.write_all(&(path_bytes.len() as u32).to_le_bytes())?;
        file.write_all(path_bytes)?;
    }

    info!(
        "Saved umount exclusion config to {}",
        UMOUNT_EXCLUSION_CONFIG_PATH
    );
    Ok(())
}

/// Load exclusion entries from config file and apply to kernel
pub fn load_umount_exclusion_config() -> Result<()> {
    let config_path = Path::new(UMOUNT_EXCLUSION_CONFIG_PATH);

    if !config_path.exists() {
        info!("Umount exclusion config file does not exist, skipping");
        return Ok(());
    }

    let file =
        fs::File::open(config_path).context("Failed to open umount exclusion config file")?;
    let mut reader = BufReader::new(file);

    // Read and verify magic number
    let mut magic_buf = [0u8; 4];
    reader
        .read_exact(&mut magic_buf)
        .context("Failed to read magic number")?;
    let magic = u32::from_le_bytes(magic_buf);

    if magic != UMOUNT_EXCLUSION_CONFIG_MAGIC {
        warn!("Invalid magic number in umount exclusion config file, skipping");
        return Ok(());
    }

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
        let path_prefix = String::from_utf8(path_buf).context("Invalid UTF-8 in path")?;

        // Add to kernel exclusion list
        ksucalls::umount_exclusion_add(&path_prefix)
            .with_context(|| format!("Failed to add exclusion: {}", path_prefix))?;

        count += 1;
    }

    info!("Loaded {count} umount exclusion entries from config");
    Ok(())
}

/// Remove a specific exclusion entry from config file
pub fn remove_umount_exclusion_from_config(path_prefix: &str) -> Result<()> {
    let config_path = Path::new(UMOUNT_EXCLUSION_CONFIG_PATH);

    if !config_path.exists() {
        return Ok(());
    }

    let file =
        fs::File::open(config_path).context("Failed to open umount exclusion config file")?;
    let mut reader = BufReader::new(file);

    let mut magic_buf = [0u8; 4];
    reader
        .read_exact(&mut magic_buf)
        .context("Failed to read magic number")?;
    let magic = u32::from_le_bytes(magic_buf);
    if magic != UMOUNT_EXCLUSION_CONFIG_MAGIC {
        warn!("Invalid magic number in umount exclusion config file, skip removal");
        return Ok(());
    }

    let mut entries: Vec<String> = Vec::new();
    loop {
        // Read path length
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let path_len = u32::from_le_bytes(len_buf) as usize;

        let mut path_buf = vec![0u8; path_len];
        reader
            .read_exact(&mut path_buf)
            .context("Failed to read path")?;
        let path = String::from_utf8(path_buf).context("Invalid UTF-8 in path")?;

        entries.push(path);
    }

    // Filter out the entry to remove
    let original_len = entries.len();
    entries.retain(|p| !p.starts_with(path_prefix) && p != path_prefix);

    if entries.len() == original_len {
        return Ok(());
    }

    // If entries is empty, delete the config file
    if entries.is_empty() {
        fs::remove_file(config_path)
            .context("Failed to remove empty umount exclusion config file")?;
        info!("Removed umount exclusion config file because list is now empty");
        return Ok(());
    }

    // Rewrite config file
    let mut file =
        fs::File::create(config_path).context("Failed to recreate umount exclusion config file")?;
    file.write_all(&UMOUNT_EXCLUSION_CONFIG_MAGIC.to_le_bytes())
        .context("Failed to write magic number")?;

    for entry in &entries {
        let path_bytes = entry.as_bytes();
        file.write_all(&(path_bytes.len() as u32).to_le_bytes())?;
        file.write_all(path_bytes)?;
    }

    info!(
        "Removed exclusion entry '{}' from config {}",
        path_prefix, UMOUNT_EXCLUSION_CONFIG_PATH
    );
    Ok(())
}

/// Clear all exclusion entries from config file
pub fn clear_umount_exclusion_config() -> Result<()> {
    let config_path = Path::new(UMOUNT_EXCLUSION_CONFIG_PATH);

    // Clear kernel exclusion list first
    ksucalls::umount_exclusion_clear().context("Failed to clear kernel umount exclusion list")?;

    // Delete config file if it exists
    if config_path.exists() {
        fs::remove_file(config_path).context("Failed to remove umount exclusion config file")?;
        info!(
            "Removed umount exclusion config file: {}",
            UMOUNT_EXCLUSION_CONFIG_PATH
        );
    } else {
        info!("Umount exclusion config file does not exist, skipping removal");
    }

    Ok(())
}
