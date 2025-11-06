use anyhow::{Context, Ok, Result};
use log::{info, warn};
use std::fs;
use std::path::Path;

use crate::defs;
use crate::ksucalls;

use const_format::concatcp;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UmountPathEntry {
    pub path: [u8; 256],
    pub check_mnt: u8,
    pub flags: u32,
}

impl Default for UmountPathEntry {
    fn default() -> Self {
        UmountPathEntry {
            path: [0; 256],
            check_mnt: 0,
            flags: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UmountPathConfig {
    pub path: String,
    pub check_mnt: bool,
    pub flags: u32,
}

const UMOUNT_CONFIG_FILE: &str = concatcp!(defs::WORKING_DIR, "umount_paths.json");
const UMOUNT_OPERATION_ADD: u32 = 0;
const UMOUNT_OPERATION_REMOVE: u32 = 1;
const UMOUNT_OPERATION_GET: u32 = 2;
const UMOUNT_OPERATION_CLEAR: u32 = 3;

fn ensure_umount_dir() -> Result<()> {
    let path = Path::new(defs::WORKING_DIR);
    if !path.exists() {
        fs::create_dir_all(path).context("Failed to create umount config directory")?;
    }
    Ok(())
}

fn string_to_cstr(s: &str, buf: &mut [u8; 256]) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(255);
    buf[..len].copy_from_slice(&bytes[..len]);
    buf[len] = 0;
}

fn cstr_to_string(buf: &[u8; 256]) -> String {
    let null_pos = buf.iter().position(|&b| b == 0).unwrap_or(256);
    String::from_utf8_lossy(&buf[..null_pos]).to_string()
}

pub fn add_umount_path(path: &str, check_mnt: bool, flags: u32) -> Result<()> {
    info!(
        "Adding umount path: {} (check_mnt: {}, flags: {})",
        path, check_mnt, flags
    );

    let mut path_bytes = [0u8; 256];
    string_to_cstr(path, &mut path_bytes);
    let cmd = ksucalls::KsuUmountPathCmd {
        operation: UMOUNT_OPERATION_ADD,
        path: path_bytes,
        check_mnt: u8::from(check_mnt),
        flags,
        ..Default::default()
    };

    ksucalls::umount_ioctl(&cmd).context("Failed to add umount path via ioctl")?;

    info!("Successfully added umount path: {}", path);
    Ok(())
}

pub fn remove_umount_path(path: &str) -> Result<()> {
    info!("Removing umount path: {}", path);

    let mut path_bytes = [0u8; 256];
    string_to_cstr(path, &mut path_bytes);
    let cmd = ksucalls::KsuUmountPathCmd {
        operation: UMOUNT_OPERATION_REMOVE,
        path: path_bytes,
        ..Default::default()
    };

    ksucalls::umount_ioctl(&cmd).context("Failed to remove umount path via ioctl")?;

    info!("Successfully removed umount path: {}", path);
    Ok(())
}

pub fn get_umount_paths() -> Result<Vec<UmountPathConfig>> {
    info!("Fetching umount paths from kernel");

    let mut entries = vec![UmountPathEntry::default(); 32];
    let cmd = ksucalls::KsuUmountPathCmd {
        operation: UMOUNT_OPERATION_GET,
        paths_ptr: entries.as_mut_ptr() as u64,
        count: 32,
        ..Default::default()
    };

    ksucalls::umount_ioctl(&cmd).context("Failed to get umount paths via ioctl")?;

    let mut result = Vec::new();
    for i in 0..cmd.count as usize {
        if i >= entries.len() {
            break;
        }
        let entry = &entries[i];
        let path = cstr_to_string(&entry.path);
        if !path.is_empty() {
            result.push(UmountPathConfig {
                path,
                check_mnt: entry.check_mnt != 0,
                flags: entry.flags,
            });
        }
    }

    info!("Retrieved {} umount paths", result.len());
    Ok(result)
}

pub fn clear_umount_paths() -> Result<()> {
    info!("Clearing all umount paths");

    let cmd = ksucalls::KsuUmountPathCmd {
        operation: UMOUNT_OPERATION_CLEAR,
        ..Default::default()
    };

    ksucalls::umount_ioctl(&cmd).context("Failed to clear umount paths via ioctl")?;

    info!("Successfully cleared all umount paths");
    Ok(())
}

pub fn save_umount_config(paths: &[UmountPathConfig]) -> Result<()> {
    ensure_umount_dir()?;

    let json_data: Vec<serde_json::Value> = paths
        .iter()
        .map(|p| {
            serde_json::json!({
                "path": p.path,
                "check_mnt": p.check_mnt,
                "flags": p.flags
            })
        })
        .collect();

    let json = serde_json::to_string_pretty(&json_data)
        .context("Failed to serialize umount paths to JSON")?;

    fs::write(UMOUNT_CONFIG_FILE, json).context("Failed to write umount config file")?;

    info!("Umount paths saved to {}", UMOUNT_CONFIG_FILE);
    Ok(())
}

pub fn load_umount_config() -> Result<Vec<UmountPathConfig>> {
    if !Path::new(UMOUNT_CONFIG_FILE).exists() {
        warn!("Umount config file not found: {}", UMOUNT_CONFIG_FILE);
        return Ok(Vec::new());
    }

    let json =
        fs::read_to_string(UMOUNT_CONFIG_FILE).context("Failed to read umount config file")?;

    let json_data: Vec<serde_json::Value> =
        serde_json::from_str(&json).context("Failed to parse umount config file")?;

    let mut paths = Vec::new();
    for item in json_data {
        if let (Some(path), Some(check_mnt), Some(flags)) = (
            item.get("path").and_then(|v| v.as_str()),
            item.get("check_mnt").and_then(|v| v.as_bool()),
            item.get("flags").and_then(|v| v.as_u64()),
        ) {
            paths.push(UmountPathConfig {
                path: path.to_string(),
                check_mnt,
                flags: flags as u32,
            });
        }
    }

    info!("Loaded {} umount paths from config", paths.len());
    Ok(paths)
}

pub fn apply_saved_config() -> Result<()> {
    info!("Applying saved umount configuration");

    let config = load_umount_config()?;

    if config.is_empty() {
        info!("No umount paths to apply");
        return Ok(());
    }

    for entry in config {
        match add_umount_path(&entry.path, entry.check_mnt, entry.flags) {
            std::result::Result::Ok(_) => info!("Applied umount path: {}", entry.path),
            Err(e) => warn!("Failed to apply umount path {}: {}", entry.path, e),
        }
    }

    Ok(())
}

pub fn list_umount_paths() -> Result<()> {
    let paths = get_umount_paths()?;

    if paths.is_empty() {
        println!("No umount paths configured");
        return Ok(());
    }

    println!("Current umount paths:");
    println!("{:<50} {:<12} {:<10}", "Path", "Check_Mnt", "Flags");
    println!("{}", "-".repeat(72));

    for entry in paths.iter() {
        println!(
            "{:<50} {:<12} {:<10}",
            entry.path,
            if entry.check_mnt { "true" } else { "false" },
            entry.flags
        );
    }

    Ok(())
}
