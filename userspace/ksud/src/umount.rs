use anyhow::{Context, Result};
use log::info;

use crate::ksucalls;

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

const UMOUNT_OPERATION_ADD: u32 = 0;
const UMOUNT_OPERATION_REMOVE: u32 = 1;
const UMOUNT_OPERATION_GET: u32 = 2;
const UMOUNT_OPERATION_CLEAR: u32 = 3;

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
    info!("Adding umount path: {}", path);

    let mut path_bytes = [0u8; 256];
    string_to_cstr(path, &mut path_bytes);
    let cmd = ksucalls::KsuUmountPathCmd {
        operation: UMOUNT_OPERATION_ADD,
        path: path_bytes,
        check_mnt: u8::from(check_mnt),
        flags,
        ..Default::default()
    };

    ksucalls::umount_ioctl(&cmd).context("Failed to add umount path")?;
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

    ksucalls::umount_ioctl(&cmd).context("Failed to remove umount path")?;
    Ok(())
}

pub fn get_umount_paths() -> Result<Vec<(String, bool, u32)>> {
    let mut entries = vec![UmountPathEntry::default(); 32];
    let cmd = ksucalls::KsuUmountPathCmd {
        operation: UMOUNT_OPERATION_GET,
        paths_ptr: entries.as_mut_ptr() as u64,
        count: 32,
        ..Default::default()
    };

    ksucalls::umount_ioctl(&cmd).context("Failed to get umount paths")?;

    let mut result = Vec::new();
    for i in 0..cmd.count as usize {
        if i >= entries.len() {
            break;
        }
        let path = cstr_to_string(&entries[i].path);
        if !path.is_empty() {
            result.push((path, entries[i].check_mnt != 0, entries[i].flags));
        }
    }

    Ok(result)
}

pub fn clear_umount_paths() -> Result<()> {
    info!("Clearing all umount paths");

    let cmd = ksucalls::KsuUmountPathCmd {
        operation: UMOUNT_OPERATION_CLEAR,
        ..Default::default()
    };

    ksucalls::umount_ioctl(&cmd).context("Failed to clear umount paths")?;
    Ok(())
}

pub fn apply_saved_config() -> Result<()> {
    info!("Umount paths will be loaded from kernel at boot");
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

    for (path, check_mnt, flags) in paths {
        println!(
            "{:<50} {:<12} {:<10}",
            path,
            if check_mnt { "true" } else { "false" },
            flags
        );
    }

    Ok(())
}
