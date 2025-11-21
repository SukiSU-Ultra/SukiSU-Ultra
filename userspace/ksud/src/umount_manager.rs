use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::ksucalls::ksuctl;

const MAGIC_NUMBER_HEADER: &[u8; 4] = b"KUMT";
const MAGIC_VERSION: u32 = 1;
const CONFIG_FILE: &str = "/data/adb/ksu/.umount";
#[allow(clippy::unreadable_literal)]
const KSU_IOCTL_UMOUNT_MANAGER: u32 = 0xc0004b6b; // _IOC(_IOC_READ|_IOC_WRITE, 'K', 107, 0)

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UmountEntry {
    pub path: String,
    pub flags: i32,
    pub is_default: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UmountConfig {
    pub entries: Vec<UmountEntry>,
}

pub struct UmountManager {
    config: UmountConfig,
    config_path: PathBuf,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UmountManagerCmd {
    pub operation: u32,
    pub path: [u8; 256],
    pub flags: i32,
    pub count: u32,
    pub entries_ptr: u64,
}

impl Default for UmountManagerCmd {
    fn default() -> Self {
        Self {
            operation: 0,
            path: [0; 256],
            flags: 0,
            count: 0,
            entries_ptr: 0,
        }
    }
}

impl UmountManager {
    pub fn new(config_path: Option<PathBuf>) -> Result<Self> {
        let path = config_path.unwrap_or_else(|| PathBuf::from(CONFIG_FILE));

        let config = if path.exists() {
            Self::load_config(&path)?
        } else {
            UmountConfig {
                entries: Vec::new(),
            }
        };

        Ok(Self {
            config,
            config_path: path,
        })
    }

    fn load_config(path: &Path) -> Result<UmountConfig> {
        let data = fs::read(path).context("Failed to read config file")?;

        if data.len() < 8 {
            return Err(anyhow!("Invalid config file: too small"));
        }

        let header = &data[0..4];
        if header != MAGIC_NUMBER_HEADER {
            return Err(anyhow!("Invalid config file: wrong magic number"));
        }

        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if version != MAGIC_VERSION {
            return Err(anyhow!("Unsupported config version: {version}"));
        }

        let json_data = &data[8..];
        let config: UmountConfig =
            serde_json::from_slice(json_data).context("Failed to parse config JSON")?;

        Ok(config)
    }

    pub fn save_config(&self) -> Result<()> {
        let dir = self.config_path.parent().unwrap();
        fs::create_dir_all(dir).context("Failed to create config directory")?;

        let mut data = Vec::new();
        data.extend_from_slice(MAGIC_NUMBER_HEADER);
        data.extend_from_slice(&MAGIC_VERSION.to_le_bytes());

        let json = serde_json::to_vec(&self.config).context("Failed to serialize config")?;
        data.extend_from_slice(&json);

        fs::write(&self.config_path, &data).context("Failed to write config file")?;

        Ok(())
    }

    pub fn add_entry(&mut self, path: &str, flags: i32) -> Result<()> {
        let exists = self.config.entries.iter().any(|e| e.path == path);
        if exists {
            return Err(anyhow!("Entry already exists: {path}"));
        }

        let entry = UmountEntry {
            path: path.to_string(),
            flags,
            is_default: false,
        };

        self.config.entries.push(entry);
        Ok(())
    }

    pub fn remove_entry(&mut self, path: &str) -> Result<()> {
        let before = self.config.entries.len();
        self.config.entries.retain(|e| e.path != path);

        if before == self.config.entries.len() {
            return Err(anyhow!("Entry not found: {path}"));
        }
        Ok(())
    }

    pub fn list_entries(&self) -> Vec<UmountEntry> {
        self.config.entries.clone()
    }

    pub fn clear_custom_entries(&mut self) {
        self.config.entries.retain(|e| e.is_default);
    }

    pub fn apply_to_kernel(&self) -> Result<()> {
        for entry in &self.config.entries {
            Self::kernel_add_entry(entry)?;
        }
        Ok(())
    }

    fn kernel_add_entry(entry: &UmountEntry) -> Result<()> {
        let mut cmd = UmountManagerCmd {
            operation: 0,
            flags: entry.flags,
            ..Default::default()
        };

        let path_bytes = entry.path.as_bytes();
        if path_bytes.len() >= cmd.path.len() {
            return Err(anyhow!("Path too long: {}", entry.path));
        }

        cmd.path[..path_bytes.len()].copy_from_slice(path_bytes);

        umount_manager_ioctl(&cmd).context(format!("Failed to add entry: {}", entry.path))?;

        Ok(())
    }
}

pub fn init_umount_manager() -> Result<UmountManager> {
    let manager = UmountManager::new(None)?;

    if !Path::new(CONFIG_FILE).exists() {
        manager.save_config()?;
    }

    Ok(manager)
}

pub fn add_umount_path(path: &str, flags: i32) -> Result<()> {
    let mut manager = init_umount_manager()?;
    manager.add_entry(path, flags)?;
    manager.save_config()?;
    println!("✓ Added umount path: {path}");
    Ok(())
}

pub fn remove_umount_path(path: &str) -> Result<()> {
    let mut manager = init_umount_manager()?;
    manager.remove_entry(path)?;
    manager.save_config()?;
    println!("✓ Removed umount path: {path}");
    Ok(())
}

pub fn list_umount_paths() -> Result<()> {
    let manager = init_umount_manager()?;
    let entries = manager.list_entries();

    if entries.is_empty() {
        println!("No umount paths configured");
        return Ok(());
    }

    println!("{:<30} {:<8} {:<10}", "Path", "Flags", "Default");
    println!("{}", "=".repeat(60));

    for entry in entries {
        println!(
            "{:<30} {:<8} {:<10}",
            entry.path,
            entry.flags,
            if entry.is_default { "Yes" } else { "No" }
        );
    }

    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn umount_manager_ioctl(cmd: &UmountManagerCmd) -> std::io::Result<()> {
    let mut ioctl_cmd = *cmd;
    ksuctl(KSU_IOCTL_UMOUNT_MANAGER, &raw mut ioctl_cmd)?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn umount_manager_ioctl(_cmd: &UmountManagerCmd) -> std::io::Result<()> {
    Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
}

pub fn clear_custom_paths() -> Result<()> {
    let mut manager = init_umount_manager()?;
    manager.clear_custom_entries();
    manager.save_config()?;
    println!("✓ Cleared all custom paths");
    Ok(())
}

pub fn save_umount_config() -> Result<()> {
    let manager = init_umount_manager()?;
    manager.save_config()?;
    println!("✓ Configuration saved to: {CONFIG_FILE}");
    Ok(())
}

pub fn load_and_apply_config() -> Result<()> {
    let manager = init_umount_manager()?;
    manager.apply_to_kernel()?;
    println!("✓ Configuration applied to kernel");
    Ok(())
}

pub fn apply_config_to_kernel() -> Result<()> {
    let manager = init_umount_manager()?;
    manager.apply_to_kernel()?;
    println!(
        "✓ Applied {} entries to kernel",
        manager.list_entries().len()
    );
    Ok(())
}
