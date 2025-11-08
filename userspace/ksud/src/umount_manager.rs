use crate::ksucalls::UmountManagerCmd;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const MAGIC_NUMBER_HEADER: &[u8; 4] = b"KUMT";
const MAGIC_VERSION: u32 = 1;
const CONFIG_FILE: &str = "/data/adb/ksu/.umount";

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UmountEntry {
    pub path: String,
    pub check_mnt: bool,
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
    defaults: Vec<UmountEntry>,
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

        Ok(UmountManager {
            config,
            config_path: path,
            defaults: Vec::new(),
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
            return Err(anyhow!("Unsupported config version: {}", version));
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

    pub fn add_entry(&mut self, path: &str, check_mnt: bool, flags: i32) -> Result<()> {
        let exists = self
            .defaults
            .iter()
            .chain(&self.config.entries)
            .any(|e| e.path == path);
        if exists {
            return Err(anyhow!("Entry already exists: {}", path));
        }

        let is_default = Self::get_default_paths().iter().any(|e| e.path == path);

        let entry = UmountEntry {
            path: path.to_string(),
            check_mnt,
            flags,
            is_default,
        };

        self.config.entries.push(entry);
        Ok(())
    }

    pub fn remove_entry(&mut self, path: &str) -> Result<()> {
        let entry = self.config.entries.iter().find(|e| e.path == path);

        if let Some(entry) = entry {
            if entry.is_default {
                return Err(anyhow!("Cannot remove default entry: {}", path));
            }
        } else {
            return Err(anyhow!("Entry not found: {}", path));
        }

        self.config.entries.retain(|e| e.path != path);
        Ok(())
    }

    pub fn list_entries(&self) -> Vec<UmountEntry> {
        let mut all = self.defaults.clone();
        all.extend(self.config.entries.iter().cloned());
        all
    }

    pub fn clear_custom_entries(&mut self) -> Result<()> {
        self.config.entries.retain(|e| e.is_default);
        Ok(())
    }

    pub fn get_default_paths() -> Vec<UmountEntry> {
        vec![
            UmountEntry {
                path: "/odm".to_string(),
                check_mnt: true,
                flags: 0,
                is_default: true,
            },
            UmountEntry {
                path: "/system".to_string(),
                check_mnt: true,
                flags: 0,
                is_default: true,
            },
            UmountEntry {
                path: "/vendor".to_string(),
                check_mnt: true,
                flags: 0,
                is_default: true,
            },
            UmountEntry {
                path: "/product".to_string(),
                check_mnt: true,
                flags: 0,
                is_default: true,
            },
            UmountEntry {
                path: "/system_ext".to_string(),
                check_mnt: true,
                flags: 0,
                is_default: true,
            },
            UmountEntry {
                path: "/data/adb/modules".to_string(),
                check_mnt: false,
                flags: -1, // MNT_DETACH
                is_default: true,
            },
            UmountEntry {
                path: "/debug_ramdisk".to_string(),
                check_mnt: false,
                flags: -1, // MNT_DETACH
                is_default: true,
            },
        ]
    }

    pub fn init_defaults(&mut self) -> Result<()> {
        self.defaults = Self::get_default_paths();
        Ok(())
    }

    pub fn apply_to_kernel(&self) -> Result<()> {
        for entry in &self.defaults {
            let _ = Self::kernel_add_entry(entry);
        }
        for entry in &self.config.entries {
            Self::kernel_add_entry(entry)?;
        }
        Ok(())
    }

    fn kernel_add_entry(entry: &UmountEntry) -> Result<()> {
        let mut cmd = UmountManagerCmd {
            operation: 0,
            check_mnt: entry.check_mnt as u8,
            flags: entry.flags,
            ..Default::default()
        };

        let path_bytes = entry.path.as_bytes();
        if path_bytes.len() >= cmd.path.len() {
            return Err(anyhow!("Path too long: {}", entry.path));
        }

        cmd.path[..path_bytes.len()].copy_from_slice(path_bytes);

        crate::ksucalls::umount_manager_ioctl(&cmd)
            .context(format!("Failed to add entry: {}", entry.path))?;

        Ok(())
    }
}

pub fn init_umount_manager() -> Result<UmountManager> {
    let mut manager = UmountManager::new(None)?;
    manager.init_defaults()?;

    if !Path::new(CONFIG_FILE).exists() {
        manager.save_config()?;
    }

    Ok(manager)
}

pub fn add_umount_path(path: &str, check_mnt: bool, flags: i32) -> Result<()> {
    let mut manager = init_umount_manager()?;
    manager.add_entry(path, check_mnt, flags)?;
    manager.save_config()?;
    println!("✓ Added umount path: {}", path);
    Ok(())
}

pub fn remove_umount_path(path: &str) -> Result<()> {
    let mut manager = init_umount_manager()?;
    manager.remove_entry(path)?;
    manager.save_config()?;
    println!("✓ Removed umount path: {}", path);
    Ok(())
}

pub fn list_umount_paths() -> Result<()> {
    let manager = init_umount_manager()?;
    let entries = manager.list_entries();

    if entries.is_empty() {
        println!("No umount paths configured");
        return Ok(());
    }

    println!(
        "{:<30} {:<12} {:<8} {:<10}",
        "Path", "CheckMnt", "Flags", "Default"
    );
    println!("{}", "=".repeat(60));

    for entry in entries {
        println!(
            "{:<30} {:<12} {:<8} {:<10}",
            entry.path,
            entry.check_mnt,
            entry.flags,
            if entry.is_default { "Yes" } else { "No" }
        );
    }

    Ok(())
}

pub fn clear_custom_paths() -> Result<()> {
    let mut manager = init_umount_manager()?;
    manager.clear_custom_entries()?;
    manager.save_config()?;
    println!("✓ Cleared all custom paths");
    Ok(())
}

pub fn save_umount_config() -> Result<()> {
    let manager = init_umount_manager()?;
    manager.save_config()?;
    println!("✓ Configuration saved to: {}", CONFIG_FILE);
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
