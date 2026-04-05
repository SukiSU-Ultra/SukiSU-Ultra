use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

const SUSFS_CONFIG_FILE: &str = "/data/adb/ksu/susfs_config.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SusfsConfig {
    #[serde(default)]
    pub uname_value: String,

    #[serde(default)]
    pub build_time_value: String,

    #[serde(default)]
    pub execute_in_post_fs_data: bool,

    #[serde(default)]
    pub auto_start_enabled: bool,

    #[serde(default)]
    pub sus_paths: HashSet<String>,

    #[serde(default)]
    pub sus_loop_paths: HashSet<String>,

    #[serde(default)]
    pub sus_maps: HashSet<String>,

    #[serde(default)]
    pub enable_log: bool,

    #[serde(default)]
    pub kstat_configs: HashSet<String>,

    #[serde(default)]
    pub add_kstat_paths: HashSet<String>,

    #[serde(default)]
    pub hide_sus_mounts_for_all_procs: bool,

    #[serde(default)]
    pub enable_hide_bl: bool,

    #[serde(default)]
    pub enable_cleanup_residue: bool,

    #[serde(default)]
    pub enable_avc_log_spoofing: bool,
}

impl SusfsConfig {
    pub fn new() -> Self {
        Self {
            uname_value: "default".to_string(),
            build_time_value: "default".to_string(),
            execute_in_post_fs_data: false,
            auto_start_enabled: false,
            sus_paths: HashSet::new(),
            sus_loop_paths: HashSet::new(),
            sus_maps: HashSet::new(),
            enable_log: false,
            kstat_configs: HashSet::new(),
            add_kstat_paths: HashSet::new(),
            hide_sus_mounts_for_all_procs: true,
            enable_hide_bl: true,
            enable_cleanup_residue: false,
            enable_avc_log_spoofing: false,
        }
    }

    pub fn has_auto_start_config(&self) -> bool {
        self.uname_value != "default"
            || self.build_time_value != "default"
            || !self.sus_paths.is_empty()
            || !self.sus_loop_paths.is_empty()
            || !self.sus_maps.is_empty()
            || !self.kstat_configs.is_empty()
            || !self.add_kstat_paths.is_empty()
    }

    pub fn add_sus_path(&mut self, path: String) {
        self.sus_paths.insert(path);
    }

    pub fn remove_sus_path(&mut self, path: &str) {
        self.sus_paths.remove(path);
    }

    pub fn add_sus_loop_path(&mut self, path: String) {
        self.sus_loop_paths.insert(path);
    }

    pub fn remove_sus_loop_path(&mut self, path: &str) {
        self.sus_loop_paths.remove(path);
    }

    pub fn add_sus_map(&mut self, map: String) {
        self.sus_maps.insert(map);
    }

    pub fn remove_sus_map(&mut self, map: &str) {
        self.sus_maps.remove(map);
    }

    pub fn add_kstat_config(&mut self, config: String) {
        self.kstat_configs.insert(config);
    }

    pub fn remove_kstat_config(&mut self, config: &str) {
        self.kstat_configs.remove(config);
    }

    pub fn add_kstat_path(&mut self, path: String) {
        self.add_kstat_paths.insert(path);
    }

    pub fn remove_kstat_path(&mut self, path: &str) {
        self.add_kstat_paths.remove(path);
    }

    pub fn reset_to_default(&mut self) {
        self.uname_value = "default".to_string();
        self.build_time_value = "default".to_string();
    }
}

pub fn load_config() -> Result<SusfsConfig> {
    let config_path = PathBuf::from(SUSFS_CONFIG_FILE);
    if !config_path.exists() {
        return Ok(SusfsConfig::new());
    }

    let content = fs::read_to_string(&config_path).context("Failed to read config")?;

    serde_json::from_str(&content).context("Failed to parse config")
}

pub fn save_config(config: &SusfsConfig) -> Result<()> {
    let content = serde_json::to_string_pretty(config).context("Failed to serialize config")?;

    fs::write(SUSFS_CONFIG_FILE, content).context("Failed to write config")?;

    Ok(())
}

pub fn reset_config() -> Result<()> {
    save_config(&SusfsConfig::new())
}
