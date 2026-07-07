//! SuSFS persistent configuration store.
//!
//! Stores all SuSFS manager settings in a binary file at
//! `/data/adb/ksu/susfs_config` using a magic-header + length-prefixed
//! key/value format.

use anyhow::{Context, Result, bail};
use const_format::concatcp;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

// ── binary format constants ────────────────────────────────────────────────────

const SUSFS_CONFIG_MAGIC: u32 = 0x5355_5346; // "SUSF"
const SUSFS_CONFIG_VERSION: u32 = 1;
const SUSFS_CONFIG_FILE: &str = concatcp!(crate::defs::WORKING_DIR, "susfs_config");

// ── config keys (mirror Kotlin KEY_* constants without the prefix) ─────────────

pub const KEY_UNAME_VALUE: &str = "uname_value";
pub const KEY_BUILD_TIME_VALUE: &str = "build_time_value";
pub const KEY_AUTO_START_ENABLED: &str = "auto_start_enabled";
pub const KEY_SUS_PATHS: &str = "sus_paths";
pub const KEY_SUS_LOOP_PATHS: &str = "sus_loop_paths";
pub const KEY_SUS_MAPS: &str = "sus_maps";
pub const KEY_ENABLE_LOG: &str = "enable_log";
pub const KEY_EXECUTE_IN_POST_FS_DATA: &str = "execute_in_post_fs_data";
pub const KEY_KSTAT_CONFIGS: &str = "kstat_configs";
pub const KEY_ADD_KSTAT_PATHS: &str = "add_kstat_paths";
pub const KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS: &str = "hide_sus_mounts_for_all_procs";
pub const KEY_ENABLE_CLEANUP_RESIDUE: &str = "enable_cleanup_residue";
pub const KEY_ENABLE_HIDE_BL: &str = "enable_hide_bl";
pub const KEY_ENABLE_AVC_LOG_SPOOFING: &str = "enable_avc_log_spoofing";

// defaults
pub const DEFAULT_UNAME: &str = "default";
pub const DEFAULT_BUILD_TIME: &str = "default";

/// All known config keys in load order
#[allow(dead_code)]
pub const ALL_KEYS: &[&str] = &[
    KEY_UNAME_VALUE,
    KEY_BUILD_TIME_VALUE,
    KEY_AUTO_START_ENABLED,
    KEY_SUS_PATHS,
    KEY_SUS_LOOP_PATHS,
    KEY_SUS_MAPS,
    KEY_ENABLE_LOG,
    KEY_EXECUTE_IN_POST_FS_DATA,
    KEY_KSTAT_CONFIGS,
    KEY_ADD_KSTAT_PATHS,
    KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS,
    KEY_ENABLE_CLEANUP_RESIDUE,
    KEY_ENABLE_HIDE_BL,
    KEY_ENABLE_AVC_LOG_SPOOFING,
];

// ── path helpers ─────────────────────────────────────────────────────────────

fn config_path() -> &'static Path {
    Path::new(SUSFS_CONFIG_FILE)
}

// ── binary read/write ────────────────────────────────────────────────────────

fn write_binary(config: &HashMap<String, String>) -> Vec<u8> {
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

fn read_binary(data: &[u8]) -> Result<HashMap<String, String>> {
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

// ── public API ────────────────────────────────────────────────────────────────

/// Load the full config from disk. Returns an empty map if the file doesn't exist.
pub fn load_config() -> Result<HashMap<String, String>> {
    let path = config_path();
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let data = std::fs::read(path).context("Failed to read config file")?;
    read_binary(&data)
}

/// Save the full config to disk.
pub fn save_config(config: &HashMap<String, String>) -> Result<()> {
    let path = config_path();

    // Ensure parent dir exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create config dir")?;
    }

    let data = write_binary(config);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .context("Failed to open config file for writing")?;
    file.write_all(&data)
        .context("Failed to write config file")?;
    file.sync_all()?;
    Ok(())
}

/// Get a single config value. Returns the default if the key is absent.
pub fn get(key: &str) -> Result<String> {
    let config = load_config()?;
    Ok(config.get(key).cloned().unwrap_or_default())
}

/// Set a single config value.
pub fn set(key: &str, value: &str) -> Result<()> {
    let mut config = load_config()?;
    config.insert(key.to_string(), value.to_string());
    save_config(&config)
}

/// Remove a single config value.
pub fn remove(key: &str) -> Result<()> {
    let mut config = load_config()?;
    config.remove(key);
    save_config(&config)
}

/// Clear all config values.
pub fn clear() -> Result<()> {
    save_config(&HashMap::new())
}

/// Reset all config keys to their defaults.
pub fn reset_to_defaults() -> Result<()> {
    let mut config = HashMap::new();
    config.insert(KEY_UNAME_VALUE.to_string(), DEFAULT_UNAME.to_string());
    config.insert(
        KEY_BUILD_TIME_VALUE.to_string(),
        DEFAULT_BUILD_TIME.to_string(),
    );
    config.insert(KEY_AUTO_START_ENABLED.to_string(), "false".to_string());
    config.insert(KEY_SUS_PATHS.to_string(), String::new());
    config.insert(KEY_SUS_LOOP_PATHS.to_string(), String::new());
    config.insert(KEY_SUS_MAPS.to_string(), String::new());
    config.insert(KEY_ENABLE_LOG.to_string(), "false".to_string());
    config.insert(KEY_EXECUTE_IN_POST_FS_DATA.to_string(), "false".to_string());
    config.insert(KEY_KSTAT_CONFIGS.to_string(), String::new());
    config.insert(KEY_ADD_KSTAT_PATHS.to_string(), String::new());
    config.insert(
        KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS.to_string(),
        "true".to_string(),
    );
    config.insert(KEY_ENABLE_CLEANUP_RESIDUE.to_string(), "false".to_string());
    config.insert(KEY_ENABLE_HIDE_BL.to_string(), "true".to_string());
    config.insert(KEY_ENABLE_AVC_LOG_SPOOFING.to_string(), "false".to_string());
    save_config(&config)
}

/// Export all config as JSON for backup / UI consumption.
pub fn export_json() -> Result<String> {
    let config = load_config()?;
    let mut lines: Vec<String> = config.iter().map(|(k, v)| format!("{k}={v}")).collect();
    lines.sort();
    Ok(lines.join("\n"))
}

// ── config-to-module helper ──────────────────────────────────────────────────

fn split_paths(raw: &str) -> Vec<String> {
    if raw.is_empty() {
        Vec::new()
    } else {
        raw.split(';')
            .map(String::from)
            .filter(|s| !s.is_empty())
            .collect()
    }
}

#[allow(dead_code)]
fn join_paths(paths: &[String]) -> String {
    paths.join(";")
}

fn split_kstat_configs(raw: &str) -> Vec<String> {
    if raw.is_empty() {
        Vec::new()
    } else {
        raw.split(";;")
            .map(String::from)
            .filter(|s| !s.is_empty())
            .collect()
    }
}

#[allow(dead_code)]
fn join_kstat_configs(configs: &[String]) -> String {
    configs.join(";;")
}

/// Load config from disk and convert to `ModuleConfig` for `susfs_module::install_module`.
pub fn load_module_config() -> Result<ModuleConfig> {
    let config = load_config()?;
    let get = |key: &str| config.get(key).cloned().unwrap_or_default();

    let sus_paths_raw = get(KEY_SUS_PATHS);
    let sus_loop_paths_raw = get(KEY_SUS_LOOP_PATHS);
    let sus_maps_raw = get(KEY_SUS_MAPS);
    let kstat_configs_raw = get(KEY_KSTAT_CONFIGS);
    let add_kstat_paths_raw = get(KEY_ADD_KSTAT_PATHS);

    Ok(ModuleConfig {
        uname_value: get(KEY_UNAME_VALUE),
        build_time_value: get(KEY_BUILD_TIME_VALUE),
        execute_in_post_fs_data: get(KEY_EXECUTE_IN_POST_FS_DATA) == "true",
        sus_paths: split_paths(&sus_paths_raw),
        sus_loop_paths: split_paths(&sus_loop_paths_raw),
        sus_maps: split_paths(&sus_maps_raw),
        enable_log: get(KEY_ENABLE_LOG) == "true",
        kstat_configs: split_kstat_configs(&kstat_configs_raw),
        add_kstat_paths: split_paths(&add_kstat_paths_raw),
        hide_sus_mounts_for_all_procs: get(KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS) == "true",
        enable_hide_bl: get(KEY_ENABLE_HIDE_BL) == "true",
        enable_cleanup_residue: get(KEY_ENABLE_CLEANUP_RESIDUE) == "true",
        enable_avc_log_spoofing: get(KEY_ENABLE_AVC_LOG_SPOOFING) == "true",
    })
}

/// SuSFS module installation config — mirrors the fields stored in the binary config file.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct ModuleConfig {
    pub uname_value: String,
    pub build_time_value: String,
    pub execute_in_post_fs_data: bool,
    pub sus_paths: Vec<String>,
    pub sus_loop_paths: Vec<String>,
    pub sus_maps: Vec<String>,
    pub enable_log: bool,
    pub kstat_configs: Vec<String>,
    pub add_kstat_paths: Vec<String>,
    pub hide_sus_mounts_for_all_procs: bool,
    pub enable_hide_bl: bool,
    pub enable_cleanup_residue: bool,
    pub enable_avc_log_spoofing: bool,
}
