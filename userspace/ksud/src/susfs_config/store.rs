//! High-level `HashMap<String, String>` accessors.
//!
//! Reads/writes the binary file via [`binary`]; treats each public
//! function as a single atomic operation (load → mutate → save).

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;

use super::binary::{config_path, read_binary, write_binary};
use super::keys::{
    KEY_ADD_KSTAT_PATHS, KEY_AUTO_START_ENABLED, KEY_BUILD_TIME_VALUE, KEY_ENABLE_AVC_LOG_SPOOFING,
    KEY_ENABLE_CLEANUP_RESIDUE, KEY_ENABLE_HIDE_BL, KEY_ENABLE_LOG, KEY_EXECUTE_IN_POST_FS_DATA,
    KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS, KEY_KSTAT_CONFIGS, KEY_SUS_LOOP_PATHS, KEY_SUS_MAPS,
    KEY_SUS_PATHS, KEY_UNAME_VALUE,
};

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
    config.insert(KEY_UNAME_VALUE.to_string(), "default".to_string());
    config.insert(KEY_BUILD_TIME_VALUE.to_string(), "default".to_string());
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
