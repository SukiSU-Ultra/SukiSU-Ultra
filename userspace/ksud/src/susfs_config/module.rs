//! `ModuleConfig` + config-to-module glue.
//!
//! Separated from [`super::store`] because `ModuleConfig` is a strongly-
//! typed snapshot of the values needed by `susfs_module`, while
//! [`super::store`] operates on a generic `HashMap<String, String>`.

use anyhow::Result;

use super::keys::{
    KEY_ADD_KSTAT_PATHS, KEY_BUILD_TIME_VALUE, KEY_CMDLINE_OR_BOOTCONFIG_PATH,
    KEY_ENABLE_AVC_LOG_SPOOFING, KEY_ENABLE_CLEANUP_RESIDUE, KEY_ENABLE_HIDE_BL, KEY_ENABLE_LOG,
    KEY_EXECUTE_IN_POST_FS_DATA, KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS, KEY_KSTAT_CONFIGS,
    KEY_SUS_LOOP_PATHS, KEY_SUS_MAPS, KEY_SUS_PATHS, KEY_UNAME_VALUE,
};
use super::store::load_config;

pub(crate) fn split_paths(raw: &str) -> Vec<String> {
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
pub(crate) fn join_paths(paths: &[String]) -> String {
    paths.join(";")
}

pub(crate) fn split_kstat_configs(raw: &str) -> Vec<String> {
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
pub(crate) fn join_kstat_configs(configs: &[String]) -> String {
    configs.join(";;")
}

/// Load config from disk and convert to `ModuleConfig` for
/// `susfs_module::install_module`.
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
        cmdline_or_bootconfig_path: get(KEY_CMDLINE_OR_BOOTCONFIG_PATH),
    })
}

/// SuSFS module installation config — mirrors the fields stored in the
/// binary config file.
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
    pub cmdline_or_bootconfig_path: String,
}