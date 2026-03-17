#![allow(clippy::unreadable_literal)]
#![allow(clippy::too_many_lines)]

use anyhow::{bail, Context, Ok, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::Write,
    path::PathBuf,
    process::Command,
};

use crate::defs;
use crate::ksucalls;

const SUSFS_CONFIG_DIR: &str = "/data/adb/susfs";
const SUSFS_CONFIG_FILE: &str = "/data/adb/susfs/config.json";
const SUSFS_BACKUP_DIR: &str = "/data/adb/susfs/backups";
const MODULE_ID: &str = "susfs_manager";
const MODULE_PATH: &str = "/data/adb/modules/susfs_manager";

const DEFAULT_UNAME: &str = "default";
const DEFAULT_BUILD_TIME: &str = "default";
const LOG_DIR: &str = "/data/adb/ksu/log";


#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SusfsConfig {
    #[serde(rename = "unameValue")]
    pub uname_value: String,
    #[serde(rename = "buildTimeValue")]
    pub build_time_value: String,
    #[serde(rename = "autoStartEnabled")]
    pub auto_start_enabled: bool,
    #[serde(rename = "susPaths")]
    pub sus_paths: Vec<String>,
    #[serde(rename = "susLoopPaths")]
    pub sus_loop_paths: Vec<String>,
    #[serde(rename = "susMaps")]
    pub sus_maps: Vec<String>,
    #[serde(rename = "enableLog")]
    pub enable_log: bool,
    #[serde(rename = "executeInPostFsData")]
    pub execute_in_post_fs_data: bool,
    #[serde(rename = "kstatConfigs")]
    pub kstat_configs: Vec<String>,
    #[serde(rename = "addKstatPaths")]
    pub add_kstat_paths: Vec<String>,
    #[serde(rename = "hideSusMountsForAllProcs")]
    pub hide_sus_mounts_for_all_procs: bool,
    #[serde(rename = "enableHideBl")]
    pub enable_hide_bl: bool,
    #[serde(rename = "enableCleanupResidue")]
    pub enable_cleanup_residue: bool,
    #[serde(rename = "enableAvcLogSpoofing")]
    pub enable_avc_log_spoofing: bool,
}

impl SusfsConfig {
    pub fn new() -> Self {
        Self {
            uname_value: DEFAULT_UNAME.to_string(),
            build_time_value: DEFAULT_BUILD_TIME.to_string(),
            auto_start_enabled: false,
            sus_paths: Vec::new(),
            sus_loop_paths: Vec::new(),
            sus_maps: Vec::new(),
            enable_log: false,
            execute_in_post_fs_data: false,
            kstat_configs: Vec::new(),
            add_kstat_paths: Vec::new(),
            hide_sus_mounts_for_all_procs: true,
            enable_hide_bl: true,
            enable_cleanup_residue: false,
            enable_avc_log_spoofing: false,
        }
    }

    pub fn has_auto_start_config(&self) -> bool {
        self.uname_value != DEFAULT_UNAME
            || self.build_time_value != DEFAULT_BUILD_TIME
            || !self.sus_paths.is_empty()
            || !self.sus_loop_paths.is_empty()
            || !self.sus_maps.is_empty()
            || !self.kstat_configs.is_empty()
            || !self.add_kstat_paths.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupData {
    #[serde(rename = "version")]
    pub version: String,
    #[serde(rename = "timestamp")]
    pub timestamp: i64,
    #[serde(rename = "deviceInfo")]
    pub device_info: String,
    #[serde(rename = "configurations")]
    pub configurations: SusfsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotInfo {
    #[serde(rename = "slotName")]
    pub slot_name: String,
    #[serde(rename = "uname")]
    pub uname: String,
    #[serde(rename = "buildTime")]
    pub build_time: String,
}

fn ensure_config_dir() -> Result<()> {
    fs::create_dir_all(SUSFS_CONFIG_DIR).context("Failed to create config directory")?;
    Ok(())
}

pub fn load_config() -> Result<SusfsConfig> {
    ensure_config_dir()?;

    if !PathBuf::from(SUSFS_CONFIG_FILE).exists() {
        return Ok(SusfsConfig::new());
    }

    let content = fs::read_to_string(SUSFS_CONFIG_FILE)
        .context("Failed to read config file")?;

    let config: SusfsConfig = serde_json::from_str(&content)
        .context("Failed to parse config file")?;

    Ok(config)
}

pub fn save_config(config: &SusfsConfig) -> Result<()> {
    ensure_config_dir()?;

    let content = serde_json::to_string_pretty(config)
        .context("Failed to serialize config")?;

    fs::write(SUSFS_CONFIG_FILE, content)
        .context("Failed to write config file")?;

    Ok(())
}

pub fn get_uname_value() -> Result<String> {
    Ok(load_config()?.uname_value)
}

pub fn set_uname_value(value: String) -> Result<()> {
    let mut config = load_config()?;
    config.uname_value = value;
    save_config(&config)
}

pub fn get_build_time_value() -> Result<String> {
    Ok(load_config()?.build_time_value)
}

pub fn set_build_time_value(value: String) -> Result<()> {
    let mut config = load_config()?;
    config.build_time_value = value;
    save_config(&config)
}

pub fn is_auto_start_enabled() -> Result<bool> {
    Ok(load_config()?.auto_start_enabled)
}

pub fn set_auto_start_enabled(enabled: bool) -> Result<()> {
    let mut config = load_config()?;
    config.auto_start_enabled = enabled;
    save_config(&config)
}

pub fn get_enable_log() -> Result<bool> {
    Ok(load_config()?.enable_log)
}

pub fn set_enable_log(enabled: bool) -> Result<()> {
    let mut config = load_config()?;
    config.enable_log = enabled;
    save_config(&config)
}

pub fn get_execute_in_post_fs_data() -> Result<bool> {
    Ok(load_config()?.execute_in_post_fs_data)
}

pub fn set_execute_in_post_fs_data(enabled: bool) -> Result<()> {
    let mut config = load_config()?;
    config.execute_in_post_fs_data = enabled;
    save_config(&config)
}

pub fn get_sus_paths() -> Result<Vec<String>> {
    Ok(load_config()?.sus_paths)
}

pub fn set_sus_paths(paths: Vec<String>) -> Result<()> {
    let mut config = load_config()?;
    config.sus_paths = paths;
    save_config(&config)
}

pub fn add_sus_path(path: String) -> Result<()> {
    let mut config = load_config()?;
    if !config.sus_paths.contains(&path) {
        config.sus_paths.push(path);
    }
    save_config(&config)
}

pub fn remove_sus_path(path: &str) -> Result<()> {
    let mut config = load_config()?;
    config.sus_paths.retain(|p| p != path);
    save_config(&config)
}

pub fn get_sus_loop_paths() -> Result<Vec<String>> {
    Ok(load_config()?.sus_loop_paths)
}

pub fn add_sus_loop_path(path: String) -> Result<()> {
    let mut config = load_config()?;
    if !config.sus_loop_paths.contains(&path) {
        config.sus_loop_paths.push(path);
    }
    save_config(&config)
}

pub fn remove_sus_loop_path(path: &str) -> Result<()> {
    let mut config = load_config()?;
    config.sus_loop_paths.retain(|p| p != path);
    save_config(&config)
}

pub fn get_sus_maps() -> Result<Vec<String>> {
    Ok(load_config()?.sus_maps)
}

pub fn add_sus_map(map: String) -> Result<()> {
    let mut config = load_config()?;
    if !config.sus_maps.contains(&map) {
        config.sus_maps.push(map);
    }
    save_config(&config)
}

pub fn remove_sus_map(map: &str) -> Result<()> {
    let mut config = load_config()?;
    config.sus_maps.retain(|m| m != map);
    save_config(&config)
}

pub fn get_kstat_configs() -> Result<Vec<String>> {
    Ok(load_config()?.kstat_configs)
}

pub fn add_kstat_config(config_str: String) -> Result<()> {
    let mut config = load_config()?;
    if !config.kstat_configs.contains(&config_str) {
        config.kstat_configs.push(config_str);
    }
    save_config(&config)
}

pub fn remove_kstat_config(config_str: &str) -> Result<()> {
    let mut config = load_config()?;
    config.kstat_configs.retain(|c| c != config_str);
    save_config(&config)
}

pub fn get_add_kstat_paths() -> Result<Vec<String>> {
    Ok(load_config()?.add_kstat_paths)
}

pub fn add_kstat_path(path: String) -> Result<()> {
    let mut config = load_config()?;
    if !config.add_kstat_paths.contains(&path) {
        config.add_kstat_paths.push(path);
    }
    save_config(&config)
}

pub fn remove_kstat_path(path: &str) -> Result<()> {
    let mut config = load_config()?;
    config.add_kstat_paths.retain(|p| p != path);
    save_config(&config)
}

pub fn get_hide_sus_mounts_for_all_procs() -> Result<bool> {
    Ok(load_config()?.hide_sus_mounts_for_all_procs)
}

pub fn set_hide_sus_mounts_for_all_procs(hide: bool) -> Result<()> {
    let mut config = load_config()?;
    config.hide_sus_mounts_for_all_procs = hide;
    save_config(&config)
}

pub fn get_enable_hide_bl() -> Result<bool> {
    Ok(load_config()?.enable_hide_bl)
}

pub fn set_enable_hide_bl(enabled: bool) -> Result<()> {
    let mut config = load_config()?;
    config.enable_hide_bl = enabled;
    save_config(&config)
}

pub fn get_enable_cleanup_residue() -> Result<bool> {
    Ok(load_config()?.enable_cleanup_residue)
}

pub fn set_enable_cleanup_residue(enabled: bool) -> Result<()> {
    let mut config = load_config()?;
    config.enable_cleanup_residue = enabled;
    save_config(&config)
}

pub fn get_enable_avc_log_spoofing() -> Result<bool> {
    Ok(load_config()?.enable_avc_log_spoofing)
}

pub fn set_enable_avc_log_spoofing(enabled: bool) -> Result<()> {
    let mut config = load_config()?;
    config.enable_avc_log_spoofing = enabled;
    save_config(&config)
}

fn get_susfs_binary_path() -> String {
    format!("{}/bin/ksu_susfs", defs::KSU_DATA)
}

fn run_susfs_command(args: &[&str]) -> Result<(bool, String, String)> {
    let binary_path = get_susfs_binary_path();

    if !PathBuf::from(&binary_path).exists() {
        return Ok((false, String::new(), "SuSFS binary not found".to_string()));
    }

    let mut cmd = Command::new(&binary_path);
    cmd.args(args);

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok((output.status.success(), stdout, stderr))
}

pub fn susfs_enable_log(enabled: bool) -> Result<bool> {
    let value = if enabled { "1" } else { "0" };
    let (success, output, error) = run_susfs_command(&["enable_log", value])?;

    if success {
        set_enable_log(enabled)?;
    }

    Ok(success)
}

pub fn susfs_enable_avc_log_spoofing(enabled: bool) -> Result<bool> {
    let value = if enabled { "1" } else { "0" };
    let (success, output, error) = run_susfs_command(&["enable_avc_log_spoofing", value])?;

    if success {
        set_enable_avc_log_spoofing(enabled)?;
    }

    Ok(success)
}

pub fn susfs_hide_sus_mnts_for_non_su_procs(hide: bool) -> Result<bool> {
    let value = if hide { "1" } else { "0" };
    let (success, output, error) = run_susfs_command(&["hide_sus_mnts_for_non_su_procs", value])?;

    if success {
        set_hide_sus_mounts_for_all_procs(hide)?;
    }

    Ok(success)
}

pub fn susfs_set_uname(uname: &str, build_time: &str) -> Result<bool> {
    let (success, output, error) = run_susfs_command(&["set_uname", uname, build_time])?;

    if success {
        set_uname_value(uname.to_string())?;
        set_build_time_value(build_time.to_string())?;
    }

    Ok(success)
}

pub fn susfs_add_sus_path(path: &str) -> Result<bool> {
    let (success, output, error) = run_susfs_command(&["add_sus_path", path])?;

    if success && !output.contains("not found, skip adding") {
        add_sus_path(path.to_string())?;
    }

    Ok(success)
}

pub fn susfs_remove_sus_path(path: &str) -> Result<bool> {
    remove_sus_path(path)?;
    Ok(true)
}

pub fn susfs_add_sus_path_loop(path: &str) -> Result<bool> {
    let (success, output, error) = run_susfs_command(&["add_sus_path_loop", path])?;

    if success && !output.contains("not found, skip adding") {
        add_sus_loop_path(path.to_string())?;
    }

    Ok(success)
}

pub fn susfs_remove_sus_path_loop(path: &str) -> Result<bool> {
    remove_sus_loop_path(path)?;
    Ok(true)
}

pub fn susfs_add_sus_map(map: &str) -> Result<bool> {
    let (success, output, error) = run_susfs_command(&["add_sus_map", map])?;

    if success {
        add_sus_map(map.to_string())?;
    }

    Ok(success)
}

pub fn susfs_remove_sus_map(map: &str) -> Result<bool> {
    remove_sus_map(map)?;
    Ok(true)
}

pub fn susfs_add_sus_kstat(path: &str) -> Result<bool> {
    let (success, output, error) = run_susfs_command(&["add_sus_kstat", path])?;

    if success {
        add_kstat_path(path.to_string())?;
    }

    Ok(success)
}

pub fn susfs_remove_sus_kstat(path: &str) -> Result<bool> {
    remove_kstat_path(path)?;
    Ok(true)
}

pub fn susfs_add_sus_kstat_statically(config_str: &str) -> Result<bool> {
    let parts: Vec<&str> = config_str.split('|').collect();
    if parts.len() < 13 {
        bail!("Invalid kstat config format");
    }

    let mut args = vec!["add_sus_kstat_statically", parts[0]];
    args.extend(parts[1..].iter().copied());

    let (success, output, error) = run_susfs_command(&args)?;

    if success {
        add_kstat_config(config_str.to_string())?;
    }

    Ok(success)
}

pub fn susfs_remove_sus_kstat_config(config_str: &str) -> Result<bool> {
    remove_kstat_config(config_str)?;
    Ok(true)
}

pub fn susfs_update_sus_kstat(path: &str) -> Result<bool> {
    let (success, output, error) = run_susfs_command(&["update_sus_kstat", path])?;
    Ok(success)
}

pub fn susfs_update_sus_kstat_full_clone(path: &str) -> Result<bool> {
    let (success, output, error) = run_susfs_command(&["update_sus_kstat_full_clone", path])?;
    Ok(success)
}

fn run_shell_cmd(cmd: &str) -> Result<(bool, String, String)> {
    let output = Command::new("sh")
        .args(["-c", cmd])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok((output.status.success(), stdout, stderr))
}

pub fn create_magisk_module() -> Result<bool> {
    let config = load_config()?;

    // 创建模块目录
    run_shell_cmd(&format!("mkdir -p {}", MODULE_PATH))?;

    // 生成 module.prop
    let module_prop = generate_module_prop();
    run_shell_cmd(&format!(
        "cat > {}/module.prop << 'EOF'\n{}\nEOF",
        MODULE_PATH, module_prop
    ))?;

    let config_json = serde_json::to_string(&config)?;
    let config_path = format!("{}/config.json", SUSFS_CONFIG_DIR);
    fs::write(&config_path, &config_json)?;

    let script_path = format!("{}/bin/susfs_module_generator.sh", defs::KSU_DATA);
    if PathBuf::from(&script_path).exists() {
        run_shell_cmd(&format!("sh {} '{}'", script_path, MODULE_PATH))?;
    } else {
        let scripts = generate_all_scripts(&config);
        for (filename, content) in scripts {
            let script_path = format!("{}/{}", MODULE_PATH, filename);
            fs::write(&script_path, content)?;
            run_shell_cmd(&format!("chmod 755 {}", script_path))?;
        }
    }

    Ok(true)
}

pub fn remove_magisk_module() -> Result<bool> {
    run_shell_cmd(&format!("rm -rf {}", MODULE_PATH))?;
    Ok(true)
}

pub fn update_magisk_module() -> Result<bool> {
    remove_magisk_module()?;
    create_magisk_module()
}

pub fn configure_auto_start(enabled: bool) -> Result<bool> {
    if enabled {
        let config = load_config()?;
        if !config.has_auto_start_config() {
            bail!("No configuration available for auto start");
        }
        create_magisk_module()?;
        set_auto_start_enabled(true)?;
    } else {
        remove_magisk_module()?;
        set_auto_start_enabled(false)?;
    }
    Ok(true)
}

fn generate_module_prop() -> String {
    r#"id=susfs_manager
name=SuSFS Manager
version=v4.0.0
versionCode=40000
author=ShirkNeko
description=SuSFS Manager Auto Configuration Module (Automatically generated)
updateJson=
"#
    .to_string()
}

fn generate_log_setup(log_file_name: &str) -> String {
    format!(
        r#"LOG_DIR="{}"
LOG_FILE="$LOG_DIR/{}"

# 创建日志目录
mkdir -p "$LOG_DIR"

# 获取当前时间
get_current_time() {{
    date '+%Y-%m-%d %H:%M:%S'
}}
"#,
        LOG_DIR, log_file_name
    )
}

fn generate_binary_check(target_path: &str) -> String {
    format!(
        r#"# 检查SuSFS二进制文件
SUSFS_BIN="{}"
if [ ! -f "$SUSFS_BIN" ]; then
    echo "$(get_current_time): SuSFS二进制文件未找到: $SUSFS_BIN" >> "$LOG_FILE"
    exit 1
fi
"#,
        target_path
    )
}

fn should_configure_in_service(config: &SusfsConfig) -> bool {
    !config.sus_paths.is_empty()
        || !config.sus_loop_paths.is_empty()
        || !config.kstat_configs.is_empty()
        || !config.add_kstat_paths.is_empty()
        || (!config.execute_in_post_fs_data
            && (config.uname_value != DEFAULT_UNAME
                || config.build_time_value != DEFAULT_BUILD_TIME))
}

fn generate_service_script(config: &SusfsConfig) -> String {
    let binary_path = get_susfs_binary_path();
    let mut script = String::new();

    script.push_str("#!/system/bin/sh\n");
    script.push_str("# SuSFS Service Script\n");
    script.push_str("# 在系统服务启动后执行\n\n");

    script.push_str(&generate_log_setup("susfs_service.log"));
    script.push('\n');

    script.push_str(&generate_binary_check(&binary_path));
    script.push('\n');

    if should_configure_in_service(config) {
        // 添加SUS路径
        if !config.sus_paths.is_empty() {
            script.push_str("# 添加SUS路径\n");
            script.push_str("until [ -d \"/sdcard/Android\" ]; do sleep 1; done\n");
            script.push_str("sleep 45\n");
            for path in &config.sus_paths {
                script.push_str(&format!("\"$SUSFS_BIN\" add_sus_path '{}'\n", path));
                script.push_str(&format!(
                    "echo \"$(get_current_time): 添加SUS路径: {}\" >> \"$LOG_FILE\"\n",
                    path
                ));
            }
            script.push('\n');
        }

        // 设置uname和构建时间
        if !config.execute_in_post_fs_data
            && (config.uname_value != DEFAULT_UNAME || config.build_time_value != DEFAULT_BUILD_TIME)
        {
            script.push_str("# 设置uname和构建时间\n");
            script.push_str(&format!(
                "\"$SUSFS_BIN\" set_uname '{}' '{}'\n",
                config.uname_value, config.build_time_value
            ));
            script.push('\n');
        }

        // 添加Kstat配置
        if !config.add_kstat_paths.is_empty() {
            script.push_str("# 添加Kstat路径\n");
            for path in &config.add_kstat_paths {
                script.push_str(&format!("\"$SUSFS_BIN\" add_sus_kstat '{}'\n", path));
            }
            script.push('\n');
        }

        if !config.kstat_configs.is_empty() {
            script.push_str("# 添加Kstat静态配置\n");
            for config_str in &config.kstat_configs {
                let parts: Vec<&str> = config_str.split('|').collect();
                if parts.len() >= 13 {
                    script.push_str(&format!(
                        "\"$SUSFS_BIN\" add_sus_kstat_statically '{}' '{}' '{}' '{}' '{}' '{}' '{}' '{}' '{}' '{}' '{}' '{}' '{}'\n",
                        parts[0], parts[1], parts[2], parts[3], parts[4], parts[5],
                        parts[6], parts[7], parts[8], parts[9], parts[10], parts[11], parts[12]
                    ));
                }
            }
            script.push('\n');
        }
    }

    // 日志设置
    script.push_str("# 设置日志启用状态\n");
    let log_value = if config.enable_log { 1 } else { 0 };
    script.push_str(&format!("\"$SUSFS_BIN\" enable_log {}\n", log_value));
    script.push('\n');

    // 隐藏BL相关配置
    if config.enable_hide_bl {
        script.push_str(&generate_hide_bl_section());
        script.push('\n');
    }

    // 清理工具残留
    if config.enable_cleanup_residue {
        script.push_str(&generate_cleanup_residue_section());
        script.push('\n');
    }

    script.push_str(&format!(
        "echo \"$(get_current_time): Service脚本执行完成\" >> \"$LOG_FILE\"\n"
    ));

    script
}

fn generate_post_fs_data_script(config: &SusfsConfig) -> String {
    let binary_path = get_susfs_binary_path();
    let mut script = String::new();

    script.push_str("#!/system/bin/sh\n");
    script.push_str("# SuSFS Post-FS-Data Script\n");
    script.push_str("# 在文件系统挂载后但在系统完全启动前执行\n\n");

    script.push_str(&generate_log_setup("susfs_post_fs_data.log"));
    script.push('\n');

    script.push_str(&generate_binary_check(&binary_path));
    script.push('\n');

    script.push_str("echo \"$(get_current_time): Post-FS-Data脚本开始执行\" >> \"$LOG_FILE\"\n\n");

    // 设置uname和构建时间
    if config.execute_in_post_fs_data
        && (config.uname_value != DEFAULT_UNAME || config.build_time_value != DEFAULT_BUILD_TIME)
    {
        script.push_str("# 设置uname和构建时间\n");
        script.push_str(&format!(
            "\"$SUSFS_BIN\" set_uname '{}' '{}'\n",
            config.uname_value, config.build_time_value
        ));
        script.push('\n');
    }

    // AVC日志欺骗设置
    if config.enable_avc_log_spoofing {
        let avc_value = if config.enable_avc_log_spoofing { 1 } else { 0 };
        script.push_str("# 设置AVC日志欺骗状态\n");
        script.push_str(&format!("\"$SUSFS_BIN\" enable_avc_log_spoofing {}\n", avc_value));
        script.push('\n');
    }

    script.push_str("echo \"$(get_current_time): Post-FS-Data脚本执行完成\" >> \"$LOG_FILE\"\n");

    script
}

fn generate_post_mount_script(_config: &SusfsConfig) -> String {
    let binary_path = get_susfs_binary_path();
    let mut script = String::new();

    script.push_str("#!/system/bin/sh\n");
    script.push_str("# SuSFS Post-Mount Script\n");
    script.push_str("# 在所有分区挂载完成后执行\n\n");

    script.push_str(&generate_log_setup("susfs_post_mount.log"));
    script.push('\n');

    script.push_str("echo \"$(get_current_time): Post-Mount脚本开始执行\" >> \"$LOG_FILE\"\n\n");

    script.push_str(&generate_binary_check(&binary_path));
    script.push('\n');

    script.push_str("echo \"$(get_current_time): Post-Mount脚本执行完成\" >> \"$LOG_FILE\"\n");

    script
}

fn generate_boot_completed_script(config: &SusfsConfig) -> String {
    let binary_path = get_susfs_binary_path();
    let mut script = String::new();

    script.push_str("#!/system/bin/sh\n");
    script.push_str("# SuSFS Boot-Completed Script\n");
    script.push_str("# 在系统完全启动后执行\n\n");

    script.push_str(&generate_log_setup("susfs_boot_completed.log"));
    script.push('\n');

    script.push_str("echo \"$(get_current_time): Boot-Completed脚本开始执行\" >> \"$LOG_FILE\"\n\n");

    script.push_str(&generate_binary_check(&binary_path));
    script.push('\n');

    // SUS挂载隐藏控制
    let hide_value = if config.hide_sus_mounts_for_all_procs {
        1
    } else {
        0
    };
    script.push_str("# 设置SUS挂载隐藏控制\n");
    script.push_str(&format!(
        "\"$SUSFS_BIN\" hide_sus_mnts_for_non_su_procs {}\n",
        hide_value
    ));
    script.push('\n');

    // SUS路径设置
    if !config.sus_paths.is_empty() || !config.sus_loop_paths.is_empty() {
        if !config.sus_paths.is_empty() {
            script.push_str("# 添加普通SUS路径\n");
            for path in &config.sus_paths {
                script.push_str(&format!("\"$SUSFS_BIN\" add_sus_path '{}'\n", path));
            }
            script.push('\n');
        }

        if !config.sus_loop_paths.is_empty() {
            script.push_str("# 添加循环SUS路径\n");
            for path in &config.sus_loop_paths {
                script.push_str(&format!("\"$SUSFS_BIN\" add_sus_path_loop '{}'\n", path));
            }
            script.push('\n');
        }

        if !config.sus_maps.is_empty() {
            script.push_str("# 添加SUS映射\n");
            for map in &config.sus_maps {
                script.push_str(&format!("\"$SUSFS_BIN\" add_sus_map '{}'\n", map));
            }
            script.push('\n');
        }
    }

    script.push_str("echo \"$(get_current_time): Boot-Completed脚本执行完成\" >> \"$LOG_FILE\"\n");

    script
}

fn generate_hide_bl_section() -> String {
    r#"# 隐藏BL 来自 Shamiko 脚本
RESETPROP_BIN="/data/adb/ksu/bin/resetprop"

check_reset_prop() {
    local NAME=$1
    local EXPECTED=$2
    local VALUE=$("$RESETPROP_BIN" $NAME)
    [ -z $VALUE ] || [ $VALUE = $EXPECTED ] || "$RESETPROP_BIN" $NAME $EXPECTED
}

check_missing_prop() {
    local NAME=$1
    local EXPECTED=$2
    local VALUE=$("$RESETPROP_BIN" $NAME)
    [ -z $VALUE ] && "$RESETPROP_BIN" $NAME $EXPECTED
}

check_missing_match_prop() {
    local NAME=$1
    local EXPECTED=$2
    local VALUE=$("$RESETPROP_BIN" $NAME)
    [ -z $VALUE ] || [ $VALUE = $EXPECTED ] || "$RESETPROP_BIN" $NAME $EXPECTED
    [ -z $VALUE ] && "$RESETPROP_BIN" $NAME $EXPECTED
}

contains_reset_prop() {
    local NAME=$1
    local CONTAINS=$2
    local NEWVAL=$3
    case "$("$RESETPROP_BIN" $NAME)" in
        *"$CONTAINS"*) "$RESETPROP_BIN" $NAME $NEWVAL ;;
    esac
}

sleep 30
"$RESETPROB_BIN" -w sys.boot_completed 0

# 重置系统属性
check_reset_prop "ro.boot.vbmeta.invalidate_on_error" "yes"
check_reset_prop "ro.boot.vbmeta.avb_version" "1.2"
check_reset_prop "ro.boot.vbmeta.hash_alg" "sha256"
check_reset_prop "ro.boot.vbmeta.size" "19968"
check_reset_prop "ro.boot.vbmeta.device_state" "locked"
check_reset_prop "ro.boot.verifiedbootstate" "green"
check_reset_prop "ro.boot.flash.locked" "1"
check_reset_prop "ro.boot.veritymode" "enforcing"
check_reset_prop "ro.boot.warranty_bit" "0"
check_reset_prop "ro.warranty_bit" "0"
check_reset_prop "ro.debuggable" "0"
check_reset_prop "ro.force.debuggable" "0"
check_reset_prop "ro.secure" "1"
check_reset_prop "ro.adb.secure" "1"
check_reset_prop "ro.build.type" "user"
check_reset_prop "ro.build.tags" "release-keys"
check_reset_prop "ro.vendor.boot.warranty_bit" "0"
check_reset_prop "ro.vendor.warranty_bit" "0"
check_reset_prop "vendor.boot.vbmeta.device_state" "locked"
check_reset_prop "vendor.boot.verifiedbootstate" "green"
check_reset_prop "sys.oem_unlock_allowed" "0"
check_reset_prop "ro.secureboot.lockstate" "locked"
check_reset_prop "ro.boot.realmebootstate" "green"
check_reset_prop "ro.boot.realme.lockstate" "1"
check_reset_prop "ro.crypto.state" "encrypted"

# Hide adb debugging traces
resetprop "sys.usb.adb.disabled" " "

# Hide recovery boot mode
contains_reset_prop "ro.bootmode" "recovery" "unknown"
contains_reset_prop "ro.boot.bootmode" "recovery" "unknown"
contains_reset_prop "vendor.boot.bootmode" "recovery" "unknown"

# Hide cloudphone detection
[ -n "$(resetprop ro.kernel.qemu)" ] && resetprop ro.kernel.qemu ""

"#
    .to_string()
}

fn generate_cleanup_residue_section() -> String {
    r#"# 清理工具残留文件
echo "$(get_current_time): 开始清理工具残留" >> "$LOG_FILE"

cleanup_path() {
    local path="$1"
    local desc="$2"
    local current="$3"
    local total="$4"

    if [ -n "$desc" ]; then
        echo "$(get_current_time): [$current/$total] 清理: $path ($desc)" >> "$LOG_FILE"
    else
        echo "$(get_current_time): [$current/$total] 清理: $path" >> "$LOG_FILE"
    fi

    if rm -rf "$path" 2>/dev/null; then
        echo "$(get_current_time): 成功清理: $path" >> "$LOG_FILE"
    else
        echo "$(get_current_time): 清理失败或不存在: $path" >> "$LOG_FILE"
    fi
}

TOTAL=33

cleanup_path "/data/local/stryker/" "Stryker残留" 1 $TOTAL
cleanup_path "/data/system/AppRetention" "AppRetention残留" 2 $TOTAL
cleanup_path "/data/local/tmp/luckys" "Luck Tool残留" 3 $TOTAL
cleanup_path "/data/local/tmp/HyperCeiler" "西米露残留" 4 $TOTAL
cleanup_path "/data/local/tmp/simpleHook" "simple Hook残留" 5 $TOTAL
cleanup_path "/data/local/tmp/DisabledAllGoogleServices" "谷歌省电模块残留" 6 $TOTAL
cleanup_path "/data/local/MIO" "解包软件" 7 $TOTAL
cleanup_path "/data/DNA" "解包软件" 8 $TOTAL
cleanup_path "/data/local/tmp/cleaner_starter" "质感清理残留" 9 $TOTAL
cleanup_path "/data/local/tmp/byyang" "" 10 $TOTAL
cleanup_path "/data/local/tmp/mount_mask" "" 11 $TOTAL
cleanup_path "/data/local/tmp/mount_mark" "" 12 $TOTAL
cleanup_path "/data/local/tmp/scriptTMP" "" 13 $TOTAL
cleanup_path "/data/local/luckys" "" 14 $TOTAL
cleanup_path "/data/local/tmp/horae_control.log" "" 15 $TOTAL
cleanup_path "/data/gpu_freq_table.conf" "" 16 $TOTAL
cleanup_path "/storage/emulated/0/Download/advanced/" "" 17 $TOTAL
cleanup_path "/storage/emulated/0/Documents/advanced/" "爱玩机" 18 $TOTAL
cleanup_path "/storage/emulated/0/Android/naki/" "旧版asoulopt" 19 $TOTAL
cleanup_path "/data/swap_config.conf" "scene附加模块2" 20 $TOTAL
cleanup_path "/data/local/tmp/resetprop" "" 21 $TOTAL
cleanup_path "/dev/cpuset/AppOpt/" "AppOpt模块" 22 $TOTAL
cleanup_path "/storage/emulated/0/Android/Clash/" "Clash for Magisk模块" 23 $TOTAL
cleanup_path "/storage/emulated/0/Android/Yume-Yunyun/" "网易云后台优化模块" 24 $TOTAL
cleanup_path "/data/local/tmp/Surfing_update" "Surfing模块缓存" 25 $TOTAL
cleanup_path "/data/encore/custom_default_cpu_gov" "encore模块" 26 $TOTAL
cleanup_path "/data/encore/default_cpu_gov" "encore模块" 27 $TOTAL
cleanup_path "/data/local/tmp/yshell" "" 28 $TOTAL
cleanup_path "/data/local/tmp/encore_logo.png" "" 29 $TOTAL
cleanup_path "/storage/emulated/legacy/" "" 30 $TOTAL
cleanup_path "/storage/emulated/elgg/" "" 31 $TOTAL
cleanup_path "/data/system/junge/" "" 32 $TOTAL
cleanup_path "/data/local/tmp/mount_namespace" "挂载命名空间残留" 33 $TOTAL

echo "$(get_current_time): 工具残留清理完成" >> "$LOG_FILE"

"#
    .to_string()
}

fn generate_all_scripts(config: &SusfsConfig) -> Vec<(String, String)> {
    vec![
        ("service.sh".to_string(), generate_service_script(config)),
        (
            "post-fs-data.sh".to_string(),
            generate_post_fs_data_script(config),
        ),
        ("post-mount.sh".to_string(), generate_post_mount_script(config)),
        (
            "boot-completed.sh".to_string(),
            generate_boot_completed_script(config),
        ),
    ]
}

fn get_device_info() -> String {
    let manufacturer = crate::utils::getprop("ro.product.manufacturer").unwrap_or_default();
    let model = crate::utils::getprop("ro.product.model").unwrap_or_default();
    let version = crate::utils::getprop("ro.build.version.release").unwrap_or_default();

    format!("{} {} ({})", manufacturer, model, version)
}

fn generate_backup_file_name() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    format!("SuSFS_Config_{}.susfs_backup", now)
}

pub fn create_backup(backup_path: Option<String>) -> Result<String> {
    let config = load_config()?;
    let version = crate::susfs::get_susfs_version();

    fs::create_dir_all(SUSFS_BACKUP_DIR)?;

    let backup_file_name = backup_path.unwrap_or_else(|| {
        format!("{}/{}", SUSFS_BACKUP_DIR, generate_backup_file_name())
    });

    let backup_data = BackupData {
        version,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        device_info: get_device_info(),
        configurations: config,
    };

    let content = serde_json::to_string_pretty(&backup_data)
        .context("Failed to serialize backup data")?;

    fs::write(&backup_file_name, content)
        .context("Failed to write backup file")?;

    Ok(backup_file_name)
}

pub fn restore_from_backup(backup_file_path: &str) -> Result<bool> {
    if !PathBuf::from(backup_file_path).exists() {
        bail!("Backup file not found");
    }

    let content = fs::read_to_string(backup_file_path)
        .context("Failed to read backup file")?;

    let backup_data: BackupData = serde_json::from_str(&content)
        .context("Failed to parse backup file")?;

    // 恢复配置
    save_config(&backup_data.configurations)?;

    // 如果自启动已启用，更新模块
    if backup_data.configurations.auto_start_enabled {
        create_magisk_module()?;
    }

    Ok(true)
}

pub fn validate_backup(backup_file_path: &str) -> Result<BackupData> {
    if !PathBuf::from(backup_file_path).exists() {
        bail!("Backup file not found");
    }

    let content = fs::read_to_string(backup_file_path)
        .context("Failed to read backup file")?;

    let backup_data: BackupData = serde_json::from_str(&content)
        .context("Failed to parse backup file")?;

    Ok(backup_data)
}

pub fn list_backups() -> Result<Vec<String>> {
    if !PathBuf::from(SUSFS_BACKUP_DIR).exists() {
        return Ok(Vec::new());
    }

    let mut backups = Vec::new();

    for entry in fs::read_dir(SUSFS_BACKUP_DIR)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "susfs_backup" {
                    backups.push(path.to_string_lossy().to_string());
                }
            }
        }
    }

    backups.sort_by(|a, b| b.cmp(a));

    Ok(backups)
}

pub fn get_slot_info() -> Result<Vec<SlotInfo>> {
    let mut slot_info_list = Vec::new();

    for slot in &["boot_a", "boot_b"] {
        let block_path = format!("/dev/block/by-name/{}", slot);

        if !PathBuf::from(&block_path).exists() {
            continue;
        }

        let uname_cmd = format!(
            "strings -n 20 {} | awk '/Linux version/ && ++c==2 {{print $3; exit}}'",
            block_path
        );
        let build_time_cmd = format!(
            "strings -n 20 {} | sed -n '/Linux version.*#/{{s/.*#/#/p;q}}'",
            block_path
        );

        let (success_uname, uname_out, _) = run_shell_cmd(&uname_cmd)?;
        let (success_build, build_out, _) = run_shell_cmd(&build_time_cmd)?;

        let uname = uname_out.trim();
        let build_time = build_out.trim();

        if !uname.is_empty() && !build_time.is_empty() {
            slot_info_list.push(SlotInfo {
                slot_name: slot.to_string(),
                uname: uname.to_string(),
                build_time: build_time.to_string(),
            });
        }
    }

    Ok(slot_info_list)
}

pub fn get_current_active_slot() -> Result<String> {
    let suffix = crate::utils::getprop("ro.boot.slot_suffix").unwrap_or_default();

    let slot = match suffix.as_str() {
        "_a" => "boot_a",
        "_b" => "boot_b",
        _ => "unknown",
    };

    Ok(slot.to_string())
}

// ============== 列出配置 ==============

pub fn show_config() -> Result<()> {
    let config = load_config()?;

    println!("=== SuSFS Configuration ===");
    println!("uname_value: {}", config.uname_value);
    println!("build_time_value: {}", config.build_time_value);
    println!("auto_start_enabled: {}", config.auto_start_enabled);
    println!("enable_log: {}", config.enable_log);
    println!("execute_in_post_fs_data: {}", config.execute_in_post_fs_data);
    println!("hide_sus_mounts_for_all_procs: {}", config.hide_sus_mounts_for_all_procs);
    println!("enable_hide_bl: {}", config.enable_hide_bl);
    println!("enable_cleanup_residue: {}", config.enable_cleanup_residue);
    println!("enable_avc_log_spoofing: {}", config.enable_avc_log_spoofing);
    println!();
    println!("sus_paths:");
    for path in &config.sus_paths {
        println!("  - {}", path);
    }
    println!();
    println!("sus_loop_paths:");
    for path in &config.sus_loop_paths {
        println!("  - {}", path);
    }
    println!();
    println!("sus_maps:");
    for map in &config.sus_maps {
        println!("  - {}", map);
    }
    println!();
    println!("kstat_configs:");
    for config_str in &config.kstat_configs {
        println!("  - {}", config_str);
    }
    println!();
    println!("add_kstat_paths:");
    for path in &config.add_kstat_paths {
        println!("  - {}", path);
    }

    Ok(())
}

pub fn reset_to_default() -> Result<bool> {
    let (success, _, _) = susfs_set_uname(DEFAULT_UNAME, DEFAULT_BUILD_TIME)?;

    if success {
        let config = load_config()?;
        if config.auto_start_enabled {
            configure_auto_start(false)?;
        }
    }

    Ok(success)
}
