use crate::susfs_config::SusfsConfig;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

const MODULE_ID: &str = "susfs_manager";
const MODULE_PATH: &str = "/data/adb/modules/susfs_manager";
const LOG_DIR: &str = "/data/adb/ksu/log";

pub fn create_magisk_module(config: &SusfsConfig) -> Result<()> {
    create_module_dir()?;
    create_module_prop()?;
    create_all_scripts(config)?;
    Ok(())
}

pub fn remove_magisk_module() -> Result<()> {
    let path = Path::new(MODULE_PATH);
    if path.exists() {
        fs::remove_dir_all(path).context("Failed to remove module")?;
    }
    Ok(())
}

pub fn update_magisk_module(config: &SusfsConfig) -> Result<()> {
    remove_magisk_module()?;
    create_magisk_module(config)?;
    Ok(())
}

fn create_module_dir() -> Result<()> {
    let path = Path::new(MODULE_PATH);
    if !path.exists() {
        fs::create_dir_all(path).context("Failed to create module dir")?;
    }
    Ok(())
}

fn create_module_prop() -> Result<()> {
    let content = r"id=susfs_manager
name=SuSFS Manager
version=v4.0.0
versionCode=40000
author=ShirkNeko
description=SuSFS Manager Auto Configuration Module (Automatically generated. Do not manually uninstall or delete this module!)
updateJson=
";
    let path = Path::new(MODULE_PATH).join("module.prop");
    fs::write(&path, content).context("Failed to write module.prop")?;
    Ok(())
}

fn create_all_scripts(config: &SusfsConfig) -> Result<()> {
    create_service_sh(config)?;
    create_post_fs_data_sh(config)?;
    create_post_mount_sh(config)?;
    create_boot_completed_sh(config)?;
    Ok(())
}

fn write_script(filename: &str, content: &str) -> Result<()> {
    let path = Path::new(MODULE_PATH).join(filename);
    fs::write(&path, content).with_context(|| format!("Failed to write {}", filename))?;
    
    // Set executable permission
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&path).context("Failed to get metadata")?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).context("Failed to set permissions")?;
    }
    
    Ok(())
}

fn get_log_setup() -> String {
    format!(r"# Log setup
LOG_DIR="{}"
LOG_FILE="$LOG_DIR/susfs_service.log"

mkdir -p "$LOG_DIR"

get_current_time() {{
    date '+%Y-%m-%d %H:%M:%S'
}}
", LOG_DIR)
}

fn get_binary_check() -> String {
    r"# Check SuSFS binary
SUSFS_BIN="/data/adb/ksu/bin/ksu_susfs"
if [ ! -f "$SUSFS_BIN" ]; then
    SUSFS_BIN="/data/adb/ksud/ksu_susfs"
fi
if [ ! -f "$SUSFS_BIN" ]; then
    echo "$(get_current_time): SuSFS binary not found" >> "$LOG_FILE"
    exit 1
fi
"#.to_string()
}

fn create_service_sh(config: &SusfsConfig) -> Result<()> {
    let mut content = String::new();
    content.push_str("#!/system/bin/sh\n");
    content.push_str("# SuSFS Service Script\n");
    content.push_str("# Execute after system services start\n\n");
    content.push_str(&get_log_setup());
    content.push_str("\n");
    content.push_str(&get_binary_check());
    content.push_str("\n");
    content.push_str("echo \"$(get_current_time): Service script started\" >> \"$LOG_FILE\"\n\n");

    if config.has_auto_start_config() {
        // Add SUS paths
        if !config.sus_paths.is_empty() {
            content.push_str("# Add SUS paths\n");
            content.push_str("until [ -d \"/sdcard/Android\" ]; do sleep 1; done\n");
            content.push_str("sleep 45\n");
            for path in &config.sus_paths {
                content.push_str(&format!("\"$SUSFS_BIN\" add_sus_path '{}'\n", path));
                content.push_str(&format!("echo \"$(get_current_time): Add SUS path: {}\" >> \"$LOG_FILE\"\n", path));
            }
            content.push('\n');
        }

        // Add SUS loop paths
        if !config.sus_loop_paths.is_empty() {
            content.push_str("# Add SUS loop paths\n");
            for path in &config.sus_loop_paths {
                content.push_str(&format!("\"$SUSFS_BIN\" add_sus_path_loop '{}'\n", path));
                content.push_str(&format!("echo \"$(get_current_time): Add SUS loop path: {}\" >> \"$LOG_FILE\"\n", path));
            }
            content.push('\n');
        }

        // Set uname and build time
        if !config.execute_in_post_fs_data && 
           (config.uname_value != "default" || config.build_time_value != "default") {
            content.push_str("# Set uname and build time\n");
            content.push_str(&format!(
                "\"{}\" set_uname '{}' '{}'\n",
                "$SUSFS_BIN", config.uname_value, config.build_time_value
            ));
            content.push_str(&format!(
                "echo \"$(get_current_time): Set uname: {}, build time: {}\" >> \"$LOG_FILE\"\n",
                config.uname_value, config.build_time_value
            ));
            content.push('\n');
        }

        // Add Kstat paths
        if !config.add_kstat_paths.is_empty() {
            content.push_str("# Add Kstat paths\n");
            for path in &config.add_kstat_paths {
                content.push_str(&format!("\"$SUSFS_BIN\" add_sus_kstat '{}'\n", path));
                content.push_str(&format!("echo \"$(get_current_time): Add Kstat path: {}\" >> \"$LOG_FILE\"\n", path));
            }
            content.push('\n');
        }

        // Add Kstat static configs
        if !config.kstat_configs.is_empty() {
            content.push_str("# Add Kstat static configs\n");
            for config_str in &config.kstat_configs {
                let parts: Vec<&str> = config_str.split('|').collect();
                if parts.len() >= 13 {
                    let path = parts[0];
                    let params = parts[1..].join("' '");
                    content.push_str(&format!("\"$SUSFS_BIN\" add_sus_kstat_statically '{}' '{}'\n", path, params));
                    content.push_str(&format!("echo \"$(get_current_time): Add Kstat static config: {}\" >> \"$LOG_FILE\"\n", path));
                    content.push_str(&format!("\"$SUSFS_BIN\" update_sus_kstat '{}'\n", path));
                    content.push_str(&format!("echo \"$(get_current_time): Update Kstat config: {}\" >> \"$LOG_FILE\"\n", path));
                }
            }
            content.push('\n');
        }
    }

    // Enable log
    content.push_str("# Enable log\n");
    content.push_str(&format!(
        "\"{}\" enable_log {}\n",
        "$SUSFS_BIN", if config.enable_log { 1 } else { 0 }
    ));
    content.push_str(&format!(
        "echo \"$(get_current_time): Log enabled: {}\" >> \"$LOG_FILE\"\n",
        config.enable_log
    ));
    content.push('\n');

    // Hide BL
    if config.enable_hide_bl {
        content.push_str(&generate_hide_bl_section());
    }

    // Cleanup residue
    if config.enable_cleanup_residue {
        content.push_str(&generate_cleanup_residue_section());
    }

    content.push_str("echo \"$(get_current_time): Service script completed\" >> \"$LOG_FILE\"\n");

    write_script("service.sh", &content)
}

fn create_post_fs_data_sh(config: &SusfsConfig) -> Result<()> {
    let mut content = String::new();
    content.push_str("#!/system/bin/sh\n");
    content.push_str("# SuSFS Post-FS-Data Script\n");
    content.push_str("# Execute after filesystem is mounted but before system fully starts\n\n");
    content.push_str(&get_log_setup());
    content.push_str("\n");
    content.push_str(&get_binary_check());
    content.push_str("\n");
    content.push_str("echo \"$(get_current_time): Post-FS-Data script started\" >> \"$LOG_FILE\"\n\n");

    // Set uname in post-fs-data if configured
    if config.execute_in_post_fs_data && 
       (config.uname_value != "default" || config.build_time_value != "default") {
        content.push_str("# Set uname and build time\n");
        content.push_str(&format!(
            "\"{}\" set_uname '{}' '{}'\n",
            "$SUSFS_BIN", config.uname_value, config.build_time_value
        ));
        content.push_str(&format!(
            "echo \"$(get_current_time): Set uname: {}, build time: {}\" >> \"$LOG_FILE\"\n",
            config.uname_value, config.build_time_value
        ));
        content.push('\n');
    }

    // Enable AVC log spoofing
    content.push_str("# Enable AVC log spoofing\n");
    content.push_str(&format!(
        "\"{}\" enable_avc_log_spoofing {}\n",
        "$SUSFS_BIN", if config.enable_avc_log_spoofing { 1 } else { 0 }
    ));
    content.push_str(&format!(
        "echo \"$(get_current_time): AVC log spoofing: {}\" >> \"$LOG_FILE\"\n",
        config.enable_avc_log_spoofing
    ));
    content.push('\n');

    content.push_str("echo \"$(get_current_time): Post-FS-Data script completed\" >> \"$LOG_FILE\"\n");

    write_script("post-fs-data.sh", &content)
}

#[allow(unused_variables)]
fn create_post_mount_sh(config: &SusfsConfig) -> Result<()> {
    let mut content = String::new();
    content.push_str("#!/system/bin/sh\n");
    content.push_str("# SuSFS Post-Mount Script\n");
    content.push_str("# Execute after all partitions are mounted\n\n");
    content.push_str(&get_log_setup());
    content.push_str("\n");
    content.push_str("echo \"$(get_current_time): Post-Mount script started\" >> \"$LOG_FILE\"\n\n");
    content.push_str(&get_binary_check());
    content.push_str("\n");
    content.push_str("echo \"$(get_current_time): Post-Mount script completed\" >> \"$LOG_FILE\"\n");

    write_script("post-mount.sh", &content)
}

fn create_boot_completed_sh(config: &SusfsConfig) -> Result<()> {
    let mut content = String::new();
    content.push_str("#!/system/bin/sh\n");
    content.push_str("# SuSFS Boot-Completed Script\n");
    content.push_str("# Execute after system fully starts\n\n");
    content.push_str(&get_log_setup());
    content.push_str("\n");
    content.push_str("echo \"$(get_current_time): Boot-Completed script started\" >> \"$LOG_FILE\"\n\n");
    content.push_str(&get_binary_check());
    content.push_str("\n");

    // Hide SUS mounts
    content.push_str("# Hide SUS mounts\n");
    content.push_str(&format!(
        "\"{}\" hide_sus_mnts_for_non_su_procs {}\n",
        "$SUSFS_BIN", if config.hide_sus_mounts_for_all_procs { 1 } else { 0 }
    ));
    content.push_str(&format!(
        "echo \"$(get_current_time): Hide SUS mounts: {}\" >> \"$LOG_FILE\"\n",
        if config.hide_sus_mounts_for_all_procs { "all processes" } else { "non-KSU processes only" }
    ));
    content.push('\n');

    // Add SUS maps
    if !config.sus_maps.is_empty() {
        content.push_str("# Add SUS maps\n");
        for map in &config.sus_maps {
            content.push_str(&format!("\"$SUSFS_BIN\" add_sus_map '{}'\n", map));
            content.push_str(&format!("echo \"$(get_current_time): Add SUS map: {}\" >> \"$LOG_FILE\"\n", map));
        }
        content.push('\n');
    }

    content.push_str("echo \"$(get_current_time): Boot-Completed script completed\" >> \"$LOG_FILE\"\n");

    write_script("boot-completed.sh", &content)
}

fn generate_hide_bl_section() -> String {
    let mut content = String::new();
    content.push_str("# Hide bootloader from Shamiko script\n");
    content.push_str(r#"
RESETPROP_BIN="/data/adb/ksu/bin/resetprop"

check_reset_prop() {
    local NAME=$1
    local EXPECTED=$2
    local VALUE=$("$RESETPROP_BIN" $NAME)
    [ -z "$VALUE" ] || [ "$VALUE" = "$EXPECTED" ] || "$RESETPROP_BIN" $NAME $EXPECTED
}

check_missing_prop() {
    local NAME=$1
    local EXPECTED=$2
    local VALUE=$("$RESETPROP_BIN" $NAME)
    [ -z "$VALUE" ] && "$RESETPROP_BIN" $NAME $EXPECTED
}

check_missing_match_prop() {
    local NAME=$1
    local EXPECTED=$2
    local VALUE=$("$RESETPROP_BIN" $NAME)
    [ -z "$VALUE" ] || [ "$VALUE" = "$EXPECTED" ] || "$RESETPROP_BIN" $NAME $EXPECTED
    [ -z "$VALUE" ] && "$RESETPROP_BIN" $NAME $EXPECTED
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

"$RESETPROP_BIN" -w sys.boot_completed 0

check_missing_match_prop "ro.boot.vbmeta.invalidate_on_error" "yes"
check_missing_match_prop "ro.boot.vbmeta.avb_version" "1.2"
check_missing_match_prop "ro.boot.vbmeta.hash_alg" "sha256"
check_missing_match_prop "ro.boot.vbmeta.size" "19968"
check_missing_match_prop "ro.boot.vbmeta.device_state" "locked"
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
check_missing_match_prop "vendor.boot.vbmeta.device_state" "locked"
check_missing_match_prop "vendor.boot.verifiedbootstate" "green"
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

"#);
    content
}

fn generate_cleanup_residue_section() -> String {
    let mut content = String::new();
    content.push_str("# Cleanup tool residue\n");
    content.push_str(r#"
cleanup_path() {
    local path="$1"
    local desc="$2"
    
    if [ -n "$desc" ]; then
        echo "$(get_current_time): Cleanup: $path ($desc)" >> "$LOG_FILE"
    else
        echo "$(get_current_time): Cleanup: $path" >> "$LOG_FILE"
    fi
    
    if rm -rf "$path" 2>/dev/null; then
        echo "$(get_current_time): ✓ Cleaned: $path" >> "$LOG_FILE"
    else
        echo "$(get_current_time): ✗ Failed or not exists: $path" >> "$LOG_FILE"
    fi
}

echo "$(get_current_time): Starting cleanup" >> "$LOG_FILE"

cleanup_path "/data/local/stryker/" "Stryker residue"
cleanup_path "/data/system/AppRetention" "AppRetention residue"
cleanup_path "/data/local/tmp/luckys" "Lucky Tool residue"
cleanup_path "/data/local/tmp/HyperCeiler" "HyperCeiler residue"
cleanup_path "/data/local/tmp/simpleHook" "simple Hook residue"
cleanup_path "/data/local/tmp/DisabledAllGoogleServices" "Google services module residue"
cleanup_path "/data/local/MIO" "Unpack tool"
cleanup_path "/data/DNA" "Unpack tool"
cleanup_path "/data/local/tmp/cleaner_starter" "Texture cleanup residue"
cleanup_path "/data/local/tmp/byyang" ""
cleanup_path "/data/local/tmp/mount_mask" ""
cleanup_path "/data/local/tmp/mount_mark" ""
cleanup_path "/data/local/tmp/scriptTMP" ""
cleanup_path "/data/local/luckys" ""
cleanup_path "/data/local/tmp/horae_control.log" ""
cleanup_path "/data/gpu_freq_table.conf" ""
cleanup_path "/storage/emulated/0/Download/advanced/" ""
cleanup_path "/storage/emulated/0/Documents/advanced/" "Advanced settings"
cleanup_path "/storage/emulated/0/Android/naki/" "Old asoulopt"
cleanup_path "/data/swap_config.conf" "Scene addon module 2"
cleanup_path "/data/local/tmp/resetprop" ""
cleanup_path "/dev/cpuset/AppOpt/" "AppOpt module"
cleanup_path "/storage/emulated/0/Android/Clash/" "Clash for Magisk module"
cleanup_path "/storage/emulated/0/Android/Yume-Yunyun/" "NetEase cloud background optimization"
cleanup_path "/data/local/tmp/Surfing_update" "Surfing module cache"
cleanup_path "/data/encore/custom_default_cpu_gov" "encore module"
cleanup_path "/data/encore/default_cpu_gov" "encore module"
cleanup_path "/data/local/tmp/yshell" ""
cleanup_path "/data/local/tmp/encore_logo.png" ""
cleanup_path "/storage/emulated/legacy/" ""
cleanup_path "/storage/emulated/elgg/" ""
cleanup_path "/data/system/junge/" ""
cleanup_path "/data/local/tmp/mount_namespace" "Mount namespace residue"

echo "$(get_current_time): Cleanup completed" >> "$LOG_FILE"

"#);
    content
}
