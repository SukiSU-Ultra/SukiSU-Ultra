use crate::susfs_config::SusfsConfig;
use anyhow::{Context, Result};
use std::fmt::Write;
use std::fs;
use std::path::Path;

#[allow(dead_code)]
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

#[allow(dead_code)]
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
    let content = "id=susfs_manager\n\
name=SuSFS Manager\n\
version=v4.0.0\n\
versionCode=40000\n\
author=ShirkNeko\n\
description=SuSFS Manager Auto Configuration Module (Automatically generated. Do not manually uninstall or delete this module!)\n\
updateJson=\n";
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
    fs::write(&path, content).with_context(|| format!("Failed to write {filename}"))?;

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
    format!(
        "# Log setup\n\
LOG_DIR=\"{LOG_DIR}\"\n\
LOG_FILE=\"$LOG_DIR/susfs_service.log\"\n\
\n\
mkdir -p \"$LOG_DIR\"\n\
\n\
get_current_time() {{\n\
    date '+%Y-%m-%d %H:%M:%S'\n\
}}\n"
    )
}

fn get_binary_check() -> String {
    String::from(
        "# Check SuSFS binary\n\
SUSFS_BIN=\"/data/adb/ksu/bin/ksu_susfs\"\n\
if [ ! -f \"$SUSFS_BIN\" ]; then\n\
    SUSFS_BIN=\"/data/adb/ksud/ksu_susfs\"\n\
fi\n\
if [ ! -f \"$SUSFS_BIN\" ]; then\n\
    echo \"$(get_current_time): SuSFS binary not found\" >> \"$LOG_FILE\"\n\
    exit 1\n\
fi\n",
    )
}

fn create_service_sh(config: &SusfsConfig) -> Result<()> {
    let mut content = String::new();
    content.push_str("#!/system/bin/sh\n");
    content.push_str("# SuSFS Service Script\n");
    content.push_str("# Execute after system services start\n\n");
    content.push_str(&get_log_setup());
    content.push('\n');
    content.push_str(&get_binary_check());
    content.push('\n');
    content.push_str("echo \"$(get_current_time): Service script started\" >> \"$LOG_FILE\"\n\n");

    if config.has_auto_start_config() {
        if !config.sus_paths.is_empty() {
            content.push_str("# Add SUS paths\n");
            content.push_str("until [ -d \"/sdcard/Android\" ]; do sleep 1; done\n");
            content.push_str("sleep 45\n");
            for path in &config.sus_paths {
                let _ = write!(content, "\"{}\" add_sus_path '{path}'\n", "$SUSFS_BIN");
                let _ = write!(
                    content,
                    "echo \"$(get_current_time): Add SUS path: {path}\" >> \"$LOG_FILE\"\n"
                );
            }
            content.push('\n');
        }

        if !config.sus_loop_paths.is_empty() {
            content.push_str("# Add SUS loop paths\n");
            for path in &config.sus_loop_paths {
                let _ = write!(content, "\"{}\" add_sus_path_loop '{path}'\n", "$SUSFS_BIN");
                let _ = write!(
                    content,
                    "echo \"$(get_current_time): Add SUS loop path: {path}\" >> \"$LOG_FILE\"\n"
                );
            }
            content.push('\n');
        }

        if !config.execute_in_post_fs_data
            && (config.uname_value != "default" || config.build_time_value != "default")
        {
            content.push_str("# Set uname and build time\n");
            let _ = write!(
                content,
                "\"{}\" set_uname '{}' '{}'\n",
                "$SUSFS_BIN", config.uname_value, config.build_time_value
            );
            let _ = write!(
                content,
                "echo \"$(get_current_time): Set uname: {}, build time: {}\" >> \"$LOG_FILE\"\n",
                config.uname_value, config.build_time_value
            );
            content.push('\n');
        }

        if !config.add_kstat_paths.is_empty() {
            content.push_str("# Add Kstat paths\n");
            for path in &config.add_kstat_paths {
                let _ = write!(content, "\"{}\" add_sus_kstat '{path}'\n", "$SUSFS_BIN");
                let _ = write!(
                    content,
                    "echo \"$(get_current_time): Add Kstat path: {path}\" >> \"$LOG_FILE\"\n"
                );
            }
            content.push('\n');
        }

        if !config.kstat_configs.is_empty() {
            content.push_str("# Add Kstat static configs\n");
            for config_str in &config.kstat_configs {
                let parts: Vec<&str> = config_str.split('|').collect();
                if parts.len() >= 13 {
                    let path = parts[0];
                    let params = parts[1..].join("' '");
                    let _ = write!(
                        content,
                        "\"{}\" add_sus_kstat_statically '{}' '{}'\n",
                        "$SUSFS_BIN", path, params
                    );
                    let _ = write!(
                        content,
                        "echo \"$(get_current_time): Add Kstat static config: {path}\" >> \"$LOG_FILE\"\n"
                    );
                    let _ = write!(content, "\"{}\" update_sus_kstat '{path}'\n", "$SUSFS_BIN");
                    let _ = write!(
                        content,
                        "echo \"$(get_current_time): Update Kstat config: {path}\" >> \"$LOG_FILE\"\n"
                    );
                }
            }
            content.push('\n');
        }
    }

    content.push_str("# Enable log\n");
    let _ = write!(
        content,
        "\"{}\" enable_log {}\n",
        "$SUSFS_BIN",
        i32::from(config.enable_log)
    );
    let _ = write!(
        content,
        "echo \"$(get_current_time): Log enabled: {}\" >> \"$LOG_FILE\"\n",
        config.enable_log
    );
    content.push('\n');

    if config.enable_hide_bl {
        content.push_str(&generate_hide_bl_section());
    }

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
    content.push('\n');
    content.push_str(&get_binary_check());
    content.push('\n');
    content
        .push_str("echo \"$(get_current_time): Post-FS-Data script started\" >> \"$LOG_FILE\"\n\n");

    if config.execute_in_post_fs_data
        && (config.uname_value != "default" || config.build_time_value != "default")
    {
        content.push_str("# Set uname and build time\n");
        let _ = write!(
            content,
            "\"{}\" set_uname '{}' '{}'\n",
            "$SUSFS_BIN", config.uname_value, config.build_time_value
        );
        let _ = write!(
            content,
            "echo \"$(get_current_time): Set uname: {}, build time: {}\" >> \"$LOG_FILE\"\n",
            config.uname_value, config.build_time_value
        );
        content.push('\n');
    }

    content.push_str("# Enable AVC log spoofing\n");
    let _ = write!(
        content,
        "\"{}\" enable_avc_log_spoofing {}\n",
        "$SUSFS_BIN",
        i32::from(config.enable_avc_log_spoofing)
    );
    let _ = write!(
        content,
        "echo \"$(get_current_time): AVC log spoofing: {}\" >> \"$LOG_FILE\"\n",
        config.enable_avc_log_spoofing
    );
    content.push('\n');

    content
        .push_str("echo \"$(get_current_time): Post-FS-Data script completed\" >> \"$LOG_FILE\"\n");

    write_script("post-fs-data.sh", &content)
}

#[allow(unused_variables)]
fn create_post_mount_sh(config: &SusfsConfig) -> Result<()> {
    let mut content = String::new();
    content.push_str("#!/system/bin/sh\n");
    content.push_str("# SuSFS Post-Mount Script\n");
    content.push_str("# Execute after all partitions are mounted\n\n");
    content.push_str(&get_log_setup());
    content.push('\n');
    content
        .push_str("echo \"$(get_current_time): Post-Mount script started\" >> \"$LOG_FILE\"\n\n");
    content.push_str(&get_binary_check());
    content.push('\n');
    content
        .push_str("echo \"$(get_current_time): Post-Mount script completed\" >> \"$LOG_FILE\"\n");

    write_script("post-mount.sh", &content)
}

fn create_boot_completed_sh(config: &SusfsConfig) -> Result<()> {
    let mut content = String::new();
    content.push_str("#!/system/bin/sh\n");
    content.push_str("# SuSFS Boot-Completed Script\n");
    content.push_str("# Execute after system fully starts\n\n");
    content.push_str(&get_log_setup());
    content.push('\n');
    content.push_str(
        "echo \"$(get_current_time): Boot-Completed script started\" >> \"$LOG_FILE\"\n\n",
    );
    content.push_str(&get_binary_check());
    content.push('\n');

    content.push_str("# Hide SUS mounts\n");
    let _ = write!(
        content,
        "\"{}\" hide_sus_mnts_for_non_su_procs {}\n",
        "$SUSFS_BIN",
        i32::from(config.hide_sus_mounts_for_all_procs)
    );
    let _ = write!(
        content,
        "echo \"$(get_current_time): Hide SUS mounts: {}\" >> \"$LOG_FILE\"\n",
        if config.hide_sus_mounts_for_all_procs {
            "all processes"
        } else {
            "non-KSU processes only"
        }
    );
    content.push('\n');

    if !config.sus_maps.is_empty() {
        content.push_str("# Add SUS maps\n");
        for map in &config.sus_maps {
            let _ = write!(content, "\"{}\" add_sus_map '{map}'\n", "$SUSFS_BIN");
            let _ = write!(
                content,
                "echo \"$(get_current_time): Add SUS map: {map}\" >> \"$LOG_FILE\"\n"
            );
        }
        content.push('\n');
    }

    content.push_str(
        "echo \"$(get_current_time): Boot-Completed script completed\" >> \"$LOG_FILE\"\n",
    );

    write_script("boot-completed.sh", &content)
}

fn generate_hide_bl_section() -> String {
    String::from(
        "# Hide bootloader from Shamiko script\n\
RESETPROP_BIN=\"/data/adb/ksu/bin/resetprop\"\n\
\n\
check_reset_prop() {\n\
    local NAME=$1\n\
    local EXPECTED=$2\n\
    local VALUE=$(\"$RESETPROP_BIN\" $NAME)\n\
    [ -z \"$VALUE\" ] || [ \"$VALUE\" = \"$EXPECTED\" ] || \"$RESETPROP_BIN\" $NAME $EXPECTED\n\
}\n\
\n\
check_missing_prop() {\n\
    local NAME=$1\n\
    local EXPECTED=$2\n\
    local VALUE=$(\"$RESETPROP_BIN\" $NAME)\n\
    [ -z \"$VALUE\" ] && \"$RESETPROP_BIN\" $NAME $EXPECTED\n\
}\n\
\n\
check_missing_match_prop() {\n\
    local NAME=$1\n\
    local EXPECTED=$2\n\
    local VALUE=$(\"$RESETPROP_BIN\" $NAME)\n\
    [ -z \"$VALUE\" ] || [ \"$VALUE\" = \"$EXPECTED\" ] || \"$RESETPROP_BIN\" $NAME $EXPECTED\n\
    [ -z \"$VALUE\" ] && \"$RESETPROP_BIN\" $NAME $EXPECTED\n\
}\n\
\n\
contains_reset_prop() {\n\
    local NAME=$1\n\
    local CONTAINS=$2\n\
    local NEWVAL=$3\n\
    case \"$(\"$RESETPROP_BIN\" $NAME)\" in\n\
        *\"$CONTAINS\"*) \"$RESETPROP_BIN\" $NAME $NEWVAL ;;\n\
    esac\n\
}\n\
\n\
sleep 30\n\
\n\
\"$RESETPROP_BIN\" -w sys.boot_completed 0\n\
\n\
check_missing_match_prop \"ro.boot.vbmeta.invalidate_on_error\" \"yes\"\n\
check_missing_match_prop \"ro.boot.vbmeta.avb_version\" \"1.2\"\n\
check_missing_match_prop \"ro.boot.vbmeta.hash_alg\" \"sha256\"\n\
check_missing_match_prop \"ro.boot.vbmeta.size\" \"19968\"\n\
check_missing_match_prop \"ro.boot.vbmeta.device_state\" \"locked\"\n\
check_reset_prop \"ro.boot.verifiedbootstate\" \"green\"\n\
check_reset_prop \"ro.boot.flash.locked\" \"1\"\n\
check_reset_prop \"ro.boot.veritymode\" \"enforcing\"\n\
check_reset_prop \"ro.boot.warranty_bit\" \"0\"\n\
check_reset_prop \"ro.warranty_bit\" \"0\"\n\
check_reset_prop \"ro.debuggable\" \"0\"\n\
check_reset_prop \"ro.force.debuggable\" \"0\"\n\
check_reset_prop \"ro.secure\" \"1\"\n\
check_reset_prop \"ro.adb.secure\" \"1\"\n\
check_reset_prop \"ro.build.type\" \"user\"\n\
check_reset_prop \"ro.build.tags\" \"release-keys\"\n\
check_reset_prop \"ro.vendor.boot.warranty_bit\" \"0\"\n\
check_reset_prop \"ro.vendor.warranty_bit\" \"0\"\n\
check_missing_match_prop \"vendor.boot.vbmeta.device_state\" \"locked\"\n\
check_missing_match_prop \"vendor.boot.verifiedbootstate\" \"green\"\n\
check_reset_prop \"sys.oem_unlock_allowed\" \"0\"\n\
check_reset_prop \"ro.secureboot.lockstate\" \"locked\"\n\
check_reset_prop \"ro.boot.realmebootstate\" \"green\"\n\
check_reset_prop \"ro.boot.realme.lockstate\" \"1\"\n\
check_reset_prop \"ro.crypto.state\" \"encrypted\"\n\
\n\
# Hide adb debugging traces\n\
resetprop \"sys.usb.adb.disabled\" \" \"\n\
\n\
# Hide recovery boot mode\n\
contains_reset_prop \"ro.bootmode\" \"recovery\" \"unknown\"\n\
contains_reset_prop \"ro.boot.bootmode\" \"recovery\" \"unknown\"\n\
contains_reset_prop \"vendor.boot.bootmode\" \"recovery\" \"unknown\"\n\
\n\
# Hide cloudphone detection\n\
[ -n \"$(resetprop ro.kernel.qemu)\" ] && resetprop ro.kernel.qemu \"\"\n",
    )
}

fn generate_cleanup_residue_section() -> String {
    String::from(
        "# Cleanup tool residue\n\
cleanup_path() {\n\
    local path=\"$1\"\n\
    local desc=\"$2\"\n\
    \n\
    if [ -n \"$desc\" ]; then\n\
        echo \"$(get_current_time): Cleanup: $path ($desc)\" >> \"$LOG_FILE\"\n\
    else\n\
        echo \"$(get_current_time): Cleanup: $path\" >> \"$LOG_FILE\"\n\
    fi\n\
    \n\
    if rm -rf \"$path\" 2>/dev/null; then\n\
        echo \"$(get_current_time): Cleaned: $path\" >> \"$LOG_FILE\"\n\
    else\n\
        echo \"$(get_current_time): Failed or not exists: $path\" >> \"$LOG_FILE\"\n\
    fi\n\
}\n\
\n\
echo \"$(get_current_time): Starting cleanup\" >> \"$LOG_FILE\"\n\
\n\
cleanup_path \"/data/local/stryker/\" \"Stryker residue\"\n\
cleanup_path \"/data/system/AppRetention\" \"AppRetention residue\"\n\
cleanup_path \"/data/local/tmp/luckys\" \"Lucky Tool residue\"\n\
cleanup_path \"/data/local/tmp/HyperCeiler\" \"HyperCeiler residue\"\n\
cleanup_path \"/data/local/tmp/simpleHook\" \"simple Hook residue\"\n\
cleanup_path \"/data/local/tmp/DisabledAllGoogleServices\" \"Google services module residue\"\n\
cleanup_path \"/data/local/MIO\" \"Unpack tool\"\n\
cleanup_path \"/data/DNA\" \"Unpack tool\"\n\
cleanup_path \"/data/local/tmp/cleaner_starter\" \"Texture cleanup residue\"\n\
cleanup_path \"/data/local/tmp/byyang\" \"\"\n\
cleanup_path \"/data/local/tmp/mount_mask\" \"\"\n\
cleanup_path \"/data/local/tmp/mount_mark\" \"\"\n\
cleanup_path \"/data/local/tmp/scriptTMP\" \"\"\n\
cleanup_path \"/data/local/luckys\" \"\"\n\
cleanup_path \"/data/local/tmp/horae_control.log\" \"\"\n\
cleanup_path \"/data/gpu_freq_table.conf\" \"\"\n\
cleanup_path \"/storage/emulated/0/Download/advanced/\" \"\"\n\
cleanup_path \"/storage/emulated/0/Documents/advanced/\" \"Advanced settings\"\n\
cleanup_path \"/storage/emulated/0/Android/naki/\" \"Old asoulopt\"\n\
cleanup_path \"/data/swap_config.conf\" \"Scene addon module 2\"\n\
cleanup_path \"/data/local/tmp/resetprop\" \"\"\n\
cleanup_path \"/dev/cpuset/AppOpt/\" \"AppOpt module\"\n\
cleanup_path \"/storage/emulated/0/Android/Clash/\" \"Clash for Magisk module\"\n\
cleanup_path \"/storage/emulated/0/Android/Yume-Yunyun/\" \"NetEase cloud background optimization\"\n\
cleanup_path \"/data/local/tmp/Surfing_update\" \"Surfing module cache\"\n\
cleanup_path \"/data/encore/custom_default_cpu_gov\" \"encore module\"\n\
cleanup_path \"/data/encore/default_cpu_gov\" \"encore module\"\n\
cleanup_path \"/data/local/tmp/yshell\" \"\"\n\
cleanup_path \"/data/local/tmp/encore_logo.png\" \"\"\n\
cleanup_path \"/storage/emulated/legacy/\" \"\"\n\
cleanup_path \"/storage/emulated/elgg/\" \"\"\n\
cleanup_path \"/data/system/junge/\" \"\"\n\
cleanup_path \"/data/local/tmp/mount_namespace\" \"Mount namespace residue\"\n\
\n\
echo \"$(get_current_time): Cleanup completed\" >> \"$LOG_FILE\"\n",
    )
}
