use std::fmt::Write as FmtWrite;

#[allow(dead_code)]
const MODULE_ID: &str = "susfs_manager";
const MODULE_PATH: &str = "/data/adb/modules/susfs_manager";
const LOG_DIR: &str = "/data/adb/ksu/log";
const DEFAULT_UNAME: &str = "default";
const DEFAULT_BUILD_TIME: &str = "default";

#[allow(dead_code)]
fn get_current_time() -> String {
    use std::process::Command;
    let output = Command::new("date")
        .args(["+%Y-%m-%d %H:%M:%S"])
        .output()
        .ok();
    output
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map_or_else(|| "unknown".to_string(), |s| s.trim().to_string())
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ── script builders ─────────────────────────────────────────────────────────

fn log_setup(log_file_name: &str) -> String {
    format!(
        r#"LOG_DIR="{LOG_DIR}"
LOG_FILE="$LOG_DIR/{log_file_name}"

mkdir -p "$LOG_DIR"

get_current_time() {{
    date '+%Y-%m-%d %H:%M:%S'
}}
"#,
    )
}

fn binary_check() -> String {
    r#"# 检查ksud是否存在
if [ ! -f "/data/adb/ksud" ]; then
    echo "$(get_current_time): ksud未找到: /data/adb/ksud" >> "$LOG_FILE"
    exit 1
fi
"#
    .to_string()
}

fn module_prop() -> String {
    r"id=susfs_manager
name=SuSFS Manager
version=v4.0.0
versionCode=40000
author=ShirkNeko
description=SuSFS Manager Auto Configuration Module (自动生成请不要手动卸载或删除该模块! / Automatically generated Please do not manually uninstall or delete the module!)
updateJson=
"
    .to_string()
}

fn hide_bl_section() -> String {
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
"#
    .to_string()
}

fn hide_bl_props() -> String {
    r#"sleep 30
"$RESETPROP_BIN" -w sys.boot_completed 0
check_missing_prop "ro.boot.vbmeta.invalidate_on_error" "yes"
check_missing_match_prop "ro.boot.vbmeta.avb_version" "1.2"
check_missing_match_prop "ro.boot.vbmeta.hash_alg" "sha256"
check_missing_prop "ro.boot.vbmeta.size" "19968"
check_missing_match_prop "ro.boot.vbmeta.device_state" "locked"
check_missing_match_prop "ro.boot.verifiedbootstate" "green"
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
check_missing_match_prop "ro.boot.realmebootstate" "green"
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

fn cleanup_residue_section() -> String {
    let paths: Vec<(&str, &str)> = vec![
        ("/data/local/stryker/", "Stryker残留"),
        ("/data/system/AppRetention", "AppRetention残留"),
        ("/data/local/tmp/luckys", "Luck Tool残留"),
        ("/data/local/tmp/HyperCeiler", "西米露残留"),
        ("/data/local/tmp/simpleHook", "simple Hook残留"),
        (
            "/data/local/tmp/DisabledAllGoogleServices",
            "谷歌省电模块残留",
        ),
        ("/data/local/MIO", "解包软件"),
        ("/data/DNA", "解包软件"),
        ("/data/local/tmp/cleaner_starter", "质感清理残留"),
        ("/data/local/tmp/byyang", ""),
        ("/data/local/tmp/mount_mask", ""),
        ("/data/local/tmp/mount_mark", ""),
        ("/data/local/tmp/scriptTMP", ""),
        ("/data/local/luckys", ""),
        ("/data/local/tmp/horae_control.log", ""),
        ("/data/gpu_freq_table.conf", ""),
        ("/storage/emulated/0/Download/advanced/", ""),
        ("/storage/emulated/0/Documents/advanced/", "爱玩机"),
        ("/storage/emulated/0/Android/naki/", "旧版asoulopt"),
        ("/data/swap_config.conf", "scene附加模块2"),
        ("/data/local/tmp/resetprop", ""),
        ("/dev/cpuset/AppOpt/", "AppOpt模块"),
        ("/storage/emulated/0/Android/Clash/", "Clash for Magisk模块"),
        (
            "/storage/emulated/0/Android/Yume-Yunyun/",
            "网易云后台优化模块",
        ),
        ("/data/local/tmp/Surfing_update", "Surfing模块缓存"),
        ("/data/encore/custom_default_cpu_gov", "encore模块"),
        ("/data/encore/default_cpu_gov", "encore模块"),
        ("/data/local/tmp/yshell", ""),
        ("/data/local/tmp/encore_logo.png", ""),
        ("/storage/emulated/legacy/", ""),
        ("/storage/emulated/elgg/", ""),
        ("/data/system/junge/", ""),
        ("/data/local/tmp/mount_namespace", "挂载命名空间残留"),
    ];

    let total = paths.len();
    let mut lines = String::new();
    writeln!(
        lines,
        r#"# 清理工具残留文件
echo "$(get_current_time): 开始清理工具残留" >> "$LOG_FILE"

cleanup_path() {{
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
        echo "$(get_current_time): ✓ 成功清理: $path" >> "$LOG_FILE"
    else
        echo "$(get_current_time): ✗ 清理失败或不存在: $path" >> "$LOG_FILE"
    fi
}}

TOTAL={total}
"#,
    )
    .ok();

    for (i, (path, desc)) in paths.iter().enumerate() {
        writeln!(
            lines,
            "cleanup_path '{}' '{}' {} $TOTAL",
            path.replace('\'', "'\\''"),
            desc.replace('\'', "'\\''"),
            i + 1
        )
        .ok();
    }

    writeln!(
        lines,
        "\necho \"$(get_current_time): 工具残留清理完成\" >> \"$LOG_FILE\"\n"
    )
    .ok();

    lines
}

fn should_configure_in_service(
    sus_paths: &[String],
    sus_loop_paths: &[String],
    kstat_configs: &[String],
    add_kstat_paths: &[String],
    execute_in_post_fs_data: bool,
    uname_value: &str,
    build_time_value: &str,
) -> bool {
    !sus_paths.is_empty()
        || !sus_loop_paths.is_empty()
        || !kstat_configs.is_empty()
        || !add_kstat_paths.is_empty()
        || (!execute_in_post_fs_data
            && (uname_value != DEFAULT_UNAME || build_time_value != DEFAULT_BUILD_TIME))
}

// ── generate ─────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn generate_service_script(
    sus_paths: &[String],
    sus_loop_paths: &[String],
    _sus_maps: &[String],
    kstat_configs: &[String],
    add_kstat_paths: &[String],
    uname_value: &str,
    build_time_value: &str,
    execute_in_post_fs_data: bool,
    enable_log: bool,
    enable_hide_bl: bool,
    enable_cleanup_residue: bool,
) -> String {
    let mut s = String::new();

    s.push_str("#!/system/bin/sh\n");
    s.push_str("# SuSFS Service Script\n");
    s.push_str("# 在系统服务启动后执行\n\n");
    s.push_str(&log_setup("susfs_service.log"));
    s.push('\n');
    s.push_str(&binary_check());
    s.push_str("\n# ksud存在，继续执行\n\n");

    if should_configure_in_service(
        sus_paths,
        sus_loop_paths,
        kstat_configs,
        add_kstat_paths,
        execute_in_post_fs_data,
        uname_value,
        build_time_value,
    ) {
        if !sus_paths.is_empty() {
            s.push_str("\n# 添加SUS路径\n");
            s.push_str("until [ -d \"/sdcard/Android\" ]; do sleep 1; done\n");
            s.push_str("sleep 45\n");
            for path in sus_paths {
                writeln!(s, "/data/adb/ksud susfs add-sus-path {}", shell_quote(path)).ok();
                writeln!(
                    s,
                    "echo \"$(get_current_time): 添加SUS路径: {}\" >> \"$LOG_FILE\"",
                    path.replace('\'', "'\\''")
                )
                .ok();
            }
            s.push('\n');
        }

        // uname (non-post-fs-data)
        if !execute_in_post_fs_data
            && (uname_value != DEFAULT_UNAME || build_time_value != DEFAULT_BUILD_TIME)
        {
            s.push_str("# 设置uname和构建时间\n");
            writeln!(
                s,
                "/data/adb/ksud susfs set-uname {} {}",
                shell_quote(uname_value),
                shell_quote(build_time_value)
            )
            .ok();
            writeln!(
                s,
                "echo \"$(get_current_time): 设置uname为: {}, 构建时间为: {}\" >> \"$LOG_FILE\"",
                uname_value.replace('\'', "'\\''"),
                build_time_value.replace('\'', "'\\''")
            )
            .ok();
            s.push('\n');
        }

        // kstat
        if !add_kstat_paths.is_empty() {
            s.push_str("# 添加Kstat路径\n");
            for path in add_kstat_paths {
                writeln!(
                    s,
                    "/data/adb/ksud susfs add-sus-kstat {}",
                    shell_quote(path)
                )
                .ok();
                writeln!(
                    s,
                    "echo \"$(get_current_time): 添加Kstat路径: {}\" >> \"$LOG_FILE\"",
                    path.replace('\'', "'\\''")
                )
                .ok();
            }
            s.push('\n');
        }

        if !kstat_configs.is_empty() {
            s.push_str("# 添加Kstat静态配置\n");
            for config in kstat_configs {
                let parts: Vec<&str> = config.split('|').collect();
                if parts.len() >= 13 {
                    let path = parts[0];
                    let params = parts[1..].join("' '");
                    writeln!(
                        s,
                        "/data/adb/ksud susfs add-sus-kstat-statically {} '{}'",
                        shell_quote(path),
                        params
                    )
                    .ok();
                    writeln!(
                        s,
                        "echo \"$(get_current_time): 添加Kstat静态配置: {}\" >> \"$LOG_FILE\"",
                        path.replace('\'', "'\\''")
                    )
                    .ok();
                    writeln!(
                        s,
                        "/data/adb/ksud susfs update-sus-kstat {}",
                        shell_quote(path)
                    )
                    .ok();
                    writeln!(
                        s,
                        "echo \"$(get_current_time): 更新Kstat配置: {}\" >> \"$LOG_FILE\"",
                        path.replace('\'', "'\\''")
                    )
                    .ok();
                }
            }
            s.push('\n');
        }
    }

    // enable log
    let log_val: u32 = u32::from(enable_log);
    writeln!(
        s,
        "# 设置日志启用状态\n/data/adb/ksud susfs enable-log {log_val}\n",
    )
    .ok();
    writeln!(
        s,
        "echo \"$(get_current_time): 日志功能设置为: {}\" >> \"$LOG_FILE\"\n",
        if enable_log { "启用" } else { "禁用" }
    )
    .ok();

    // hide bl
    if enable_hide_bl {
        s.push_str("\n# 隐藏BL\n");
        s.push_str(&hide_bl_section());
        s.push('\n');
        s.push_str(&hide_bl_props());
        s.push('\n');
    }

    // cleanup residue
    if enable_cleanup_residue {
        s.push_str(&cleanup_residue_section());
    }

    writeln!(
        s,
        "echo \"$(get_current_time): Service脚本执行完成\" >> \"$LOG_FILE\""
    )
    .ok();

    s
}

fn generate_post_fs_data_script(
    uname_value: &str,
    build_time_value: &str,
    execute_in_post_fs_data: bool,
    enable_avc_log_spoofing: bool,
) -> String {
    let mut s = String::new();

    s.push_str("#!/system/bin/sh\n");
    s.push_str("# SuSFS Post-FS-Data Script\n");
    s.push_str("# 在文件系统挂载后但在系统完全启动前执行\n\n");
    s.push_str(&log_setup("susfs_post_fs_data.log"));
    s.push('\n');
    s.push_str(&binary_check());
    s.push('\n');
    writeln!(
        s,
        "echo \"$(get_current_time): Post-FS-Data脚本开始执行\" >> \"$LOG_FILE\"\n"
    )
    .ok();

    if execute_in_post_fs_data
        && (uname_value != DEFAULT_UNAME || build_time_value != DEFAULT_BUILD_TIME)
    {
        s.push_str("# 设置uname和构建时间\n");
        writeln!(
            s,
            "/data/adb/ksud susfs set-uname {} {}",
            shell_quote(uname_value),
            shell_quote(build_time_value)
        )
        .ok();
        writeln!(
            s,
            "echo \"$(get_current_time): 设置uname为: {}, 构建时间为: {}\" >> \"$LOG_FILE\"",
            uname_value.replace('\'', "'\\''"),
            build_time_value.replace('\'', "'\\''")
        )
        .ok();
        s.push('\n');
    }

    let avc_val: u32 = u32::from(enable_avc_log_spoofing);
    writeln!(
        s,
        "# 设置AVC日志欺骗状态\n/data/adb/ksud susfs enable-avc-log-spoofing {avc_val}\n",
    )
    .ok();
    writeln!(
        s,
        "echo \"$(get_current_time): AVC日志欺骗功能设置为: {}\" >> \"$LOG_FILE\"\n",
        if enable_avc_log_spoofing {
            "启用"
        } else {
            "禁用"
        }
    )
    .ok();

    writeln!(
        s,
        "echo \"$(get_current_time): Post-FS-Data脚本执行完成\" >> \"$LOG_FILE\""
    )
    .ok();

    s
}

fn generate_post_mount_script() -> String {
    let mut s = String::new();
    s.push_str("#!/system/bin/sh\n");
    s.push_str("# SuSFS Post-Mount Script\n");
    s.push_str("# 在所有分区挂载完成后执行\n\n");
    s.push_str(&log_setup("susfs_post_mount.log"));
    s.push('\n');
    writeln!(
        s,
        "echo \"$(get_current_time): Post-Mount脚本开始执行\" >> \"$LOG_FILE\"\n"
    )
    .ok();
    s.push_str(&binary_check());
    s.push('\n');
    writeln!(
        s,
        "echo \"$(get_current_time): Post-Mount脚本执行完成\" >> \"$LOG_FILE\""
    )
    .ok();
    s
}

fn generate_boot_completed_script(
    hide_sus_mounts_for_all_procs: bool,
    sus_paths: &[String],
    sus_loop_paths: &[String],
    sus_maps: &[String],
) -> String {
    let mut s = String::new();

    s.push_str("#!/system/bin/sh\n");
    s.push_str("# SuSFS Boot-Completed Script\n");
    s.push_str("# 在系统完全启动后执行\n\n");
    s.push_str(&log_setup("susfs_boot_completed.log"));
    s.push('\n');
    writeln!(
        s,
        "echo \"$(get_current_time): Boot-Completed脚本开始执行\" >> \"$LOG_FILE\"\n"
    )
    .ok();
    s.push_str(&binary_check());
    s.push('\n');

    let hide_val: u32 = u32::from(hide_sus_mounts_for_all_procs);
    writeln!(
        s,
        "# 设置SUS挂载隐藏控制\n/data/adb/ksud susfs hide-sus-mnts-for-non-su-procs {hide_val}\n",
    )
    .ok();
    writeln!(
        s,
        "echo \"$(get_current_time): SUS挂载隐藏控制设置为: {}\" >> \"$LOG_FILE\"\n",
        if hide_sus_mounts_for_all_procs {
            "对所有进程隐藏"
        } else {
            "仅对非KSU进程隐藏"
        }
    )
    .ok();

    if !sus_paths.is_empty() {
        s.push_str("# 添加SUS路径\n");
        for path in sus_paths {
            writeln!(s, "/data/adb/ksud susfs add-sus-path {}", shell_quote(path)).ok();
            writeln!(
                s,
                "echo \"$(get_current_time): 添加SUS路径: {}\" >> \"$LOG_FILE\"",
                path.replace('\'', "'\\''")
            )
            .ok();
        }
        s.push('\n');
    }

    if !sus_loop_paths.is_empty() {
        s.push_str("# 添加SUS循环路径\n");
        for path in sus_loop_paths {
            writeln!(
                s,
                "/data/adb/ksud susfs add-sus-path-loop {}",
                shell_quote(path)
            )
            .ok();
            writeln!(
                s,
                "echo \"$(get_current_time): 添加SUS循环路径: {}\" >> \"$LOG_FILE\"",
                path.replace('\'', "'\\''")
            )
            .ok();
        }
        s.push('\n');
    }

    if !sus_maps.is_empty() {
        s.push_str("# 添加SUS映射\n");
        for map in sus_maps {
            writeln!(s, "/data/adb/ksud susfs add-sus-map {}", shell_quote(map)).ok();
            writeln!(
                s,
                "echo \"$(get_current_time): 添加SUS映射: {}\" >> \"$LOG_FILE\"",
                map.replace('\'', "'\\''")
            )
            .ok();
        }
        s.push('\n');
    }

    writeln!(
        s,
        "echo \"$(get_current_time): Boot-Completed脚本执行完成\" >> \"$LOG_FILE\""
    )
    .ok();

    s
}

use crate::susfs_config::ModuleConfig;

pub fn install_module() -> anyhow::Result<()> {
    use crate::susfs_config::load_module_config;
    let config = load_module_config()?;
    install_module_with_config(&config)
}

fn install_module_with_config(config: &ModuleConfig) -> anyhow::Result<()> {
    use std::process::Command;

    let module_path = MODULE_PATH;

    // Create module directory
    let out = Command::new("sh")
        .args(["-c", &format!("mkdir -p {module_path}")])
        .output()?;
    if !out.status.success() {
        anyhow::bail!("Failed to create module directory");
    }

    // Write module.prop
    let prop_content = module_prop();
    let out = Command::new("sh")
        .args([
            "-c",
            &format!("cat > {module_path}/module.prop << 'KSUEOF'\n{prop_content}\nKSUEOF"),
        ])
        .output()?;
    if !out.status.success() {
        anyhow::bail!("Failed to write module.prop");
    }

    let scripts = [
        (
            "service.sh",
            generate_service_script(
                &config.sus_paths,
                &config.sus_loop_paths,
                &config.sus_maps,
                &config.kstat_configs,
                &config.add_kstat_paths,
                &config.uname_value,
                &config.build_time_value,
                config.execute_in_post_fs_data,
                config.enable_log,
                config.enable_hide_bl,
                config.enable_cleanup_residue,
            ),
        ),
        (
            "post-fs-data.sh",
            generate_post_fs_data_script(
                &config.uname_value,
                &config.build_time_value,
                config.execute_in_post_fs_data,
                config.enable_avc_log_spoofing,
            ),
        ),
        ("post-mount.sh", generate_post_mount_script()),
        (
            "boot-completed.sh",
            generate_boot_completed_script(
                config.hide_sus_mounts_for_all_procs,
                &config.sus_paths,
                &config.sus_loop_paths,
                &config.sus_maps,
            ),
        ),
    ];

    for (name, content) in &scripts {
        let script_path = format!("{module_path}/{name}");
        let out = Command::new("sh")
            .args([
                "-c",
                &format!(
                    "cat > '{script_path}' << 'KSUEOF'\n{content}\nKSUEOF\nchmod 755 '{script_path}'"
                ),
            ])
            .output()?;
        if !out.status.success() {
            anyhow::bail!(
                "Failed to write {}: {}",
                name,
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    Ok(())
}

pub fn remove_module() -> anyhow::Result<()> {
    use std::process::Command;

    let out = Command::new("sh")
        .args(["-c", &format!("rm -rf {MODULE_PATH}")])
        .output()?;
    if !out.status.success() {
        anyhow::bail!(
            "Failed to remove module: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

pub fn is_module_installed() -> bool {
    use std::process::Command;
    Command::new("sh")
        .args([
            "-c",
            &format!("test -f {MODULE_PATH}/module.prop && echo yes || echo no"),
        ])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("yes"))
}
