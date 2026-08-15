//! Full per-stage script generators.
//!
//! Each public function in this module assembles one of the four
//! boot-stage scripts (`service.sh`, `post-fs-data.sh`,
//! `post-mount.sh`, `boot-completed.sh`) by composing snippets from
//! the other [`super`] files together with `ModuleConfig` data.

use std::fmt::Write as FmtWrite;

use crate::susfs_module::consts::{DEFAULT_BUILD_TIME, DEFAULT_UNAME, shell_quote};
use crate::susfs_module::scripts::{cleanup, hide_bl, prelude};

/// Return `true` when [`generate_service_script`] has at least one SuSFS
/// setting to apply at service time.
///
/// `execute_in_post_fs_data` is honored here so the same condition can be
/// used for the "uname / build_time" branch.
#[allow(clippy::too_many_arguments)]
fn should_configure_in_service(
    sus_paths: &[String],
    sus_loop_paths: &[String],
    kstat_configs: &[String],
    add_kstat_paths: &[String],
    cmdline_or_bootconfig_path: &str,
    execute_in_post_fs_data: bool,
    uname_value: &str,
    build_time_value: &str,
) -> bool {
    !sus_paths.is_empty()
        || !sus_loop_paths.is_empty()
        || !kstat_configs.is_empty()
        || !add_kstat_paths.is_empty()
        || !cmdline_or_bootconfig_path.is_empty()
        || (!execute_in_post_fs_data
            && (uname_value != DEFAULT_UNAME || build_time_value != DEFAULT_BUILD_TIME))
}

/// `service.sh` — runs once the system services are up.
///
/// Most `ksud susfs …` calls land here because `/sdcard` and the
/// non-system partitions aren't mounted early enough for the post-fs-data
/// phase to be useful.
#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
pub fn service(
    sus_paths: &[String],
    sus_loop_paths: &[String],
    _sus_maps: &[String],
    kstat_configs: &[String],
    add_kstat_paths: &[String],
    cmdline_or_bootconfig_path: &str,
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
    s.push_str(&prelude::log_setup("susfs_service.log"));
    s.push('\n');
    s.push_str(&prelude::binary_check());
    s.push_str("\n# ksud存在，继续执行\n\n");

    if should_configure_in_service(
        sus_paths,
        sus_loop_paths,
        kstat_configs,
        add_kstat_paths,
        cmdline_or_bootconfig_path,
        execute_in_post_fs_data,
        uname_value,
        build_time_value,
    ) {
        if !sus_paths.is_empty() {
            s.push_str("\n# 添加SUS路径\n");
            s.push_str("until [ -d \"/sdcard/Android\" ]; do sleep 1; done\n");
            s.push_str("sleep 45\n");
            for path in sus_paths {
                let _ = writeln!(s, "/data/adb/ksud susfs add-sus-path {}", shell_quote(path));
                let _ = writeln!(
                    s,
                    "echo \"$(get_current_time): 添加SUS路径: {}\" >> \"$LOG_FILE\"",
                    path.replace('\'', "'\\''")
                );
            }
            s.push('\n');
        }

        // uname (non-post-fs-data)
        if !execute_in_post_fs_data
            && (uname_value != DEFAULT_UNAME || build_time_value != DEFAULT_BUILD_TIME)
        {
            s.push_str("# 设置uname和构建时间\n");
            let _ = writeln!(
                s,
                "/data/adb/ksud susfs set-uname {} {}",
                shell_quote(uname_value),
                shell_quote(build_time_value)
            );
            let _ = writeln!(
                s,
                "echo \"$(get_current_time): 设置uname为: {}, 构建时间为: {}\" >> \"$LOG_FILE\"",
                uname_value.replace('\'', "'\\''"),
                build_time_value.replace('\'', "'\\''")
            );
            s.push('\n');
        }

        // kstat
        if !add_kstat_paths.is_empty() {
            s.push_str("# 添加Kstat路径\n");
            for path in add_kstat_paths {
                let _ = writeln!(
                    s,
                    "/data/adb/ksud susfs add-sus-kstat {}",
                    shell_quote(path)
                );
                let _ = writeln!(
                    s,
                    "echo \"$(get_current_time): 添加Kstat路径: {}\" >> \"$LOG_FILE\"",
                    path.replace('\'', "'\\''")
                );
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
                    let _ = writeln!(
                        s,
                        "/data/adb/ksud susfs add-sus-kstat-statically {} '{}'",
                        shell_quote(path),
                        params
                    );
                    let _ = writeln!(
                        s,
                        "echo \"$(get_current_time): 添加Kstat静态配置: {}\" >> \"$LOG_FILE\"",
                        path.replace('\'', "'\\''")
                    );
                    let _ = writeln!(
                        s,
                        "/data/adb/ksud susfs update-sus-kstat {}",
                        shell_quote(path)
                    );
                    let _ = writeln!(
                        s,
                        "echo \"$(get_current_time): 更新Kstat配置: {}\" >> \"$LOG_FILE\"",
                        path.replace('\'', "'\\''")
                    );
                }
            }
            s.push('\n');
        }

        // cmdline / bootconfig spoof — only emit when the user actually
        // picked a file via the SAF picker.
        if !cmdline_or_bootconfig_path.is_empty() {
            s.push_str("\n# 替换 cmdline / bootconfig\n");
            let quoted = shell_quote(cmdline_or_bootconfig_path);
            let _ = writeln!(
                s,
                "if [ -f {quoted} ]; then\n  /data/adb/ksud susfs set-cmdline-or-bootconfig {quoted}\nelse\n  echo \"$(get_current_time): 指定的cmdline/bootconfig文件不存在: {escaped}\" >> \"$LOG_FILE\"\nfi",
                quoted = quoted,
                escaped = cmdline_or_bootconfig_path.replace('\'', "'\\''")
            );
            let _ = writeln!(
                s,
                "echo \"$(get_current_time): 应用 cmdline/bootconfig 文件: {}\" >> \"$LOG_FILE\"",
                cmdline_or_bootconfig_path.replace('\'', "'\\''")
            );
            s.push('\n');
        }
    }

    // enable log
    let log_val: u32 = u32::from(enable_log);
    let _ = writeln!(
        s,
        "# 设置日志启用状态\n/data/adb/ksud susfs enable-log {log_val}\n",
    );
    let _ = writeln!(
        s,
        "echo \"$(get_current_time): 日志功能设置为: {}\" >> \"$LOG_FILE\"\n",
        if enable_log { "启用" } else { "禁用" }
    );

    // hide bl
    if enable_hide_bl {
        s.push_str("\n# 隐藏BL\n");
        s.push_str(&hide_bl::hide_bl_section());
        s.push('\n');
        s.push_str(&hide_bl::hide_bl_props());
        s.push('\n');
    }

    // cleanup residue
    if enable_cleanup_residue {
        s.push_str(&cleanup::cleanup_residue_section());
    }

    let _ = writeln!(
        s,
        "echo \"$(get_current_time): Service脚本执行完成\" >> \"$LOG_FILE\""
    );

    s
}

/// `post-fs-data.sh` — runs after `/data` is mounted but before services
/// start; the only thing SuSFS actually wants this early is `uname`.
pub fn post_fs_data(
    uname_value: &str,
    build_time_value: &str,
    execute_in_post_fs_data: bool,
    enable_avc_log_spoofing: bool,
) -> String {
    let mut s = String::new();

    s.push_str("#!/system/bin/sh\n");
    s.push_str("# SuSFS Post-FS-Data Script\n");
    s.push_str("# 在文件系统挂载后但在系统完全启动前执行\n\n");
    s.push_str(&prelude::log_setup("susfs_post_fs_data.log"));
    s.push('\n');
    s.push_str(&prelude::binary_check());
    s.push('\n');
    let _ = writeln!(
        s,
        "echo \"$(get_current_time): Post-FS-Data脚本开始执行\" >> \"$LOG_FILE\"\n"
    );

    if execute_in_post_fs_data
        && (uname_value != DEFAULT_UNAME || build_time_value != DEFAULT_BUILD_TIME)
    {
        s.push_str("# 设置uname和构建时间\n");
        let _ = writeln!(
            s,
            "/data/adb/ksud susfs set-uname {} {}",
            shell_quote(uname_value),
            shell_quote(build_time_value)
        );
        let _ = writeln!(
            s,
            "echo \"$(get_current_time): 设置uname为: {}, 构建时间为: {}\" >> \"$LOG_FILE\"",
            uname_value.replace('\'', "'\\''"),
            build_time_value.replace('\'', "'\\''")
        );
        s.push('\n');
    }

    let avc_val: u32 = u32::from(enable_avc_log_spoofing);
    let _ = writeln!(
        s,
        "# 设置AVC日志欺骗状态\n/data/adb/ksud susfs enable-avc-log-spoofing {avc_val}\n",
    );
    let _ = writeln!(
        s,
        "echo \"$(get_current_time): AVC日志欺骗功能设置为: {}\" >> \"$LOG_FILE\"\n",
        if enable_avc_log_spoofing {
            "启用"
        } else {
            "禁用"
        }
    );

    let _ = writeln!(
        s,
        "echo \"$(get_current_time): Post-FS-Data脚本执行完成\" >> \"$LOG_FILE\""
    );

    s
}

/// `post-mount.sh` — currently a stub that just records that it ran.
pub fn post_mount() -> String {
    let mut s = String::new();
    s.push_str("#!/system/bin/sh\n");
    s.push_str("# SuSFS Post-Mount Script\n");
    s.push_str("# 在所有分区挂载完成后执行\n\n");
    s.push_str(&prelude::log_setup("susfs_post_mount.log"));
    s.push('\n');
    let _ = writeln!(
        s,
        "echo \"$(get_current_time): Post-Mount脚本开始执行\" >> \"$LOG_FILE\"\n"
    );
    s.push_str(&prelude::binary_check());
    s.push('\n');
    let _ = writeln!(
        s,
        "echo \"$(get_current_time): Post-Mount脚本执行完成\" >> \"$LOG_FILE\""
    );
    s
}

/// `boot-completed.sh` — runs after the system has finished booting.
///
/// All per-path `add-sus-path*` / `add-sus-map` calls land here because
/// the underlying filesystems aren't available until much later.
pub fn boot_completed(
    hide_sus_mounts_for_all_procs: bool,
    sus_paths: &[String],
    sus_loop_paths: &[String],
    sus_maps: &[String],
) -> String {
    let mut s = String::new();

    s.push_str("#!/system/bin/sh\n");
    s.push_str("# SuSFS Boot-Completed Script\n");
    s.push_str("# 在系统完全启动后执行\n\n");
    s.push_str(&prelude::log_setup("susfs_boot_completed.log"));
    s.push('\n');
    let _ = writeln!(
        s,
        "echo \"$(get_current_time): Boot-Completed脚本开始执行\" >> \"$LOG_FILE\"\n"
    );
    s.push_str(&prelude::binary_check());
    s.push('\n');

    let hide_val: u32 = u32::from(hide_sus_mounts_for_all_procs);
    let _ = writeln!(
        s,
        "# 设置SUS挂载隐藏控制\n/data/adb/ksud susfs hide-sus-mnts-for-non-su-procs {hide_val}\n",
    );
    let _ = writeln!(
        s,
        "echo \"$(get_current_time): SUS挂载隐藏控制设置为: {}\" >> \"$LOG_FILE\"\n",
        if hide_sus_mounts_for_all_procs {
            "对所有进程隐藏"
        } else {
            "仅对非KSU进程隐藏"
        }
    );

    if !sus_paths.is_empty() {
        s.push_str("# 添加SUS路径\n");
        for path in sus_paths {
            let _ = writeln!(s, "/data/adb/ksud susfs add-sus-path {}", shell_quote(path));
            let _ = writeln!(
                s,
                "echo \"$(get_current_time): 添加SUS路径: {}\" >> \"$LOG_FILE\"",
                path.replace('\'', "'\\''")
            );
        }
        s.push('\n');
    }

    if !sus_loop_paths.is_empty() {
        s.push_str("# 添加SUS循环路径\n");
        for path in sus_loop_paths {
            let _ = writeln!(
                s,
                "/data/adb/ksud susfs add-sus-path-loop {}",
                shell_quote(path)
            );
            let _ = writeln!(
                s,
                "echo \"$(get_current_time): 添加SUS循环路径: {}\" >> \"$LOG_FILE\"",
                path.replace('\'', "'\\''")
            );
        }
        s.push('\n');
    }

    if !sus_maps.is_empty() {
        s.push_str("# 添加SUS映射\n");
        for map in sus_maps {
            let _ = writeln!(s, "/data/adb/ksud susfs add-sus-map {}", shell_quote(map));
            let _ = writeln!(
                s,
                "echo \"$(get_current_time): 添加SUS映射: {}\" >> \"$LOG_FILE\"",
                map.replace('\'', "'\\''")
            );
        }
        s.push('\n');
    }

    let _ = writeln!(
        s,
        "echo \"$(get_current_time): Boot-Completed脚本执行完成\" >> \"$LOG_FILE\""
    );

    s
}
