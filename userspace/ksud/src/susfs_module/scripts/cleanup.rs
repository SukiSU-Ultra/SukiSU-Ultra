//! Tool-residue cleanup list.
//!
//! Each entry is `(path, description)`. The generated shell script walks
//! the list at boot and removes whatever still exists.

use std::fmt::Write as FmtWrite;

/// Hard-coded list of paths that various third-party tools leave behind
/// and that should be removed at boot.
const RESIDUE_PATHS: &[(&str, &str)] = &[
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
    ("/storage/emulated/0/legacy/", ""),
    ("/storage/emulated/0/elgg/", ""),
    ("/data/system/junge/", ""),
    ("/data/local/tmp/mount_namespace", "挂载命名空间残留"),
];

/// Render the cleanup section: a shell `cleanup_path()` helper followed
/// by one `cleanup_path ...` line per entry.
pub fn cleanup_residue_section() -> String {
    let total = RESIDUE_PATHS.len();
    let mut lines = String::new();
    let _ = writeln!(
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
    );

    for (i, (path, desc)) in RESIDUE_PATHS.iter().enumerate() {
        let _ = writeln!(
            lines,
            "cleanup_path '{}' '{}' {} $TOTAL",
            path.replace('\'', "'\\''"),
            desc.replace('\'', "'\\''"),
            i + 1
        );
    }

    let _ = writeln!(
        lines,
        "\necho \"$(get_current_time): 工具残留清理完成\" >> \"$LOG_FILE\"\n"
    );

    lines
}
