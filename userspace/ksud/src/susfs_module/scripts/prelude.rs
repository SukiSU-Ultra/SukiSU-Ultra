//! Shared prelude emitted at the top of every generated script.

use crate::susfs_module::consts::LOG_DIR;

/// Emit the `LOG_DIR`/`LOG_FILE` setup + a shell-side `get_current_time`
/// helper. The shell-side helper is independent of the Rust one in
/// [`crate::susfs_module::consts`]; the script needs it at runtime.
pub(crate) fn log_setup(log_file_name: &str) -> String {
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

/// Bail out if `/data/adb/ksud` is missing — every script depends on it.
pub(crate) fn binary_check() -> String {
    r#"# 检查ksud是否存在
if [ ! -f "/data/adb/ksud" ]; then
    echo "$(get_current_time): ksud未找到: /data/adb/ksud" >> "$LOG_FILE"
    exit 1
fi
"#
    .to_string()
}