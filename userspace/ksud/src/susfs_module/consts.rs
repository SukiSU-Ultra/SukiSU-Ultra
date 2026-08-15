//! Constants and tiny shell helpers used by every script generator.

#[allow(dead_code)]
pub(crate) const MODULE_ID: &str = "susfs_manager";
pub(crate) const MODULE_PATH: &str = "/data/adb/modules/susfs_manager";
pub(crate) const LOG_DIR: &str = "/data/adb/ksu/log";
pub(crate) const DEFAULT_UNAME: &str = "default";
pub(crate) const DEFAULT_BUILD_TIME: &str = "default";

/// `date '+%Y-%m-%d %H:%M:%S'` for the running script — falls back to
/// `"unknown"` if the system `date` binary is unavailable.
#[allow(dead_code)]
pub(crate) fn get_current_time() -> String {
    use std::process::Command;
    let output = Command::new("date")
        .args(["+%Y-%m-%d %H:%M:%S"])
        .output()
        .ok();
    output
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map_or_else(|| "unknown".to_string(), |s| s.trim().to_string())
}

/// POSIX-safe single-quoted escape (`'foo' → 'foo'\''bar'`).
pub(crate) fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}