#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]

//! Built-in Zygisk, backed by NyaZygisk (the `external/BuiltZygisk` submodule).
//!
//! This mirrors what the standalone module's `post-fs-data.sh`, `zygisk-init.sh`
//! and `post-mount.sh` do, with ksud as the owner instead of a module:
//!
//! * `BUILTIN_ZYGISK_DIR` plays the role of `$MODDIR`: binaries, staged libraries
//!   and the `module.prop` the monitor reads when it starts.
//! * `BUILTIN_ZYGISK_WORK_DIR` is the runtime directory shared with the injected
//!   processes, it has to stay in sync with BuiltZygisk's `workDirectory`. The
//!   monitor keeps its live status in the `module.prop` here.
//!
//! Nothing here is ever installed under `/data/adb/modules`: the built-in stays
//! embedded in ksud and lives only in the two directories above, so it cannot be
//! disabled, updated or removed like a module. If a standalone provider module is
//! installed, its own directory is left untouched and only its boot scripts are
//! skipped.

use crate::defs::{
    BUILTIN_ZYGISK_DIR, BUILTIN_ZYGISK_FLAG, BUILTIN_ZYGISK_WORK_DIR, DISABLE_FILE_NAME,
    MODULE_DIR, REMOVE_FILE_NAME,
};
use crate::restorecon::setsyscon;
use crate::utils::{ensure_dir_exists, ensure_file_exists};
use anyhow::{Context, Result, bail};
use log::{error, info, warn};
use std::collections::HashMap;
use std::fs::{self, File, Permissions};
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, lchown};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// Shipped next to the binaries by CI, extracted from BuiltZygisk's
/// `module/src/sepolicy.rule` so the rules never drift from the loader.
const ASSET_SEPOLICY: &str = "zygisk-sepolicy.rule";
/// The resolved `module.prop` of the BuiltZygisk release zip.
const ASSET_MODULE_PROP: &str = "zygisk-module.prop";

/// How long `shutdown` waits for the monitor to die, same budget as emulated-soft-reboot.sh.
const SHUTDOWN_WAIT_SECS: u32 = 10;

/// Staging directory used by earlier ksud builds. Removed on disable so an upgrade
/// does not leave a second copy of the binaries behind.
const LEGACY_BUILTIN_ZYGISK_DIR: &str = "/data/adb/nyazygisk";

pub fn is_enabled() -> bool {
    Path::new(BUILTIN_ZYGISK_FLAG).exists()
}

pub fn enable() -> Result<()> {
    ensure_file_exists(BUILTIN_ZYGISK_FLAG)?;
    info!("Built-in Zygisk has been enabled");
    Ok(())
}

fn remove_leftover(dir: &str) {
    let path = Path::new(dir);
    if path.exists()
        && let Err(e) = fs::remove_dir_all(path)
    {
        warn!("Failed to remove {}: {e}", path.display());
    }
}

pub fn disable() -> Result<()> {
    // Only the flag goes; the monitor and its daemons keep running so the current
    // session is not disturbed. The module system behaves the same way: a disable file
    // takes effect on the next boot, it does not kill a running Zygisk. They are
    // stopped by a soft reboot and die with the system on a real one, at which point
    // `cleanup_disabled` drops the files.
    let flag = Path::new(BUILTIN_ZYGISK_FLAG);
    if flag.exists() {
        fs::remove_file(flag).with_context(|| "Failed to remove builtin zygisk flag")?;
    }
    info!("Built-in Zygisk disabled, its processes stop at the next reboot");
    Ok(())
}

/// Remove what a disabled built-in left behind.
///
/// Only safe with no live monitor: a boot without the flag reaches this after the reboot
/// killed the previous session's processes, and a soft reboot calls it after `shutdown`.
/// The work dir is shared with a standalone NyaZygisk module, so it is only dropped when
/// something of ours was staged next to it; otherwise a built-in that was never enabled
/// would wipe that module's settings on every boot.
pub fn cleanup_disabled() -> Result<()> {
    if is_enabled() {
        return Ok(());
    }
    let staged = Path::new(BUILTIN_ZYGISK_DIR).exists();
    remove_leftover(BUILTIN_ZYGISK_DIR);
    if staged {
        remove_leftover(BUILTIN_ZYGISK_WORK_DIR);
    }
    remove_leftover(LEGACY_BUILTIN_ZYGISK_DIR);
    Ok(())
}

pub fn is_monitor_running() -> bool {
    crate::module::is_process_running_matching(|comm| {
        comm == "zygisk-ptrace" || comm == "zygisk-ptrace64" || comm == "zygisk-ptrace32"
    })
}

pub fn is_daemon_running() -> bool {
    crate::module::is_process_running_matching(|comm| {
        comm == "zygiskd" || comm == "zygiskd64" || comm == "zygiskd32"
    })
}

/// Parse a `module.prop` body. The monitor appends runtime keys such as
/// `monitor_status=` to the runtime copy, so keys must be read defensively.
fn parse_module_prop(content: &str) -> HashMap<String, String> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((key.trim().to_owned(), value.trim().to_owned()))
        })
        .collect()
}

/// The BuiltZygisk `module.prop` of the embedded build.
///
/// The monitor reports its live state (`monitor_status=`, `zygote_*_status=`,
/// `daemon_*_status=`) into the runtime copy under the work dir; the staged copy is
/// the pristine one it read when it started. Only the runtime copy can say whether
/// Zygisk is actually running, so it wins whenever a monitor has written it. Before
/// the first boot there is no runtime copy and the embedded asset describes the build.
fn module_prop() -> Option<HashMap<String, String>> {
    let runtime = Path::new(BUILTIN_ZYGISK_WORK_DIR).join("module.prop");
    if let Ok(content) = fs::read_to_string(runtime) {
        let prop = parse_module_prop(&content);
        // The monitor truncates this file before reading its input, so an empty one
        // means it died mid-startup and must not hide the build's identity.
        if !prop.is_empty() {
            return Some(prop);
        }
    }
    if let Ok(content) = fs::read_to_string(Path::new(BUILTIN_ZYGISK_DIR).join("module.prop")) {
        return Some(parse_module_prop(&content));
    }
    let data = crate::assets::get_asset_data(ASSET_MODULE_PROP).ok()?;
    Some(parse_module_prop(&String::from_utf8_lossy(&data)))
}

/// Monitor state reported by the monitor itself. Its process names are shared
/// with standalone builds, so a process scan cannot identify the built-in.
fn is_monitor_tracing() -> bool {
    module_prop().is_some_and(|prop| {
        prop.get("monitor_status")
            .is_some_and(|status| status == "tracing")
    })
}

/// Whether any ABI's daemon is reported as running by the monitor.
fn is_daemon_reported_running() -> bool {
    module_prop().is_some_and(|prop| {
        prop.iter().any(|(key, value)| {
            key.starts_with("daemon_") && key.ends_with("_status") && value == "running"
        })
    })
}

/// Live monitor state: the monitor's own report plus its process.
///
/// The process names are shared with standalone builds, so a scan alone is ambiguous,
/// and the report alone can be stale after a crash.
pub fn is_monitor_active() -> bool {
    is_monitor_tracing() && is_monitor_running()
}

/// Live daemon state, same reasoning as [`is_monitor_active`].
pub fn is_daemon_active() -> bool {
    is_daemon_reported_running() && is_daemon_running()
}

/// Whether a module directory belongs to a standalone Zygisk provider, whose boot
/// scripts must be skipped while the built-in is on.
pub fn suppresses_module_dir(path: &Path) -> bool {
    if !is_enabled() {
        return false;
    }
    let id = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let prop_id = crate::module::read_module_prop(path)
        .ok()
        .and_then(|prop| prop.get("id").cloned())
        .unwrap_or_default();
    crate::module::is_zygisk_provider(id) || crate::module::is_zygisk_provider(&prop_id)
}

/// `module.prop` versions usually carry build details in parentheses, e.g.
/// `v1.2.0 (1234-abc1234-release)`. Only the leading version is display material.
pub fn short_version(version: &str) -> String {
    let end = version.find('(').unwrap_or(version.len());
    version[..end].trim_end().to_owned()
}

/// The Zygisk implementation this system is running, or the one it would run after a
/// reboot.
///
/// The app used to derive this from `module list`, a command that also serves the module
/// screen and carries flags for both, so the two kept drifting apart. The answer is
/// computed here instead and read with a single `ksud zygisk info`.
pub struct ImplementationInfo {
    /// `running`, `reboot`, `disabled` or `none` for the app to localize.
    pub state: &'static str,
    pub name: String,
    pub version: String,
}

pub fn implementation_info() -> ImplementationInfo {
    if is_enabled() {
        let prop = module_prop().unwrap_or_default();
        let running = is_monitor_active() || is_daemon_active();
        return ImplementationInfo {
            state: if running { "running" } else { "reboot" },
            name: prop.get("name").cloned().unwrap_or_default(),
            version: prop
                .get("version")
                .map_or_else(String::new, |v| short_version(v)),
        };
    }

    provider_info()
}

/// Which installed provider module would own Zygisk: a running daemon first, then an
/// enabled module that is waiting for the next boot, then a disabled one.
fn provider_info() -> ImplementationInfo {
    let mut running = None;
    let mut pending = None;
    let mut disabled = None;

    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = fs::read_dir(MODULE_DIR) {
        for entry in entries.flatten() {
            dirs.push(entry.path());
        }
    }
    // Stable order: the answer must not depend on readdir.
    dirs.sort();

    for path in dirs {
        if !path.is_dir() {
            continue;
        }
        let Ok(prop) = crate::module::read_module_prop(&path) else {
            continue;
        };
        let dir_id = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        let id = prop.get("id").map_or(dir_id, String::as_str);
        if !crate::module::is_zygisk_provider(id) && !crate::module::is_zygisk_provider(dir_id) {
            continue;
        }

        let info = |state| ImplementationInfo {
            state,
            name: prop.get("name").cloned().unwrap_or_else(|| id.to_owned()),
            version: prop
                .get("version")
                .map_or_else(String::new, |v| short_version(v)),
        };

        // The daemon names are shared between providers, so ask per id.
        if crate::module::is_zygisk_daemon_running(dir_id)
            || crate::module::is_zygisk_daemon_running(id)
        {
            running.get_or_insert_with(|| info("running"));
        } else if path.join(DISABLE_FILE_NAME).exists() || path.join(REMOVE_FILE_NAME).exists() {
            disabled.get_or_insert_with(|| info("disabled"));
        } else {
            pending.get_or_insert_with(|| info("reboot"));
        }
    }

    running
        .or(pending)
        .or(disabled)
        .unwrap_or(ImplementationInfo {
            state: "none",
            name: String::new(),
            version: String::new(),
        })
}

/// `(version, versionCode)` of the staged build, read from the staged `module.prop`.
pub fn version() -> Option<(String, String)> {
    let content = fs::read_to_string(Path::new(BUILTIN_ZYGISK_DIR).join("module.prop")).ok()?;
    let get = |key: &str| {
        content
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .map(|v| v.trim().to_owned())
    };
    Some((
        short_version(&get("version=")?),
        get("versionCode=").unwrap_or_default(),
    ))
}

pub fn apply_sepolicy() -> Result<()> {
    if !is_enabled() {
        return Ok(());
    }
    let rules = match crate::assets::get_asset_data(ASSET_SEPOLICY) {
        Ok(data) => String::from_utf8_lossy(&data).into_owned(),
        Err(e) => {
            warn!("Built-in Zygisk sepolicy asset missing: {e}");
            return Ok(());
        }
    };
    info!("Applying built-in Zygisk SELinux rules");
    if let Err(e) = crate::sepolicy::live_patch(&rules) {
        warn!("Failed to live patch built-in Zygisk sepolicy: {e}");
    }
    Ok(())
}

/// A directory uid 1000 can traverse: a late-injected system_server dlopens the
/// library and connects to the control socket in its own context, which is a DAC
/// check no SELinux setting relaxes.
fn create_sys_perm<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    ensure_dir_exists(path)?;
    fs::set_permissions(path, Permissions::from_mode(0o555))?;
    let _ = setsyscon(path);
    let _ = lchown(path, Some(1000), Some(1000));
    Ok(())
}

/// Publish a library without disturbing a copy a running process may have mapped.
///
/// Writing in place would fail with ETXTBSY or mutate the mapping; renaming over it
/// leaves existing mappings on the old inode.
fn install_lib(dest: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = dest.parent() {
        create_sys_perm(parent)?;
    }
    let tmp_dest = dest.with_extension("new");
    {
        let mut file = File::create(&tmp_dest)?;
        file.write_all(data)?;
        file.flush()?;
    }
    fs::set_permissions(&tmp_dest, Permissions::from_mode(0o644))?;
    let _ = setsyscon(&tmp_dest);
    let _ = lchown(&tmp_dest, Some(1000), Some(1000));
    fs::rename(&tmp_dest, dest)?;
    Ok(())
}

/// Replace an executable that a previous monitor may still be running from.
fn install_executable(dest: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = dest.parent() {
        ensure_dir_exists(parent)?;
    }
    let tmp_dest = dest.with_extension("new");
    {
        let mut file = File::create(&tmp_dest)?;
        file.write_all(data)?;
        file.flush()?;
    }
    fs::set_permissions(&tmp_dest, Permissions::from_mode(0o755))?;
    fs::rename(&tmp_dest, dest)?;
    Ok(())
}

fn tracer_path() -> Option<PathBuf> {
    let bin = Path::new(BUILTIN_ZYGISK_DIR).join("bin");
    ["zygisk-ptrace64", "zygisk-ptrace32"]
        .iter()
        .map(|name| bin.join(name))
        .find(|path| path.exists())
}

/// Stage binaries and libraries from the embedded assets into `BUILTIN_ZYGISK_DIR`.
fn stage_assets(dir: &Path) {
    let is_64bit = cfg!(target_pointer_width = "64");
    let bits = if is_64bit { "64" } else { "32" };

    match crate::assets::get_asset_data(ASSET_MODULE_PROP) {
        Ok(data) => {
            let path = dir.join("module.prop");
            // The monitor appends runtime status to this file, so only replace it when
            // the shipped build differs from the staged one.
            let staged = fs::read(&path).ok();
            let new_version = |d: &[u8]| {
                String::from_utf8_lossy(d)
                    .lines()
                    .find(|l| l.starts_with("versionCode="))
                    .map(str::to_owned)
            };
            if staged.as_deref().and_then(new_version) != new_version(&data)
                && let Err(e) = fs::write(&path, &*data)
            {
                warn!("write {} failed: {e}", path.display());
            }
        }
        Err(_) => warn!("built-in Zygisk module.prop asset missing"),
    }

    for (asset, dst) in [
        ("zygisk-ptrace", format!("bin/zygisk-ptrace{bits}")),
        ("zygiskd", format!("bin/zygiskd{bits}")),
    ] {
        if let Ok(data) = crate::assets::get_asset_data(asset)
            && let Err(e) = install_executable(&dir.join(&dst), &data)
        {
            warn!("install {dst} failed: {e}");
        }
    }

    let (native_lib, secondary_lib) = if is_64bit {
        ("lib64/libzygisk.so", "lib/libzygisk.so")
    } else {
        ("lib/libzygisk.so", "")
    };
    for (asset, dst) in [
        ("libzygisk.so", native_lib),
        ("libzygisk32.so", secondary_lib),
    ] {
        if dst.is_empty() {
            continue;
        }
        if let Ok(data) = crate::assets::get_asset_data(asset) {
            // Staged copy, then the runtime copy the zygote actually maps.
            let staged = dir.join(dst);
            if let Some(parent) = staged.parent() {
                let _ = ensure_dir_exists(parent);
            }
            if let Err(e) = fs::write(&staged, &*data) {
                warn!("stage {dst} failed: {e}");
            }
            if let Err(e) = install_lib(&Path::new(BUILTIN_ZYGISK_WORK_DIR).join(dst), &data) {
                warn!("install runtime {dst} failed: {e}");
            }
        }
    }
}

pub fn bootstrap() -> Result<()> {
    if !is_enabled() {
        return Ok(());
    }

    info!("Bootstrapping built-in Zygisk");
    let dir = Path::new(BUILTIN_ZYGISK_DIR);
    ensure_dir_exists(dir)?;
    // Deliberately not wiped: on a late load or soft reboot a monitor from the previous
    // session may still own the control socket here.
    create_sys_perm(BUILTIN_ZYGISK_WORK_DIR)?;
    stage_assets(dir);

    let Some(tracer_bin) = tracer_path() else {
        warn!(
            "built-in Zygisk tracer binary not found in {}",
            dir.display()
        );
        return Ok(());
    };

    // Unconditional: the monitor enforces the single-owner invariant itself and a
    // redundant one exits immediately.
    info!("Starting built-in Zygisk monitor: {}", tracer_bin.display());
    let mut cmd = Command::new(&tracer_bin);
    // Detached from our stdio, or a caller waiting on a pipe (late-load from a shell)
    // would block for as long as the monitor lives.
    cmd.arg("monitor")
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(target_os = "android")]
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            // Same cgroup escape the module scripts get; a boot-stage cgroup can be
            // frozen or killed under the monitor otherwise.
            crate::utils::switch_cgroups();
            Ok(())
        });
    }
    if let Err(e) = cmd.spawn() {
        error!("Failed to spawn built-in Zygisk monitor: {e}");
    }
    Ok(())
}

/// Whether a monitor currently owns the control socket. The socket file outlives
/// its owner, so a connect is what proves liveness.
fn monitor_reachable() -> bool {
    let socket = Path::new(BUILTIN_ZYGISK_WORK_DIR).join("init_monitor");
    std::os::unix::net::UnixDatagram::unbound()
        .and_then(|sock| sock.connect(socket))
        .is_ok()
}

/// A zygote rewrites its argv[0] but never sets its thread name, so its comm reads
/// "main". Match the cmdline like `pidof` does.
fn has_running_zygote() -> bool {
    crate::module::is_process_running_matching_paths(|name| name == "zygote" || name == "zygote64")
}

/// Whether the monitor already reports a zygote as injected.
fn zygote_injected() -> bool {
    module_prop().is_some_and(|prop| {
        prop.iter().any(|(key, value)| {
            key.starts_with("zygote_") && key.ends_with("_status") && value == "injected"
        })
    })
}

fn send_rearm(tracer: &Path) -> Result<()> {
    info!("Rearming built-in Zygisk via ctl rearm");
    let status = Command::new(tracer)
        .args(["ctl", "rearm"])
        .status()
        .context("Failed to run zygisk ctl rearm")?;
    if !status.success() {
        bail!("zygisk ctl rearm exited with {status}");
    }
    Ok(())
}

/// Start a monitor when none owns the control socket.
///
/// Starting one is idempotent: a live monitor holds the socket and a redundant one exits
/// before it touches anything, so every boot stage can call this without probing first.
pub fn ensure_monitor() -> Result<()> {
    if !is_enabled() || tracer_path().is_none() {
        return Ok(());
    }
    if !monitor_reachable() {
        info!("No built-in Zygisk monitor is listening, starting one");
        bootstrap()?;
    }
    Ok(())
}

/// Attach to a zygote that is already running. A normal boot has none yet and the
/// monitor injects it as init spawns it, so this is silent then.
pub fn rearm() -> Result<()> {
    if !is_enabled() {
        return Ok(());
    }

    let Some(tracer) = tracer_path() else {
        return Ok(());
    };

    // A full boot can reach the first rearm without a live monitor: the one spawned
    // in post-fs-data may have lost init to another tracer and exited. Start one
    // before talking to the socket; `ctl` retries while it binds.
    ensure_monitor()?;

    if !has_running_zygote() {
        return Ok(());
    }

    send_rearm(&tracer)
}

/// Boot-stage safety net for a system that is already up.
///
/// Starts a monitor when none is alive and attaches the running zygote if the early boot
/// missed it. Once the monitor is tracing and the zygote is injected this does nothing,
/// because a redundant `ctl rearm` blocks the monitor while it refreshes the daemon.
pub fn ensure_armed() -> Result<()> {
    if !is_enabled() {
        return Ok(());
    }

    let Some(tracer) = tracer_path() else {
        return Ok(());
    };

    ensure_monitor()?;

    if !has_running_zygote() || (is_monitor_active() && zygote_injected()) {
        return Ok(());
    }

    send_rearm(&tracer)
}

/// Stop the monitor that owns the control socket. Not gated on the flag: a disabled
/// built-in keeps its processes until the reboot that is expected to end them.
pub fn shutdown() -> Result<()> {
    let Some(tracer) = tracer_path() else {
        return Ok(());
    };
    // The socket is the only proof that the monitor is ours; a process scan would also
    // match the standalone providers, which share these names.
    if !monitor_reachable() {
        return Ok(());
    }
    info!("Stopping built-in Zygisk via ctl exit");
    let exited = Command::new(tracer)
        .args(["ctl", "exit"])
        .status()
        .is_ok_and(|status| status.success());
    if exited {
        // Only one process may trace init, and the ptrace attachment outlives the
        // control socket, so the monitor the replayed post-fs-data starts cannot seize
        // init until this one is gone.
        for _ in 0..SHUTDOWN_WAIT_SECS {
            if !is_monitor_running() {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    Ok(())
}

/// Options NyaZygisk reads from `config.prop`, with the values each accepts. They apply
/// to app processes started afterwards.
const CONFIG_KEYS: &[(&str, &[&str], &str)] = &[
    ("anonymous_memory", &["0", "1"], "0"),
    ("custom_linker", &["0", "1"], "0"),
    ("plt_engine", &["bytehook", "lsplt"], "bytehook"),
];

fn config_path() -> PathBuf {
    Path::new(BUILTIN_ZYGISK_WORK_DIR).join("config.prop")
}

fn read_config_map() -> Vec<(String, String)> {
    fs::read_to_string(config_path())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let (k, v) = line.split_once('=')?;
            Some((k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect()
}

/// Every known option with its effective value, defaults filled in.
pub fn config_get_all() -> Vec<(&'static str, String)> {
    let stored = read_config_map();
    CONFIG_KEYS
        .iter()
        .map(|(key, _, default)| {
            let value = stored
                .iter()
                .rev()
                .find(|(k, _)| k == key)
                .map_or_else(|| (*default).to_owned(), |(_, v)| v.clone());
            (*key, value)
        })
        .collect()
}

/// Set one option, keeping every other line of the file. The write is atomic and the
/// result stays readable by the zygote and system_server.
pub fn config_set(key: &str, value: &str) -> Result<()> {
    let Some((_, allowed, _)) = CONFIG_KEYS.iter().find(|(k, _, _)| *k == key) else {
        anyhow::bail!("unknown option: {key}");
    };
    if !allowed.contains(&value) {
        anyhow::bail!("invalid value for {key}: {value} (expected one of {allowed:?})");
    }

    let path = config_path();
    let existing = fs::read_to_string(&path).unwrap_or_default();
    let entry = format!("{key}={value}\n");
    let mut out = String::new();
    let mut replaced = false;
    for line in existing.lines() {
        if line.split_once('=').is_some_and(|(k, _)| k.trim() == key) {
            if !replaced {
                out.push_str(&entry);
                replaced = true;
            }
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        out.push_str(&entry);
    }

    create_sys_perm(BUILTIN_ZYGISK_WORK_DIR)?;
    let tmp = path.with_extension("prop.new");
    fs::write(&tmp, out)?;
    fs::set_permissions(&tmp, Permissions::from_mode(0o644))?;
    let _ = setsyscon(&tmp);
    let _ = lchown(&tmp, Some(1000), Some(1000));
    fs::rename(&tmp, &path)?;
    info!("Built-in Zygisk option {key}={value}");
    Ok(())
}
