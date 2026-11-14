#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]

//! Built-in Zygisk, backed by NyaZygisk (the `external/BuiltZygisk` submodule).
//!
//! This mirrors what the standalone module's `post-fs-data.sh`, `zygisk-init.sh`
//! and `post-mount.sh` do, with ksud as the owner instead of a module:
//!
//! * `BUILTIN_ZYGISK_DIR` plays the role of `$MODDIR` (binaries, staged libraries
//!   and the `module.prop` the monitor reads and updates).
//! * `BUILTIN_ZYGISK_WORK_DIR` is the runtime directory shared with the injected
//!   processes, it has to stay in sync with BuiltZygisk's `workDirectory`.

use crate::defs::{BUILTIN_ZYGISK_DIR, BUILTIN_ZYGISK_FLAG, BUILTIN_ZYGISK_WORK_DIR};
use crate::restorecon::setsyscon;
use crate::utils::{ensure_dir_exists, ensure_file_exists};
use anyhow::{Context, Result};
use log::{error, info, warn};
use std::fs::{self, File, Permissions};
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, lchown};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Shipped next to the binaries by CI, extracted from BuiltZygisk's
/// `module/src/sepolicy.rule` so the rules never drift from the loader.
const ASSET_SEPOLICY: &str = "zygisk-sepolicy.rule";
/// The resolved `module.prop` of the BuiltZygisk release zip.
const ASSET_MODULE_PROP: &str = "zygisk-module.prop";

pub fn is_enabled() -> bool {
    Path::new(BUILTIN_ZYGISK_FLAG).exists()
}

pub fn enable() -> Result<()> {
    ensure_file_exists(BUILTIN_ZYGISK_FLAG)?;
    info!("Built-in Zygisk has been enabled");
    Ok(())
}

pub fn disable() -> Result<()> {
    let flag = Path::new(BUILTIN_ZYGISK_FLAG);
    if flag.exists() {
        fs::remove_file(flag).with_context(|| "Failed to remove builtin zygisk flag")?;
    }
    info!("Built-in Zygisk has been disabled");
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

/// `(version, versionCode)` of the staged build, read from the staged `module.prop`.
pub fn version() -> Option<(String, String)> {
    let content = fs::read_to_string(Path::new(BUILTIN_ZYGISK_DIR).join("module.prop")).ok()?;
    let get = |key: &str| {
        content
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .map(|v| v.trim().to_owned())
    };
    Some((get("version=")?, get("versionCode=").unwrap_or_default()))
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

/// Publish a library without disturbing a copy a running process may have mapped:
/// writing in place would fail with ETXTBSY or mutate the mapping, renaming over it
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
            if staged.as_deref().and_then(new_version) != new_version(&data) {
                if let Err(e) = fs::write(&path, &*data) {
                    warn!("write {} failed: {e}", path.display());
                }
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
    cmd.arg("monitor");
    #[cfg(target_os = "android")]
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    if let Err(e) = cmd.spawn() {
        error!("Failed to spawn built-in Zygisk monitor: {e}");
    }
    Ok(())
}

/// Attach to a zygote that is already running. A normal boot has none yet and the
/// monitor injects it as init spawns it, so this is silent then.
pub fn rearm() -> Result<()> {
    if !is_enabled() {
        return Ok(());
    }

    let has_zygote = crate::module::is_process_running_matching(|comm| {
        comm == "zygote" || comm == "zygote64" || comm == "app_process" || comm == "app_process64"
    });
    if !has_zygote {
        return Ok(());
    }

    let Some(tracer) = tracer_path() else {
        return Ok(());
    };
    info!("Rearming built-in Zygisk via ctl rearm");
    match Command::new(tracer).args(["ctl", "rearm"]).status() {
        Ok(status) if status.success() => {}
        Ok(status) => warn!("zygisk ctl rearm exited with {status}"),
        Err(e) => warn!("zygisk ctl rearm failed: {e}"),
    }
    Ok(())
}

pub fn shutdown() -> Result<()> {
    if !is_enabled() {
        return Ok(());
    }
    let Some(tracer) = tracer_path() else {
        return Ok(());
    };
    info!("Stopping built-in Zygisk via ctl exit");
    let _ = Command::new(tracer).args(["ctl", "exit"]).status();
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
    let mut out = String::new();
    let mut replaced = false;
    for line in existing.lines() {
        if line.split_once('=').is_some_and(|(k, _)| k.trim() == key) {
            if !replaced {
                out.push_str(&format!("{key}={value}\n"));
                replaced = true;
            }
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        out.push_str(&format!("{key}={value}\n"));
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
