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
/// The loader the zygote is injected with; a live handover needs both sides identical.
const ASSET_ZYGISK_LIB: &str = "libzygisk.so";
/// The 32-bit loader, for devices with a 32-bit zygote.
const ASSET_ZYGISK32_LIB: &str = "libzygisk32.so";

/// How long `shutdown` waits for the monitor to die, same budget as emulated-soft-reboot.sh.
const SHUTDOWN_WAIT_SECS: u32 = 10;
/// How long a switch waits for the monitor, the daemon or the old processes.
const SWITCH_WAIT_SECS: u32 = 5;

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
/// The work dir is shared with a standalone NyaZygisk module, which keeps its options and
/// reported status there; it is only dropped when something of ours was staged next to it
/// and no standalone NyaZygisk stands in for the built-in.
pub fn cleanup_disabled() -> Result<()> {
    if is_enabled() {
        return Ok(());
    }
    // A monitor that outlived `shutdown` still runs from the staged dir. Deleting it
    // would leave init traced by a process whose binaries are gone and would keep every
    // provider from seizing init, so the files wait for the next boot.
    if monitor_process().is_some() {
        warn!("Built-in Zygisk cleanup skipped, its monitor is still running");
        return Ok(());
    }
    let staged = Path::new(BUILTIN_ZYGISK_DIR).exists();
    remove_leftover(BUILTIN_ZYGISK_DIR);
    if staged && !nya_module_installed() {
        remove_leftover(BUILTIN_ZYGISK_WORK_DIR);
    }
    remove_leftover(LEGACY_BUILTIN_ZYGISK_DIR);
    Ok(())
}

/// Whether a standalone NyaZygisk module exists on disk.
///
/// The built-in is embedded and uses its own staging dir, so a `zygisksu` module
/// directory can only be that standalone build. Its `config.prop` lives in the shared
/// work dir and has to survive a built-in cleanup; a module marked for removal is on its
/// way out and does not count.
fn nya_module_installed() -> bool {
    let Ok(entries) = fs::read_dir(MODULE_DIR) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        if !path.is_dir() || path.join(REMOVE_FILE_NAME).exists() {
            return false;
        }
        let dir_id = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        dir_id == "zygisksu" || module_prop_id(&path) == "zygisksu"
    })
}

/// `(pid, name)` of the processes running our own binaries out of the staging directory.
/// The names are shared with the standalone providers, so the executable path is what
/// tells ours apart.
fn staged_processes(prefix: &str) -> Vec<(i32, String)> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(exe) = fs::read_link(entry.path().join("exe")) else {
            continue;
        };
        if !exe.starts_with(BUILTIN_ZYGISK_DIR) {
            continue;
        }
        let name = exe.file_name().and_then(|name| name.to_str()).unwrap_or("");
        if name.starts_with(prefix) {
            found.push((pid, name.to_owned()));
        }
    }
    found.sort();
    found
}

/// Our monitor, with the pid and name the app shows.
pub fn monitor_process() -> Option<(i32, String)> {
    staged_processes("zygisk-ptrace").into_iter().next()
}

/// Our daemons, one per injected ABI.
pub fn daemon_processes() -> Vec<(i32, String)> {
    staged_processes("zygiskd")
}

pub fn is_monitor_running() -> bool {
    monitor_process().is_some()
}

pub fn is_daemon_running() -> bool {
    !daemon_processes().is_empty()
}

/// Monitor and daemon processes of one implementation, for the dashboard's process rows.
pub struct ImplementationProcesses {
    pub monitors: Vec<(i32, String)>,
    pub daemons: Vec<(i32, String)>,
}

/// Everything running for `target`: our staged binaries, or an installed provider's own.
pub fn processes(target: &str) -> Result<ImplementationProcesses> {
    if target == BUILTIN_TARGET {
        return Ok(ImplementationProcesses {
            monitors: monitor_process().into_iter().collect(),
            daemons: daemon_processes(),
        });
    }

    let dir =
        provider_dir(target).with_context(|| format!("Zygisk provider {target} is missing"))?;
    let mut monitors = Vec::new();
    let mut daemons = Vec::new();
    for pid in provider_pids(std::slice::from_ref(&dir)) {
        let Some(name) = process_name(pid) else {
            continue;
        };
        if is_monitor_name(&name) {
            monitors.push((pid, name));
        } else {
            daemons.push((pid, name));
        }
    }
    monitors.sort();
    daemons.sort();
    Ok(ImplementationProcesses { monitors, daemons })
}

/// One Zygisk module the built-in is serving, as both ABI daemons and the monitor see it.
pub struct InjectedModule {
    pub id: String,
    pub name: String,
    pub version: String,
    /// `zygisk` for the Magisk API, `next` for the Zygisk Next API.
    pub kind: String,
    /// ABIs whose daemon loaded the module, `32` and/or `64`.
    pub abi: Vec<String>,
    /// Injection targets declared by a Zygisk Next module, as plain names or paths.
    pub targets: Vec<String>,
    pub companion: bool,
    /// `injected`, `loaded`, `failed` or `unknown`.
    pub state: String,
    /// `(name, pid, kind)` with kind `companion` or `target`.
    pub processes: Vec<(String, i32, String)>,
}

/// One entry of a daemon's `modules_list`.
struct DaemonModule {
    id: String,
    kind: String,
    target: String,
    companion: bool,
}

/// The live state the monitor wrote into the runtime `module.prop`.
fn runtime_prop_content() -> Option<String> {
    let runtime = Path::new(BUILTIN_ZYGISK_WORK_DIR).join("module.prop");
    let content = fs::read_to_string(runtime).ok()?;
    // The monitor truncates the file before writing, so an empty one belongs to a
    // monitor that died mid-startup and must not hide the build's identity.
    (!content.trim().is_empty()).then_some(content)
}

/// Every `modules_list` a daemon reported, tagged with the ABI that reported it.
///
/// The monitor appends each daemon's info blob right after its `daemon_<abi>_status`
/// line, so the ABI of a list is the last status line before it.
fn daemon_reported_modules(content: &str) -> Vec<(String, DaemonModule)> {
    let mut abi: Option<String> = None;
    let mut found = Vec::new();
    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if let Some(name) = key
            .strip_prefix("daemon_")
            .and_then(|key| key.strip_suffix("_status"))
        {
            abi = (value.trim() == "running").then_some(name.to_owned());
            continue;
        }
        if key != "modules_list" {
            continue;
        }
        let Some(current) = abi.as_deref() else {
            continue;
        };
        let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(value.trim()) else {
            continue;
        };
        for entry in entries {
            let Some(id) = entry.get("name").and_then(serde_json::Value::as_str) else {
                continue;
            };
            found.push((
                current.to_owned(),
                DaemonModule {
                    id: id.to_owned(),
                    kind: entry
                        .get("type")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("zygisk")
                        .to_owned(),
                    target: entry
                        .get("target")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_owned(),
                    companion: entry
                        .get("companion")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false),
                },
            ));
        }
    }
    found
}

/// Display name and version of an installed module, falling back to its directory id.
fn module_identity(id: &str) -> (String, String) {
    let prop = fs::read_to_string(Path::new(MODULE_DIR).join(id).join("module.prop"))
        .map_or_else(|_| HashMap::new(), |content| parse_module_prop(&content));
    let name = prop.get("name").cloned().unwrap_or_else(|| id.to_owned());
    let version = prop
        .get("version")
        .map_or_else(String::new, |v| short_version(v));
    (name, version)
}

/// What `zygiskd` last reported for a Zygisk Next module: every injected or failed load
/// is appended to `zn_modules_state`, keyed by the module library path.
fn zn_module_state(id: &str) -> String {
    let state_file = Path::new(BUILTIN_ZYGISK_WORK_DIR).join("zn_modules_state");
    let Ok(content) = fs::read_to_string(state_file) else {
        return "unknown".to_owned();
    };
    let prefix = format!("/data/adb/modules/{id}/");
    let mut failed = false;
    for line in content.lines() {
        let Some((state, lib)) = line.split_once(' ') else {
            continue;
        };
        if !lib.starts_with(&prefix) {
            continue;
        }
        match state {
            "injected" => return "injected".to_owned(),
            "failed" => failed = true,
            _ => (),
        }
    }
    if failed {
        "failed".to_owned()
    } else {
        "unknown".to_owned()
    }
}

/// One `/proc` entry, read once and matched against every module.
struct ProcessEntry {
    pid: i32,
    /// `argv[0]`, which is what companions and targets are identified by.
    argv0: String,
    argv: Vec<String>,
    exe: Option<PathBuf>,
}

fn read_process(pid: i32) -> Option<ProcessEntry> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if raw.is_empty() {
        return None;
    }
    let mut argv: Vec<String> = raw
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    if argv.is_empty() {
        return None;
    }
    let argv0 = argv.remove(0);
    Some(ProcessEntry {
        pid,
        argv0,
        argv,
        exe: fs::read_link(format!("/proc/{pid}/exe")).ok(),
    })
}

fn scan_processes() -> Vec<ProcessEntry> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut processes: Vec<ProcessEntry> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<i32>().ok())
        .filter_map(read_process)
        .collect();
    processes.sort_by_key(|process| process.pid);
    processes
}

/// Whether `process` is this module's companion.
fn is_companion(process: &ProcessEntry, id: &str) -> bool {
    let name = process.argv0.rsplit('/').next().unwrap_or("");
    let Some(name) = name.strip_prefix("zygiskd-") else {
        return false;
    };
    if name == "zn-companion" {
        // `zygiskd-zn-companion zn-companion <lib> <fd>`: the library names the module.
        return process
            .argv
            .get(1)
            .is_some_and(|lib| lib.starts_with(&format!("/data/adb/modules/{id}/")));
    }
    name == id
}

/// Whether `process` is one of the injection targets the module declared.
///
/// Targets are stored without their `name=` / `path=` prefix: an absolute path matches
/// the executable, anything else the process name.
fn matches_target(process: &ProcessEntry, target: &str) -> bool {
    if target.starts_with('/') {
        return process
            .exe
            .as_deref()
            .is_some_and(|exe| exe == Path::new(target));
    }
    let argv0 = process.argv0.rsplit('/').next().unwrap_or("");
    argv0 == target
}

/// The Zygisk modules the built-in is serving, with the processes each one reaches.
///
/// A disabled or stopped built-in has no daemon report, so the installed modules are
/// listed instead and left in the `unknown` state: the dashboard still shows what would
/// be injected without claiming it is running.
pub fn injected_modules() -> Vec<InjectedModule> {
    let content = runtime_prop_content().unwrap_or_default();
    let reported = daemon_reported_modules(&content);
    if reported.is_empty() {
        return installed_modules();
    }
    let zygote_injected = |abi: &str| {
        let status = format!("zygote_{abi}_status=injected");
        content.lines().any(|line| line.trim() == status)
    };

    let mut order: Vec<String> = Vec::new();
    let mut merged: HashMap<String, InjectedModule> = HashMap::new();
    for (abi, entry) in reported {
        let module = merged.entry(entry.id.clone()).or_insert_with(|| {
            order.push(entry.id.clone());
            let (name, version) = module_identity(&entry.id);
            InjectedModule {
                id: entry.id.clone(),
                name,
                version,
                kind: "zygisk".to_owned(),
                abi: Vec::new(),
                targets: Vec::new(),
                companion: false,
                state: "unknown".to_owned(),
                processes: Vec::new(),
            }
        });
        if !module.abi.contains(&abi) {
            module.abi.push(abi);
        }
        if entry.kind == "next" {
            "next".clone_into(&mut module.kind);
        }
        module.companion |= entry.companion;
        for target in entry
            .target
            .split(',')
            .map(str::trim)
            .filter(|target| !target.is_empty() && *target != "unknown")
        {
            // The prefix only tells the daemon how to match; the app shows a plain name.
            let target = target
                .strip_prefix("name=")
                .or_else(|| target.strip_prefix("path="))
                .unwrap_or(target);
            // The zygotes are the base injection, not a per-module process.
            if target.starts_with("zygote") {
                continue;
            }
            if !module.targets.iter().any(|known| known == target) {
                module.targets.push(target.to_owned());
            }
        }
    }

    let processes = scan_processes();
    let mut modules: Vec<InjectedModule> = order
        .into_iter()
        .filter_map(|id| merged.remove(&id))
        .collect();
    for module in &mut modules {
        module.abi.sort();
        let state = if module.kind == "next" {
            zn_module_state(&module.id)
        } else if module.abi.iter().any(|abi| zygote_injected(abi)) {
            "injected".to_owned()
        } else {
            "loaded".to_owned()
        };
        module.state = state;
        let processes_of_module: Vec<(String, i32, String)> = processes
            .iter()
            .filter_map(|process| {
                let name = process.argv0.rsplit('/').next().unwrap_or("").to_owned();
                if is_companion(process, &module.id) {
                    return Some((name, process.pid, "companion".to_owned()));
                }
                module
                    .targets
                    .iter()
                    .any(|target| matches_target(process, target))
                    .then_some((name, process.pid, "target".to_owned()))
            })
            .collect();
        module.processes = processes_of_module;
    }
    modules.sort_by(|left, right| left.name.cmp(&right.name));
    modules
}

/// Every enabled module that ships Zygisk code, used when no daemon report exists.
fn installed_modules() -> Vec<InjectedModule> {
    let Ok(entries) = fs::read_dir(MODULE_DIR) else {
        return Vec::new();
    };
    let mut modules = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir()
            || path.join(DISABLE_FILE_NAME).exists()
            || path.join(REMOVE_FILE_NAME).exists()
        {
            continue;
        }
        let id = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .to_owned();
        let libs = path.join("zygisk");
        let is_next = path.join("zn_modules.txt").exists();
        if !is_next && !libs.is_dir() {
            continue;
        }
        let mut abi = Vec::new();
        let has = |arch: &str| libs.join(format!("{arch}.so")).exists();
        if ["arm64-v8a", "x86_64", "riscv64"]
            .iter()
            .any(|arch| has(arch))
        {
            abi.push("64".to_owned());
        }
        if ["armeabi-v7a", "x86"].iter().any(|arch| has(arch)) {
            abi.push("32".to_owned());
        }
        let (name, version) = module_identity(&id);
        modules.push(InjectedModule {
            id,
            name,
            version,
            kind: if is_next { "next" } else { "zygisk" }.to_owned(),
            abi,
            targets: Vec::new(),
            companion: false,
            state: "unknown".to_owned(),
            processes: Vec::new(),
        });
    }
    modules.sort_by(|left, right| left.name.cmp(&right.name));
    modules
}

fn process_name(pid: i32) -> Option<String> {
    let exe = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    exe.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
}

/// Any NyaZygisk tracer, ours or a standalone provider's: a switch has to wait for the
/// one it just asked to exit before a new one can seize init.
fn any_tracer_running() -> bool {
    is_process_running_matching(|comm| {
        comm == "zygisk-ptrace" || comm == "zygisk-ptrace64" || comm == "zygisk-ptrace32"
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

/// Whether any ABI's zygote carries the loader, as the monitor reports it.
///
/// A live monitor and daemon only mean the implementation is up; the modules become
/// usable once a zygote was actually injected.
pub fn is_zygote_injected() -> bool {
    zygote_injected()
}

/// The state the dashboard calls "fully active": monitor, daemon and zygote injection all
/// in place. Anything less leaves some Zygisk modules unusable until a soft reboot.
pub fn is_fully_active() -> bool {
    is_monitor_active() && is_daemon_active() && is_zygote_injected()
}

/// `(abi, status)` for every zygote the monitor reported, e.g. `("64", "injected")`.
///
/// The monitor writes one `zygote_<abi>_status` key per supported ABI, so this is also
/// what tells 32-bit and 64-bit zygotes apart on a mixed device.
pub fn zygote_states() -> Vec<(String, String)> {
    let Some(content) = runtime_prop_content() else {
        return Vec::new();
    };
    let mut states: Vec<(String, String)> = content
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            let abi = key
                .trim()
                .strip_prefix("zygote_")?
                .strip_suffix("_status")?;
            Some((abi.to_owned(), value.trim().to_owned()))
        })
        .collect();
    states.sort();
    states
}

/// Ids of the installed Zygisk provider modules the built-in can hand over to.
///
/// Both the directory name and the declared `id` are reported: `zygisk switch` accepts
/// either, and modules do not always name the directory after their id.
pub fn provider_ids() -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for dir in active_providers() {
        if let Some(name) = dir.file_name().and_then(|name| name.to_str()) {
            let name = name.to_owned();
            if !ids.contains(&name) {
                ids.push(name);
            }
        }
        let prop_id = module_prop_id(&dir);
        if !prop_id.is_empty() && !ids.contains(&prop_id) {
            ids.push(prop_id);
        }
    }
    ids
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
    is_provider_module(id, &prop_id)
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
    /// [`BUILTIN_TARGET`] or the provider module's id, for `zygisk switch`.
    pub id: String,
    pub name: String,
    pub version: String,
}

pub fn implementation_info() -> ImplementationInfo {
    if is_enabled() {
        let prop = module_prop().unwrap_or_default();
        let running = is_monitor_active() || is_daemon_active();
        return ImplementationInfo {
            state: if running { "running" } else { "reboot" },
            id: BUILTIN_TARGET.to_owned(),
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
        if !is_provider_module(dir_id, id) {
            continue;
        }

        let info = |state| ImplementationInfo {
            state,
            id: id.to_owned(),
            name: prop.get("name").cloned().unwrap_or_else(|| id.to_owned()),
            version: prop
                .get("version")
                .map_or_else(String::new, |v| short_version(v)),
        };

        // The daemon names are shared between providers, so ask per id.
        if provider_running(dir_id, id) {
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
            id: String::new(),
            name: String::new(),
            version: String::new(),
        })
}

/// Target id the app uses for the built-in implementation.
pub const BUILTIN_TARGET: &str = "builtin";

/// Whether the id names a Zygisk implementation, embedded or a standalone provider.
pub fn is_provider_id(module_id: &str) -> bool {
    let id = module_id.to_ascii_lowercase();
    matches!(
        id.as_str(),
        "zygisksu" | "rezygisk" | "nyazygisk" | "neozygisk" | "yukizygisk" | "yukisu"
    )
}

/// Whether a module is a Zygisk provider, by directory name or `module.prop` id: the two
/// may differ, so both are checked.
pub fn is_provider_module(dir_id: &str, prop_id: &str) -> bool {
    is_provider_id(dir_id) || (!prop_id.is_empty() && is_provider_id(prop_id))
}

fn module_prop_id(path: &Path) -> String {
    crate::module::read_module_prop(path)
        .ok()
        .and_then(|prop| prop.get("id").cloned())
        .unwrap_or_default()
}

/// Provider module directories that are enabled right now.
fn active_providers() -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(MODULE_DIR) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    // Stable order: the scan must not depend on readdir.
    dirs.sort();
    dirs.retain(|path| {
        if path.join(DISABLE_FILE_NAME).exists() {
            return false;
        }
        let dir_id = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        is_provider_module(dir_id, &module_prop_id(path))
    });
    dirs
}

/// The installed provider module with this id, matched by directory name or `module.prop`
/// id like the module list does.
fn provider_dir(id: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(MODULE_DIR).ok()?;
    entries.flatten().map(|entry| entry.path()).find(|path| {
        if !path.is_dir() {
            return false;
        }
        let dir_id = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        let prop_id = module_prop_id(path);
        (dir_id == id || prop_id == id) && is_provider_module(dir_id, &prop_id)
    })
}

/// Whether a provider's daemon runs, under either id it goes by.
fn provider_running(dir_id: &str, prop_id: &str) -> bool {
    is_provider_running(dir_id)
        || (!prop_id.is_empty() && prop_id != dir_id && is_provider_running(prop_id))
}

/// Monitors call themselves a tracer or a ptrace helper; everything else is a daemon.
fn is_monitor_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("ptrace") || name.contains("monitor") || name.contains("tracer")
}

/// Whether a process whose `comm` satisfies the predicate is running.
fn is_process_running_matching(predicate: impl Fn(&str) -> bool) -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let file_str = file_name.to_string_lossy();
        if file_str.chars().all(|c| c.is_ascii_digit())
            && let Ok(comm) = fs::read_to_string(entry.path().join("comm"))
            && predicate(comm.trim())
        {
            return true;
        }
    }
    false
}

/// Like [`is_process_running_matching`], but also tests the basenames of the `cmdline`
/// arguments and of the `exe` link.
///
/// Daemons such as YukiZygisk's `zygiskd64`/`zygiskd32` are started through
/// `execveat(..., AT_EMPTY_PATH)`; on kernels without `comm_from_dentry` the kernel
/// derives `comm` from the synthetic "/dev/fd/N" path, so the real name only shows up in
/// `cmdline`/`exe`.
fn is_process_running_matching_paths(predicate: impl Fn(&str) -> bool) -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let is_pid = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.chars().all(|c| c.is_ascii_digit()));
        if !is_pid {
            continue;
        }
        let proc_path = entry.path();

        if let Ok(comm) = fs::read_to_string(proc_path.join("comm"))
            && predicate(comm.trim())
        {
            return true;
        }

        if let Ok(cmdline) = fs::read(proc_path.join("cmdline")) {
            for arg in cmdline.split(|byte| *byte == 0) {
                if arg.is_empty() {
                    continue;
                }
                let arg = String::from_utf8_lossy(arg);
                let basename = arg.rsplit('/').next().unwrap_or_default();
                if predicate(basename) {
                    return true;
                }
            }
        }

        if let Ok(exe) = fs::read_link(proc_path.join("exe"))
            && let Some(basename) = exe.file_name().and_then(|name| name.to_str())
            && predicate(basename)
        {
            return true;
        }
    }
    false
}

/// Whether the Zygisk provider module with this id has a running daemon.
///
/// Providers rename their daemons freely (`zn-daemon`, `rezygiskd`, ...) and some start
/// them through `execveat(AT_EMPTY_PATH)`, which leaves an fd number in `comm`, so the
/// names known per implementation are matched against more than `comm`.
pub fn is_provider_running(module_id: &str) -> bool {
    let id_lower = module_id.to_ascii_lowercase();
    let result = match id_lower.as_str() {
        "rezygisk" => is_process_running_matching(|name| {
            name.starts_with("rezygisk") || name.contains("rezygisk")
        }),
        "zygisksu" => is_process_running_matching(|name| {
            name.starts_with("zygiskd")
                || name.starts_with("zygisk-ptrace")
                || name.starts_with("zygisk-comp")
                || name.starts_with("zygisk_comp")
                // Zygisk Next >= 1.5.0 renames its daemon to "zn-daemon"/
                // "zn-daemon64"/"zn-daemon32" for stealth, so the legacy
                // "zygisk*" patterns no longer match it.
                || name.starts_with("zn-daemon")
                || name.contains("zygiskd")
                || name.contains("zygisk")
        }),
        "nyazygisk" => is_process_running_matching(|name| {
            name.starts_with("nyazygisk")
                || name.starts_with("zygiskd")
                || name.starts_with("zygisk-ptrace")
                || name.contains("nyazygisk")
                || name.contains("zygisk")
        }),
        "neozygisk" => is_process_running_matching(|name| {
            name.starts_with("neozygisk")
                || name.starts_with("zygiskd")
                || name.starts_with("zygisk-ptrace")
                || name.contains("neozygisk")
                || name.contains("zygisk")
        }),
        // YukiZygisk launches its daemons from $MODDIR/bin/zygiskd64 / $MODDIR/bin/zygiskd32
        // via execveat(AT_EMPTY_PATH); on Android GKI kernels the process `comm` there is
        // just the fd number, so fall back to the cmdline/exe basenames as well.
        "yukizygisk" => is_process_running_matching_paths(|name| {
            name.starts_with("zygiskd") || name.contains("yukizygisk")
        }),
        _ => is_process_running_matching(|name| {
            name.starts_with("zygiskd")
                || name.starts_with("zygisk-ptrace")
                || name.starts_with("rezygisk")
                || name.contains("zygisk")
        }),
    };
    info!("Zygisk daemon check for '{module_id}': {result}");
    result
}

/// Hand the live system to the built-in or to an installed provider module.
///
/// Both directions are userspace only: the zygote keeps whatever loader it was injected
/// with, and the new implementation takes that zygote over.
pub fn switch_to(target: &str) -> Result<()> {
    if target == BUILTIN_TARGET {
        switch_to_builtin()
    } else {
        switch_to_provider(target)
    }
}

/// Switch to the built-in Zygisk, enabling it first.
///
/// Only one process may trace init, so the current monitor goes first and ours re-arms
/// the zygote the previous implementation left behind. A handover that does not come up
/// is rolled back to the provider that was replaced.
fn switch_to_builtin() -> Result<()> {
    let providers = active_providers();
    // Only the providers that are actually running come back on a failed handover;
    // replaying an idle one would start a second implementation next to the built-in.
    let previous: Vec<PathBuf> = providers
        .iter()
        .filter(|path| provider_dir_running(path))
        .cloned()
        .collect();
    let was_enabled = is_enabled();
    // Enabling it also starts it: the flag alone only counts from the next boot.
    enable()?;

    // Already the implementation in charge, with nothing of the replaced one running.
    // A live monitor and daemon are not enough: only an injected zygote actually serves
    // the modules, and a handover that never got there has to be finished here.
    if is_monitor_active() && is_daemon_active() && provider_pids(&providers).is_empty() {
        if zygote_injected() {
            return Ok(());
        }
        // The monitor already owns init, so a rearm finishes the job without restarting it.
        if let Some(tracer) = tracer_path() {
            let _ = send_rearm(&tracer);
        }
        if wait_until(zygote_injected, SWITCH_WAIT_SECS * 2) {
            return Ok(());
        }
        info!("The running monitor did not inject the zygote, restarting it");
    }

    stop_current(&providers);
    if let Err(e) = start_switched() {
        rollback(was_enabled, &previous);
        return Err(e);
    }
    info!("Switched to the built-in Zygisk without restarting the zygote");
    Ok(())
}

/// Switch back to an installed provider module.
///
/// Our monitor and daemons stop, the staged copy goes away so the module owns its boot
/// scripts again, and the module's own entry script starts against the running zygote.
fn switch_to_provider(id: &str) -> Result<()> {
    let dir = provider_dir(id).with_context(|| format!("Zygisk provider {id} is not installed"))?;
    let dir_id = dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(id)
        .to_owned();
    if dir.join(DISABLE_FILE_NAME).exists() || dir.join(REMOVE_FILE_NAME).exists() {
        bail!("{dir_id} is disabled");
    }
    if !has_start_script(&dir) {
        bail!("{dir_id} has no Zygisk start script");
    }
    // By executable path, not process name: the built-in uses the same names.
    let dirs = [dir.clone()];
    if !is_enabled() && !provider_pids(&dirs).is_empty() {
        return Ok(());
    }

    let was_enabled = is_enabled();
    // Another provider may still be the one tracing init.
    let others: Vec<PathBuf> = active_providers()
        .into_iter()
        .filter(|path| path != &dir)
        .collect();
    // Whoever is actually serving the zygote right now gets put back if this fails.
    let previous: Vec<PathBuf> = others
        .iter()
        .filter(|path| provider_dir_running(path))
        .cloned()
        .collect();

    shutdown()?;
    // The socket is only one way to find our monitor; its binaries are the other.
    stop_staged_processes();
    stop_provider_processes(&others);

    disable()?;
    // Only the staged copy: the work dir is shared with a standalone NyaZygisk module,
    // and `cleanup_disabled` skips it once nothing of ours is staged.
    remove_leftover(BUILTIN_ZYGISK_DIR);

    let mut daemon_up = || !provider_pids(&dirs).is_empty();
    let started = start_provider(&dir).is_ok_and(|entry| {
        wait_until(&mut daemon_up, SWITCH_WAIT_SECS)
            // Some providers start the daemon from `service.sh`, not from the entry script.
            || (entry != "service.sh"
                && replay_service(&dir)
                && wait_until(&mut daemon_up, SWITCH_WAIT_SECS))
    });
    if !started {
        // Nothing took over: put the previous implementation back.
        rollback_to_previous(was_enabled, &dir, &previous);
        bail!("{dir_id} did not take over the zygote");
    }
    info!("Switched to the {dir_id} Zygisk provider without restarting the zygote");
    Ok(())
}

/// The scripts a provider can be started from, in the order a boot would run them.
const PROVIDER_START_SCRIPTS: [&str; 3] = ["zygisk-init.sh", "post-fs-data.sh", "service.sh"];

fn has_start_script(dir: &Path) -> bool {
    PROVIDER_START_SCRIPTS
        .iter()
        .any(|name| dir.join(name).exists())
}

fn replay_service(dir: &Path) -> bool {
    let service = dir.join("service.sh");
    if !service.exists() {
        return false;
    }
    crate::module::exec_script(&service, crate::module::ScriptWait::NoWait).is_ok()
}

/// Best effort after a failed handover: stop whatever half-started and give the system
/// back to the implementation that owned it, a provider module or the built-in.
///
/// A switch from one provider to another must not leave the device without Zygisk, so
/// the previously running provider is replayed before falling back to the built-in.
fn rollback_to_previous(was_enabled: bool, target: &Path, previous: &[PathBuf]) {
    stop_provider_processes(&[target.to_path_buf()]);
    stop_staged_processes();
    if !previous.is_empty() {
        restore_provider(previous);
        let up = || {
            previous
                .iter()
                .any(|dir| !provider_pids(std::slice::from_ref(dir)).is_empty())
        };
        if wait_until(up, SWITCH_WAIT_SECS) {
            return;
        }
        warn!("The replaced Zygisk provider did not come back");
    }
    if !was_enabled {
        return;
    }
    let _ = enable();
    let _ = start_switched();
}

/// Replay a provider's own entry script, the same one its boot would run. Returns the
/// script name it picked.
fn start_provider(dir: &Path) -> Result<&'static str> {
    let entry = PROVIDER_START_SCRIPTS
        .iter()
        .map(|name| (*name, dir.join(name)))
        .find(|(_, path)| path.exists());
    let Some((name, path)) = entry else {
        bail!("{} has no Zygisk start script", dir.display());
    };
    info!("Starting {} to hand Zygisk over", path.display());
    crate::module::exec_script(&path, crate::module::ScriptWait::NoWait)?;
    Ok(name)
}

/// Start our monitor and daemon over the zygote the previous implementation left behind.
fn start_switched() -> Result<()> {
    bootstrap()?;
    if !wait_until(monitor_reachable, SWITCH_WAIT_SECS) {
        bail!("the built-in monitor did not start");
    }
    let tracer = tracer_path().context("built-in Zygisk tracer is missing")?;
    // The rearm is what injects the running zygote, and it only works once the monitor
    // has taken init over; a socket that exists is not enough.
    wait_until(is_monitor_active, SWITCH_WAIT_SECS * 2);

    // Injection is the goal: a daemon can come up without the zygote being served.
    let injected = || is_monitor_active() && is_daemon_active() && zygote_injected();
    send_rearm(&tracer)?;
    if !wait_until(injected, SWITCH_WAIT_SECS * 2) {
        // A monitor that took init over a moment late misses the first rearm.
        info!("Zygote was not injected by the first rearm, retrying");
        send_rearm(&tracer)?;
        if !wait_until(injected, SWITCH_WAIT_SECS * 2) {
            bail!("the built-in did not inject the running zygote");
        }
    }
    Ok(())
}

fn rollback(was_enabled: bool, providers: &[PathBuf]) {
    // Our monitor may already own init; the provider's cannot start until it lets go.
    let _ = shutdown();
    if !was_enabled {
        let _ = disable();
    }
    restore_provider(providers);
}

/// Stop whatever owns init today: a NyaZygisk monitor understands `ctl exit`, anything
/// else is terminated by path, daemons included.
fn stop_current(providers: &[PathBuf]) {
    if monitor_reachable() {
        if let Some(tracer) = tracer_path().or_else(|| provider_tracer(providers)) {
            info!("Stopping the current Zygisk monitor");
            let _ = Command::new(&tracer).args(["ctl", "exit"]).status();
        }
        // The ptrace attachment to init is released at exit, not when the socket closes,
        // so wait for the process too: ours cannot seize init before that.
        if !wait_until(
            || !monitor_reachable() && !any_tracer_running(),
            SHUTDOWN_WAIT_SECS,
        ) {
            warn!("The current Zygisk monitor is still running");
        }
    }
    stop_provider_processes(providers);
}

/// A tracer of the replaced provider, used to send `ctl exit` when nothing of ours is
/// staged yet.
fn provider_tracer(providers: &[PathBuf]) -> Option<PathBuf> {
    providers.iter().find_map(|dir| {
        ["zygisk-ptrace64", "zygisk-ptrace32"]
            .iter()
            .map(|name| dir.join("bin").join(*name))
            .find(|path| path.exists())
    })
}

fn stop_provider_processes(providers: &[PathBuf]) {
    let victims = provider_pids(providers);
    if victims.is_empty() {
        return;
    }
    info!(
        "Stopping {} process(es) of the replaced Zygisk provider",
        victims.len()
    );
    signal_all(&victims, libc::SIGTERM);
    if !wait_until(|| !any_alive(&victims), SWITCH_WAIT_SECS) {
        signal_all(&victims, libc::SIGKILL);
        wait_until(|| !any_alive(&victims), SWITCH_WAIT_SECS);
    }
}

/// Our own processes, found by executable path so a monitor whose control socket is gone
/// cannot keep init to itself.
fn stop_staged_processes() {
    let victims: Vec<i32> = staged_processes("")
        .into_iter()
        .map(|(pid, _)| pid)
        .collect();
    if victims.is_empty() {
        return;
    }
    info!("Stopping {} built-in Zygisk process(es)", victims.len());
    signal_all(&victims, libc::SIGTERM);
    if !wait_until(|| !any_alive(&victims), SWITCH_WAIT_SECS) {
        signal_all(&victims, libc::SIGKILL);
        wait_until(|| !any_alive(&victims), SWITCH_WAIT_SECS);
    }
}

/// A zombie has no executable link, so a process that lost `exe` is gone for our purposes.
fn any_alive(pids: &[i32]) -> bool {
    pids.iter()
        .any(|pid| fs::read_link(format!("/proc/{pid}/exe")).is_ok())
}

/// Zygisk processes of the given providers, matched by the directory they were started
/// from. Providers name their processes freely (`zn-daemon`, `rezygiskd`, or a bare fd
/// number after `execveat`), so the module directory is the only reliable marker.
fn provider_pids(providers: &[PathBuf]) -> Vec<i32> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut pids = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(exe) = fs::read_link(entry.path().join("exe")) else {
            continue;
        };
        if providers.iter().any(|dir| exe.starts_with(dir)) {
            pids.push(pid);
        }
    }
    pids
}

/// Whether a provider module has any process running right now.
fn provider_dir_running(dir: &Path) -> bool {
    !provider_pids(&[dir.to_path_buf()]).is_empty()
}

fn signal_all(pids: &[i32], signal: i32) {
    for &pid in pids {
        let _ = unsafe { libc::kill(pid, signal) };
    }
}

/// Best effort: bring the replaced provider back after a failed handover.
fn restore_provider(providers: &[PathBuf]) {
    for dir in providers {
        if let Err(e) = start_provider(dir) {
            warn!("Restoring {} failed: {e}", dir.display());
        }
    }
}

fn wait_until(mut condition: impl FnMut() -> bool, secs: u32) -> bool {
    for _ in 0..secs * 10 {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    condition()
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
        (ASSET_ZYGISK_LIB, native_lib),
        (ASSET_ZYGISK32_LIB, secondary_lib),
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
    is_process_running_matching_paths(|name| name == "zygote" || name == "zygote64")
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
///
/// A monitor that stays alive is reported as an error: it still traces init, so a soft
/// reboot would replay post-fs-data against a traced init and every later switch would
/// be refused by the kernel.
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
    let exited = Command::new(&tracer)
        .args(["ctl", "exit"])
        .status()
        .is_ok_and(|status| status.success());
    if !exited {
        warn!("ctl exit failed, stopping the built-in Zygisk monitor by pid");
    }
    // Only one process may trace init, and the ptrace attachment outlives the control
    // socket, so wait for the process rather than the socket.
    if wait_until(|| !is_monitor_running(), SHUTDOWN_WAIT_SECS) {
        return Ok(());
    }
    stop_staged_processes();
    if wait_until(|| !is_monitor_running(), SWITCH_WAIT_SECS) {
        return Ok(());
    }
    bail!("the built-in Zygisk monitor did not exit");
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
