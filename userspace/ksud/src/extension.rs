//! Extension management for ksud.
//!
//! Parallels [`crate::feature`] but for the `extension` subsystem
//! (`uapi/extension.h`). The kernel reports a `supported` flag per id
//! so the CLI can show a "Not supported by this kernel" hint rather
//! than failing when an extension handler is missing.
//!
//! Persisted values live in [`EXTENSION_CONFIG_PATH`] in the same
//! binary format as `feature::FEATURE_CONFIG_PATH`. Forced-by-config
//! entries (kernel `force_extension=`) and module-managed entries are
//! not persisted: the kernel re-applies forced values, and modules
//! own their entries.

use anyhow::{Context, Result, bail};
use const_format::concatcp;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use crate::defs;
#[cfg(target_os = "android")]
use crate::extension_id::{ExtensionId, parse_extension_id};
#[cfg(target_os = "android")]
use crate::ksu_uapi;

const EXTENSION_CONFIG_PATH: &str = concatcp!(defs::WORKING_DIR, ".extension_config");
#[allow(clippy::unreadable_literal)]
const EXTENSION_MAGIC: u32 = 0x7f4b_4558; // \x7fKEX
const EXTENSION_VERSION: u32 = 1;

const fn on_extension_applied(_extension_id: u32, _value: u64) {}

#[cfg(target_os = "android")]
fn set_kernel_extension(extension_id: u32, name: &str, value: u64) -> Result<()> {
    crate::ksucalls::set_extension(extension_id, value)
        .with_context(|| format!("Failed to set extension {name} to {value}"))?;
    on_extension_applied(extension_id, value);
    Ok(())
}

/// Whether `state` exposes a runtime sticky bit.
///
/// Known ids keep the ABI-0 fallback in [`ExtensionId::is_sticky`]; an id
/// this build has never heard of can only be judged from the kernel's own
/// capability bits, which are always present when enumeration works.
#[cfg(target_os = "android")]
fn is_sticky(known: Option<ExtensionId>, state: &crate::ksucalls::ExtensionState) -> bool {
    known.map_or_else(
        || state.caps_known() && state.has_cap(ksu_uapi::KSU_EXTENSION_FLAG_STICKY),
        |id| id.is_sticky(state),
    )
}

#[cfg(target_os = "android")]
fn is_persistent(known: Option<ExtensionId>, state: &crate::ksucalls::ExtensionState) -> bool {
    known.map_or_else(
        || state.caps_known() && state.has_cap(ksu_uapi::KSU_EXTENSION_FLAG_PERSIST),
        |id| id.is_persistent(state),
    )
}

#[cfg(target_os = "android")]
fn extension_display_name(id: u32, known: Option<ExtensionId>) -> String {
    known.map_or_else(|| format!("#{id}"), |id| id.name().to_owned())
}

/// Resolve a CLI argument (known name, numeric id, or a name the kernel
/// reported through KSU_EXTENSION_ENUM) into an id and display name.
///
/// The numeric and kernel-name paths are what let a manager built before a
/// new extension existed still drive it.
#[cfg(target_os = "android")]
fn resolve_extension_arg(id: &str) -> Result<(u32, String, Option<ExtensionId>)> {
    if let Ok(known) = parse_extension_id(id) {
        return Ok((known as u32, known.name().to_owned(), Some(known)));
    }

    if let Ok(raw) = id.parse::<u32>() {
        let known = ExtensionId::from_u32(raw);
        let name = known.map_or_else(
            || {
                crate::ksucalls::enumerate_extensions()
                    .ok()
                    .and_then(|descriptors| {
                        descriptors
                            .into_iter()
                            .find(|desc| desc.id == raw)
                            .map(|desc| desc.name)
                    })
                    .unwrap_or_else(|| format!("#{raw}"))
            },
            |known| known.name().to_owned(),
        );
        return Ok((raw, name, known));
    }

    if let Ok(descriptors) = crate::ksucalls::enumerate_extensions()
        && let Some(desc) = descriptors.into_iter().find(|desc| desc.name == id)
    {
        return Ok((desc.id, desc.name, ExtensionId::from_u32(desc.id)));
    }

    bail!("Unknown extension: {id}")
}

/// One row rendered by `extension list`, saved by `extension save`, and
/// applied from `.extension_config` at boot. `known` is `None` for handlers
/// this ksud build has no compiled-in enum entry for.
#[cfg(target_os = "android")]
struct ExtensionRow {
    id: u32,
    name: String,
    known: Option<ExtensionId>,
    state: crate::ksucalls::ExtensionState,
}

#[cfg(target_os = "android")]
struct ExtensionRows {
    rows: Vec<ExtensionRow>,
    /// True when the kernel answered KSU_EXTENSION_ENUM, i.e. rows came from
    /// the kernel's handler table rather than the static enum.
    enumerated: bool,
}

#[cfg(target_os = "android")]
fn discover_extension_rows() -> ExtensionRows {
    let mut rows = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut enumerated = false;

    if let Ok(descriptors) = crate::ksucalls::enumerate_extensions()
        && !descriptors.is_empty()
    {
        enumerated = true;
        let api_version = crate::ksucalls::extension_api_version();

        for desc in descriptors {
            let mut state = crate::ksucalls::get_extension(desc.id)
                .unwrap_or_else(|_| crate::ksucalls::unknown_extension_state());
            // GET supplies the live value; the descriptor is authoritative
            // for presence and capabilities even when a handler has no
            // ops->get. A handler whose min ABI is newer than this ksud is
            // not usable, so do not resurrect its caps from the descriptor.
            let abi_ok = desc.min_api_version == 0 || desc.min_api_version <= api_version;
            if abi_ok {
                state.caps |= desc.caps;
                state.supported |= desc.caps & ksu_uapi::KSU_FEATURE_FLAG_SUPPORTED != 0;
            }
            state.forced |= desc.forced;
            seen.insert(desc.id);
            rows.push(ExtensionRow {
                id: desc.id,
                name: desc.name,
                known: ExtensionId::from_u32(desc.id),
                state,
            });
        }
    }

    // Keep the historical "unsupported" rows for compiled-in extensions the
    // kernel did not register, so the CLI and the manager keep showing them
    // instead of silently dropping a build option.
    for known in ExtensionId::ALL {
        let id = known as u32;
        if !seen.insert(id) {
            continue;
        }
        let state = crate::ksucalls::get_extension(id)
            .unwrap_or_else(|_| crate::ksucalls::unknown_extension_state());
        rows.push(ExtensionRow {
            id,
            name: known.name().to_owned(),
            known: Some(known),
            state,
        });
    }

    ExtensionRows { rows, enumerated }
}

/// Read a single extension's current sticky state from the kernel.
/// Returns `Ok(None)` if the kernel did not register a handler for
/// the id (UI shows a "Not supported" hint in that case).
#[cfg(target_os = "android")]
#[allow(dead_code)] // exposed for external ksud callers
pub fn probe(id: ExtensionId) -> Result<Option<crate::ksucalls::ExtensionState>> {
    let state = crate::ksucalls::get_extension(id as u32)
        .with_context(|| format!("Failed to probe extension {}", id.name()))?;
    Ok(state.supported.then_some(state))
}

/// Whether the KPM subsystem is actually usable on this device.
///
/// The KSU_EXTENSION_GET handler only reflects `CONFIG_KPM`; on a
/// kernel that was built with KPM but where the control surface is
/// not reachable (e.g. a stub `do_kpm` that returns -EOPNOTSUPP), the
/// handler still reports "supported". A live `kpm version` ioctl
/// distinguishes the two. Used by both `check_extension` and
/// `list_extensions` so the answer is computed once per ksud
/// invocation. Always returns `false` on non-aarch64 builds: KPM is
/// aarch64-only and the `kpm` module is not compiled in for other
/// arches.
#[cfg(target_os = "android")]
#[allow(clippy::missing_const_for_fn)] // aarch64 branch calls check_version() which is non-const
pub fn kpm_actually_working() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        crate::kpm::check_version().is_ok_and(|v| !v.is_empty())
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

/// Whether the SuSFS module is actually installed.
///
/// The KSU_EXTENSION_GET handler only reports "supported" when the
/// kernel is built with the SuSFS extension stub. A live `susfs status`
/// ioctl distinguishes the two (stub returns success but the module may
/// not be installed). Used by `check_extension` and `list_extensions`
/// so the answer is computed once per ksud invocation.
#[cfg(all(target_os = "android", target_arch = "aarch64"))]
pub fn susfs_actually_working() -> bool {
    crate::susfs::get_susfs_status()
}

/// Stub for non-aarch64 builds (susfs module is aarch64-only).
#[cfg(not(all(target_os = "android", target_arch = "aarch64")))]
pub const fn susfs_actually_working() -> bool {
    false
}

pub fn load_binary_config() -> Result<HashMap<u32, u64>> {
    let path = Path::new(EXTENSION_CONFIG_PATH);
    if !path.exists() {
        log::info!("Extension config not found, using defaults");
        return Ok(HashMap::new());
    }

    let mut file = File::open(path).with_context(|| "Failed to open extension config")?;

    let mut magic_buf = [0u8; 4];
    file.read_exact(&mut magic_buf)
        .with_context(|| "Failed to read magic")?;
    let magic = u32::from_le_bytes(magic_buf);

    if magic != EXTENSION_MAGIC {
        bail!(
            "Invalid extension config magic: expected 0x{EXTENSION_MAGIC:08x}, got 0x{magic:08x}"
        );
    }

    let mut version_buf = [0u8; 4];
    file.read_exact(&mut version_buf)
        .with_context(|| "Failed to read version")?;
    let version = u32::from_le_bytes(version_buf);

    if version != EXTENSION_VERSION {
        log::warn!(
            "Extension config version mismatch: expected {EXTENSION_VERSION}, got {version}"
        );
    }

    let mut count_buf = [0u8; 4];
    file.read_exact(&mut count_buf)
        .with_context(|| "Failed to read count")?;
    let count = u32::from_le_bytes(count_buf);

    let mut extensions = HashMap::new();
    for _ in 0..count {
        let mut id_buf = [0u8; 4];
        let mut value_buf = [0u8; 8];

        file.read_exact(&mut id_buf)
            .with_context(|| "Failed to read extension id")?;
        file.read_exact(&mut value_buf)
            .with_context(|| "Failed to read extension value")?;

        let id = u32::from_le_bytes(id_buf);
        let value = u64::from_le_bytes(value_buf);

        extensions.insert(id, value);
    }

    log::info!("Loaded {} extensions from config", extensions.len());
    Ok(extensions)
}

pub fn save_binary_config(extensions: &HashMap<u32, u64>) -> Result<()> {
    crate::utils::ensure_dir_exists(Path::new(defs::WORKING_DIR))?;

    let path = Path::new(EXTENSION_CONFIG_PATH);
    let mut file = File::create(path).with_context(|| "Failed to create extension config")?;

    file.write_all(&EXTENSION_MAGIC.to_le_bytes())
        .with_context(|| "Failed to write magic")?;
    file.write_all(&EXTENSION_VERSION.to_le_bytes())
        .with_context(|| "Failed to write version")?;

    let count = extensions.len() as u32;
    file.write_all(&count.to_le_bytes())
        .with_context(|| "Failed to write count")?;

    for (&id, &value) in extensions {
        file.write_all(&id.to_le_bytes())
            .with_context(|| format!("Failed to write extension id {id}"))?;
        file.write_all(&value.to_le_bytes())
            .with_context(|| format!("Failed to write extension value for id {id}"))?;
    }

    file.sync_all()
        .with_context(|| "Failed to sync extension config")?;

    log::info!("Saved {} extensions to config", extensions.len());
    Ok(())
}

#[cfg(target_os = "android")]
fn apply_config(extensions: &HashMap<u32, u64>) {
    log::info!("Applying extension configuration to kernel...");

    let mut applied = 0;
    for (&id, &value) in extensions {
        if id == ExtensionId::VersionSpoof as u32 {
            log::debug!("Version overrides are restored by version_spoof::apply_saved");
            continue;
        }
        let known = ExtensionId::from_u32(id);
        // A failed probe is not evidence about the extension, so fall
        // through and let the kernel decide at SET time; only skip when the
        // kernel positively reports it cannot use the value.
        let state = crate::ksucalls::get_extension(id).ok();
        if state.is_some_and(|state| state.forced) {
            log::info!("Skip extension {id}: forced by boot config");
            continue;
        }
        // The kernel decides whether a sticky bit exists at all; the
        // static table only covers kernels that predate capability
        // negotiation.
        if state.is_some_and(|state| !is_sticky(known, &state)) {
            log::info!("Skip extension {id}: no runtime sticky bit");
            continue;
        }
        let name = extension_display_name(id, known);
        match set_kernel_extension(id, &name, value) {
            Ok(()) => {
                log::info!("Set extension {name} to {value}");
                applied += 1;
            }
            Err(e) => {
                log::warn!("Failed to set extension {name}: {e}");
            }
        }
    }

    log::info!("Applied {applied} extensions successfully");
}

#[cfg(target_os = "android")]
pub fn get_extension_cli(id: &str) -> Result<()> {
    let (extension_id, name, known) = resolve_extension_arg(id)?;
    let state = crate::ksucalls::get_extension(extension_id)
        .with_context(|| format!("Failed to get extension {name}"))?;

    if !state.supported {
        println!("Extension '{name}' is not supported by kernel");
        return Ok(());
    }

    println!("Extension: {name} ({extension_id})");
    println!(
        "Description: {}",
        known.map_or("Kernel-provided extension.", |known| known.description())
    );
    println!("Value: {}", state.value);
    println!(
        "Status: {}",
        if is_sticky(known, &state) {
            if state.value != 0 {
                "enabled"
            } else {
                "disabled"
            }
        } else {
            "available (no runtime switch)"
        }
    );
    if state.forced {
        println!("Forced: by boot config");
    }
    // Capability bits are only present from extension ABI 1 onwards; on an
    // older kernel every bit below would be a guess, so say so instead of
    // printing a table of "no".
    if state.caps_known() {
        println!(
            "Capabilities: sticky={} persist={} per_uid={} reboot={}",
            u32::from(is_sticky(known, &state)),
            u32::from(is_persistent(known, &state)),
            u32::from(state.has_cap(ksu_uapi::KSU_EXTENSION_FLAG_PER_UID)),
            u32::from(state.has_cap(ksu_uapi::KSU_EXTENSION_FLAG_REBOOT)),
        );
        println!("Extension ABI: {}", state.api_version);
    } else {
        println!("Capabilities: unavailable (kernel predates extension ABI)");
    }

    Ok(())
}

#[cfg(target_os = "android")]
pub fn get_extension_config_cli(id: &str) -> Result<()> {
    let (extension_id, name, known) = resolve_extension_arg(id)?;

    let extensions = load_binary_config()?;

    println!("Extension: {name} ({extension_id})");
    println!(
        "Description: {}",
        known.map_or("Kernel-provided extension.", |known| known.description())
    );

    if let Some(value) = extensions.get(&extension_id) {
        println!("Value: {value}");
        println!(
            "Status: {}",
            if *value != 0 { "enabled" } else { "disabled" }
        );
    } else {
        println!("Not set in config");
    }

    Ok(())
}

#[cfg(target_os = "android")]
pub fn set_extension_cli(id: &str, value: u64) -> Result<()> {
    let (extension_id, name, known) = resolve_extension_arg(id)?;
    let state = crate::ksucalls::get_extension(extension_id)
        .unwrap_or_else(|_| crate::ksucalls::unknown_extension_state());

    if !state.supported {
        bail!("Extension '{name}' is not supported by this kernel.");
    }

    if !is_sticky(known, &state) {
        bail!("Extension '{name}' does not have a runtime enable/disable switch (value={value}).");
    }

    // Only 0/1 are meaningful: the kernel's `value != 0` check would
    // silently coerce 42 to "enabled", which is a footgun for boot-config
    // generators and human-typed values alike.
    if !matches!(value, 0 | 1) {
        bail!("Extension '{name}' only accepts 0 or 1 (got {value}).");
    }

    if state.forced {
        bail!(
            "Extension '{name}' is forced to {} by boot config. Direct modification is not allowed.",
            state.value
        );
    }

    if let Ok(managed_extensions_map) = crate::module::get_managed_extensions() {
        let managing_modules: Vec<&String> = managed_extensions_map
            .iter()
            .filter(|(_, exts)| exts.iter().any(|e| e == &name))
            .map(|(module_id, _)| module_id)
            .collect();

        if !managing_modules.is_empty() {
            let caller_module = std::env::var("KSU_MODULE").unwrap_or_default();

            if caller_module.is_empty() || !managing_modules.contains(&&caller_module) {
                bail!(
                    "Extension '{name}' is managed by module(s): {}. Direct modification is not allowed.",
                    managing_modules
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            log::info!("Module '{caller_module}' is setting managed extension '{name}'");
        }
    }

    set_kernel_extension(extension_id, &name, value)?;

    // Persist future sticky extensions the same way the DynamicManager
    // path persists its own enabled bit. DynamicManager keeps its state in
    // its own file, so writing it here too would create a second source of
    // truth that can drift.
    if is_persistent(known, &state) && known != Some(ExtensionId::DynamicManager) {
        let mut extensions = load_binary_config().unwrap_or_default();
        extensions.insert(extension_id, value);
        if let Err(e) = save_binary_config(&extensions) {
            log::warn!("Failed to persist extension {name}: {e}");
        }
    }

    println!(
        "Extension '{name}' set to {value} ({})",
        if value != 0 { "enabled" } else { "disabled" }
    );

    Ok(())
}

#[cfg(target_os = "android")]
pub fn list_extensions() {
    println!("Available Extensions:");
    println!("{}", "=".repeat(80));

    let managed_extensions_map = crate::module::get_managed_extensions().unwrap_or_default();
    let ExtensionRows { rows, enumerated } = discover_extension_rows();

    let is_kpm = |row: &ExtensionRow| row.known == Some(ExtensionId::Kpm) || row.name == "kpm";
    let is_susfs =
        |row: &ExtensionRow| row.known == Some(ExtensionId::Susfs) || row.name == "susfs";

    // Lazy KPM probe: only run the live `kpm version` ioctl if the kernel
    // already advertised CONFIG_KPM support. On non-KPM builds this saves
    // a syscall on every `extension list`.
    let kpm_advertised = rows.iter().any(|row| is_kpm(row) && row.state.supported);
    let kpm_working = kpm_advertised && kpm_actually_working();

    // Lazy SuSFS probe: only run `susfs status` if the kernel advertised
    // SuSFS support (i.e. the stub handler is registered).
    let susfs_advertised = rows.iter().any(|row| is_susfs(row) && row.state.supported);
    let susfs_working = susfs_advertised && susfs_actually_working();

    let really_supported = |row: &ExtensionRow| {
        row.state.supported && (!is_kpm(row) || kpm_working) && (!is_susfs(row) || susfs_working)
    };

    let mut extension_to_modules: HashMap<String, Vec<String>> = HashMap::new();
    for (module_id, ext_list) in &managed_extensions_map {
        for ext_name in ext_list {
            extension_to_modules
                .entry(ext_name.clone())
                .or_default()
                .push(module_id.clone());
        }
    }

    for row in &rows {
        let supported = really_supported(row);
        let sticky = is_sticky(row.known, &row.state);

        let label = if !supported {
            "NOT_SUPPORTED".to_string()
        } else if !sticky {
            "AVAILABLE".to_string()
        } else if row.state.value != 0 {
            format!("ENABLED ({})", row.state.value)
        } else {
            "DISABLED".to_string()
        };

        let managed_by = extension_to_modules.get(&row.name);
        let managed_mark = if row.state.forced {
            " [FORCED]"
        } else if managed_by.is_some() {
            " [MODULE_MANAGED]"
        } else {
            ""
        };

        println!("[{}] {} (ID={}){}", label, row.name, row.id, managed_mark);
        println!(
            "    {}",
            row.known
                .map_or("Kernel-provided extension.", |known| known.description())
        );

        if let Some(modules) = managed_by {
            println!(
                "    ⚠️  Managed by module(s): {} (controlled by module, ksud will skip persistence)",
                modules.join(", ")
            );
        }

        println!();
    }

    // Machine-readable block for `extension list --json`-style
    // consumers (the manager UI pulls every state in one shell call
    // to avoid paying N× the libksud.so startup cost). Lines starting
    // with "EXTENSION_LIST_V1" are guaranteed stable: the manager-side
    // parser keys on this exact prefix.
    //
    // V1 is emitted unconditionally for consumers built before the
    // capability bits existed. It has no room for them, and appending a
    // field would break the managers' `matchEntire` regex, so the new
    // bits travel in a second row per extension instead:
    //
    //   EXTENSION_LIST_V1 name=<wire-name> id=<u32> supported=<0|1> \
    //                     forced=<0|1> value=<u64> managed=<0|1> \
    //                     sticky=<0|1>
    //   EXTENSION_LIST_V2 name=<wire-name> id=<u32> caps=<0x%08x> api=<u32> \
    //                     sticky=<0|1> persist=<0|1> per_uid=<0|1> reboot=<0|1>
    //   EXTENSION_LIST_V3 ... (ABI 2+ only; see below)
    //   EXTENSION_LIST_END
    //
    // V3 enumerates the kernel's handler table instead of the compiled-in
    // ids, so it is the only row set that can describe an extension this
    // ksud build did not know about. It repeats every field so a V3-aware
    // manager never has to merge V1/V2 by hand. Old managers ignore the
    // unknown prefix and keep reading V1/V2.
    //
    // In all rows `sticky` is the kernel's answer when it publishes
    // capabilities, and the static table only as a fallback for ABI-0
    // kernels. `api=0` in a V2 row means the kernel predates the probe,
    // so `caps` carries nothing beyond SUPPORTED/FORCED and the sticky
    // bit is the fallback value.
    for extension_id in &ExtensionId::ALL {
        let id = *extension_id as u32;
        let row = rows.iter().find(|row| row.id == id);
        let state = row.map(|row| row.state).unwrap_or_default();
        let supported = row.is_some_and(really_supported);
        let managed = extension_to_modules
            .get(extension_id.name())
            .is_some_and(|v| !v.is_empty());
        println!(
            "EXTENSION_LIST_V1 name={} id={} supported={} forced={} value={} managed={} sticky={}",
            extension_id.name(),
            id,
            u32::from(supported),
            u32::from(state.forced),
            state.value,
            u32::from(managed),
            u32::from(is_sticky(Some(*extension_id), &state)),
        );
    }
    for extension_id in &ExtensionId::ALL {
        let id = *extension_id as u32;
        let state = rows
            .iter()
            .find(|row| row.id == id)
            .map(|row| row.state)
            .unwrap_or_default();
        println!(
            "EXTENSION_LIST_V2 name={} id={} caps=0x{:08x} api={} sticky={} persist={} per_uid={} reboot={}",
            extension_id.name(),
            id,
            state.caps,
            state.api_version,
            u32::from(is_sticky(Some(*extension_id), &state)),
            u32::from(is_persistent(Some(*extension_id), &state)),
            u32::from(state.has_cap(ksu_uapi::KSU_EXTENSION_FLAG_PER_UID)),
            u32::from(state.has_cap(ksu_uapi::KSU_EXTENSION_FLAG_REBOOT)),
        );
    }
    if enumerated {
        for row in &rows {
            let managed = extension_to_modules
                .get(&row.name)
                .is_some_and(|v| !v.is_empty());
            println!(
                "EXTENSION_LIST_V3 name={} id={} caps=0x{:08x} api={} supported={} forced={} value={} managed={} sticky={} persist={} per_uid={} reboot={}",
                row.name,
                row.id,
                row.state.caps,
                row.state.api_version,
                u32::from(really_supported(row)),
                u32::from(row.state.forced),
                row.state.value,
                u32::from(managed),
                u32::from(is_sticky(row.known, &row.state)),
                u32::from(is_persistent(row.known, &row.state)),
                u32::from(row.state.has_cap(ksu_uapi::KSU_EXTENSION_FLAG_PER_UID)),
                u32::from(row.state.has_cap(ksu_uapi::KSU_EXTENSION_FLAG_REBOOT)),
            );
        }
    }
    println!("EXTENSION_LIST_END");
}

#[cfg(target_os = "android")]
pub fn load_config_and_apply() -> Result<()> {
    let extensions = load_binary_config()?;

    if extensions.is_empty() {
        println!("No extensions found in config file");
        return Ok(());
    }

    apply_config(&extensions);
    println!("Extension configuration loaded and applied");
    Ok(())
}

#[cfg(target_os = "android")]
pub fn save_config() -> Result<()> {
    let mut extensions = load_binary_config().unwrap_or_default();
    let ExtensionRows { rows, .. } = discover_extension_rows();

    for row in rows {
        // Leave the on-disk value alone when the probe fails: an
        // unreadable extension has not told us anything about its
        // persistence, and dropping the entry would lose the setting.
        if !row.state.supported {
            continue;
        }
        // A sticky-but-not-persistent extension offers a switch for the
        // current boot only, so writing it here would replay a state the
        // extension explicitly does not carry across boots.
        if !is_persistent(row.known, &row.state) {
            extensions.remove(&row.id);
            continue;
        }
        if !row.state.forced {
            extensions.insert(row.id, row.state.value);
            log::info!("Saved extension {} = {}", row.name, row.state.value);
        }
    }

    save_binary_config(&extensions)?;
    println!(
        "Current extension states saved to config file ({} extensions)",
        extensions.len()
    );
    Ok(())
}

#[cfg(target_os = "android")]
pub fn check_extension(id: &str) -> Result<()> {
    let (extension_id, name, known) = resolve_extension_arg(id)?;

    let state = crate::ksucalls::get_extension(extension_id)
        .with_context(|| format!("Failed to get extension {name}"))?;

    if state.forced {
        println!("forced");
        return Ok(());
    }

    let managed_extensions_map = crate::module::get_managed_extensions().unwrap_or_default();
    let is_managed = managed_extensions_map
        .values()
        .any(|exts| exts.iter().any(|e| e == &name));

    if is_managed {
        println!("managed");
        return Ok(());
    }

    if !state.supported {
        println!("unsupported");
        return Ok(());
    }

    // KPM reports supported whenever CONFIG_KPM=y, but the live
    // control surface may still be unreachable. Probe it once.
    if (known == Some(ExtensionId::Kpm) || name == "kpm") && !kpm_actually_working() {
        println!("unsupported");
        return Ok(());
    }

    // SuSFS reports supported whenever the stub handler is registered,
    // but the module may not be installed. Probe it once.
    if (known == Some(ExtensionId::Susfs) || name == "susfs") && !susfs_actually_working() {
        println!("unsupported");
        return Ok(());
    }

    println!("supported");
    Ok(())
}

/// Forced extensions are applied by the kernel itself. Runs
/// regardless of safe mode and the persisted config.
pub fn init_forced_extensions() {
    let ExtensionRows { rows, .. } = discover_extension_rows();
    for row in rows {
        if row.state.forced {
            log::info!(
                "Extension '{}' is forced to {} by boot config, skip loading",
                row.name,
                row.state.value
            );
            on_extension_applied(row.id, row.state.value);
        }
    }
}

#[cfg(target_os = "android")]
pub fn init_extensions() -> Result<()> {
    log::info!("Initializing extensions from config...");
    if let Err(error) = crate::version_spoof::apply_saved() {
        log::warn!("Failed to restore version overrides: {error:#}");
    }

    let mut extensions = load_binary_config()?;

    if let Ok(managed_extensions_map) = crate::module::get_managed_extensions() {
        if !managed_extensions_map.is_empty() {
            log::info!(
                "Found {} modules managing extensions",
                managed_extensions_map.len()
            );

            for (module_id, ext_list) in &managed_extensions_map {
                log::info!(
                    "Module '{module_id}' manages {} extension(s)",
                    ext_list.len()
                );

                for ext_name in ext_list {
                    if let Ok((ext_id_u32, _, _)) = resolve_extension_arg(ext_name) {
                        if extensions.remove(&ext_id_u32).is_some() {
                            log::info!(
                                "  - Skipping managed extension '{ext_name}' (controlled by module: {module_id})",
                            );
                        } else {
                            log::info!(
                                "  - Extension '{ext_name}' is managed by module '{module_id}', skipping",
                            );
                        }
                    } else {
                        log::warn!(
                            "  - Unknown managed extension '{ext_name}' from module '{module_id}', ignoring",
                        );
                    }
                }
            }
        }
    } else {
        log::warn!(
            "Failed to get managed extensions from modules, continuing with normal initialization"
        );
    }

    if extensions.is_empty() {
        log::info!("No extensions to apply, skipping initialization");
        return Ok(());
    }

    apply_config(&extensions);

    save_binary_config(&extensions)?;
    log::info!("Saved extension configuration to file");

    Ok(())
}
