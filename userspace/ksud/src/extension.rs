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

const EXTENSION_CONFIG_PATH: &str = concatcp!(defs::WORKING_DIR, ".extension_config");
#[allow(clippy::unreadable_literal)]
const EXTENSION_MAGIC: u32 = 0x7f4b_4558; // \x7fKEX
const EXTENSION_VERSION: u32 = 1;

const fn on_extension_applied(_extension_id: ExtensionId, _value: u64) {}

#[cfg(target_os = "android")]
fn set_kernel_extension(extension_id: ExtensionId, value: u64) -> Result<()> {
    crate::ksucalls::set_extension(extension_id as u32, value)
        .with_context(|| format!("Failed to set extension {} to {value}", extension_id.name()))?;
    on_extension_applied(extension_id, value);
    Ok(())
}

#[cfg(target_os = "android")]
fn is_forced(id: u32) -> bool {
    crate::ksucalls::get_extension(id).is_ok_and(|state| state.forced)
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
        if is_forced(id) {
            log::info!("Skip extension {id}: forced by boot config");
            continue;
        }
        let Some(ext_id) = ExtensionId::from_u32(id) else {
            log::info!("Skip extension {id}: unknown id");
            continue;
        };
        // KPM, CPU spoof and umount paths have no runtime sticky bit
        // to apply; ignore any persisted entry.
        if !ext_id.has_sticky_bit() {
            log::info!("Skip extension {id}: no runtime sticky bit");
            continue;
        }
        match set_kernel_extension(ext_id, value) {
            Ok(()) => {
                log::info!("Set extension {} to {value}", ext_id.name());
                applied += 1;
            }
            Err(e) => {
                log::warn!("Failed to set extension {}: {e}", ext_id.name());
            }
        }
    }

    log::info!("Applied {applied} extensions successfully");
}

#[cfg(target_os = "android")]
pub fn get_extension_cli(id: &str) -> Result<()> {
    let extension_id = parse_extension_id(id)?;
    let state = crate::ksucalls::get_extension(extension_id as u32)
        .with_context(|| format!("Failed to get extension {id}"))?;

    if !state.supported {
        println!("Extension '{id}' is not supported by kernel");
        return Ok(());
    }

    println!(
        "Extension: {} ({})",
        extension_id.name(),
        extension_id as u32
    );
    println!("Description: {}", extension_id.description());
    println!("Value: {}", state.value);
    println!(
        "Status: {}",
        if state.value != 0 {
            "enabled"
        } else {
            "disabled"
        }
    );
    if state.forced {
        println!("Forced: by boot config");
    }

    Ok(())
}

#[cfg(target_os = "android")]
pub fn get_extension_config_cli(id: &str) -> Result<()> {
    let extension_id = parse_extension_id(id)?;

    let extensions = load_binary_config()?;
    let id_u32 = extension_id as u32;

    println!("Extension: {} ({})", extension_id.name(), id_u32);
    println!("Description: {}", extension_id.description());

    if let Some(value) = extensions.get(&id_u32) {
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
    let extension_id = parse_extension_id(id)?;

    if !extension_id.has_sticky_bit() {
        bail!(
            "Extension '{}' does not have a runtime enable/disable switch (value={value}).",
            extension_id.name()
        );
    }

    // Only DynamicManager currently exposes a sticky bit, and its
    // semantic is "0 = off, 1 = on". Any other value would be silently
    // coerced by the kernel's `value != 0` check, which is a footgun
    // for boot-config generators and human-typed values alike. Reject
    // explicitly here so the caller sees the right error rather than
    // a "set to 42 (enabled)" success line.
    if !matches!(value, 0 | 1) {
        bail!(
            "Extension '{}' only accepts 0 or 1 (got {value}).",
            extension_id.name()
        );
    }

    if let Ok(state) = crate::ksucalls::get_extension(extension_id as u32)
        && state.forced
    {
        bail!(
            "Extension '{}' is forced to {} by boot config. Direct modification is not allowed.",
            extension_id.name(),
            state.value
        );
    }

    if let Ok(managed_extensions_map) = crate::module::get_managed_extensions() {
        let managing_modules: Vec<&String> = managed_extensions_map
            .iter()
            .filter(|(_, exts)| exts.iter().any(|e| e == extension_id.name()))
            .map(|(module_id, _)| module_id)
            .collect();

        if !managing_modules.is_empty() {
            let caller_module = std::env::var("KSU_MODULE").unwrap_or_default();

            if caller_module.is_empty() || !managing_modules.contains(&&caller_module) {
                bail!(
                    "Extension '{}' is managed by module(s): {}. Direct modification is not allowed.",
                    extension_id.name(),
                    managing_modules
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            log::info!(
                "Module '{caller_module}' is setting managed extension '{}'",
                extension_id.name()
            );
        }
    }

    set_kernel_extension(extension_id, value)?;

    println!(
        "Extension '{}' set to {value} ({})",
        extension_id.name(),
        if value != 0 { "enabled" } else { "disabled" }
    );

    Ok(())
}

#[cfg(target_os = "android")]
pub fn list_extensions() {
    println!("Available Extensions:");
    println!("{}", "=".repeat(80));

    let managed_extensions_map = crate::module::get_managed_extensions().unwrap_or_default();

    // First pass: collect each id's kernel-side state. We need this
    // up-front to decide whether KPM is even worth live-probing — if
    // the kernel reports `supported = false` for KPM (no CONFIG_KPM
    // or no handler), there is no point burning an extra ioctl on
    // the `kpm version` probe.
    let mut states: HashMap<ExtensionId, crate::ksucalls::ExtensionState> =
        HashMap::with_capacity(ExtensionId::ALL.len());
    for extension_id in ExtensionId::ALL {
        let id = extension_id as u32;
        let state = crate::ksucalls::get_extension(id).unwrap_or_default();
        states.insert(extension_id, state);
    }

    // Lazy KPM probe: only run the live `kpm version` ioctl if the
    // kernel already advertised CONFIG_KPM support. On non-KPM
    // builds this saves a syscall on every `extension list`.
    let kpm_advertised = states.get(&ExtensionId::Kpm).is_some_and(|s| s.supported);
    let kpm_working = kpm_advertised && kpm_actually_working();

    // Lazy SuSFS probe: only run `susfs status` if the kernel
    // advertised SuSFS support (i.e. the stub handler is registered).
    let susfs_advertised = states.get(&ExtensionId::Susfs).is_some_and(|s| s.supported);
    let susfs_working = susfs_advertised && susfs_actually_working();

    let mut extension_to_modules: HashMap<String, Vec<String>> = HashMap::new();
    for (module_id, ext_list) in &managed_extensions_map {
        for ext_name in ext_list {
            extension_to_modules
                .entry(ext_name.clone())
                .or_default()
                .push(module_id.clone());
        }
    }

    for extension_id in &ExtensionId::ALL {
        let id = *extension_id as u32;
        let state = states.get(extension_id).copied().unwrap_or_default();

        // For KPM, "supported" requires the live ioctl probe to succeed.
        // For SuSFS, "supported" requires the susfs status probe.
        // For the other three, the kernel-side supported flag is enough.
        let really_supported = state.supported
            && (extension_id != &ExtensionId::Kpm || kpm_working)
            && (extension_id != &ExtensionId::Susfs || susfs_working);

        let label = if !really_supported {
            "NOT_SUPPORTED".to_string()
        } else if !extension_id.has_sticky_bit() {
            "AVAILABLE".to_string()
        } else if state.value != 0 {
            format!("ENABLED ({})", state.value)
        } else {
            "DISABLED".to_string()
        };

        let managed_by = extension_to_modules.get(extension_id.name());
        let managed_mark = if state.forced {
            " [FORCED]"
        } else if managed_by.is_some() {
            " [MODULE_MANAGED]"
        } else {
            ""
        };

        println!(
            "[{}] {} (ID={}){}",
            label,
            extension_id.name(),
            id,
            managed_mark
        );
        println!("    {}", extension_id.description());

        if let Some(modules) = managed_by {
            println!(
                "    ⚠️  Managed by module(s): {} (controlled by module, ksud will skip persistence)",
                modules.join(", ")
            );
        }

        println!();
    }

    // Machine-readable block for `extension list --json`-style
    // consumers (the manager UI pulls the four states in one shell
    // call to avoid paying 4× the libksud.so startup cost). Lines
    // starting with "EXTENSION_LIST_V1" are guaranteed stable: the
    // manager-side parser keys on this exact prefix.
    //
    // Format (one line per extension):
    //   EXTENSION_LIST_V1 name=<wire-name> id=<u32> supported=<0|1> \
    //                       forced=<0|1> value=<u64> managed=<0|1> \
    //                       sticky=<0|1>
    //   EXTENSION_LIST_END
    //
    // `sticky` mirrors ExtensionId::has_sticky_bit() — a static
    // property of the id, included for callers that don't have a
    // mirror of the canonical extension_id list.
    for extension_id in &ExtensionId::ALL {
        let id = *extension_id as u32;
        let state = states.get(extension_id).copied().unwrap_or_default();
        let really_supported = state.supported
            && (extension_id != &ExtensionId::Kpm || kpm_working)
            && (extension_id != &ExtensionId::Susfs || susfs_working);
        let managed = extension_to_modules
            .get(extension_id.name())
            .is_some_and(|v| !v.is_empty());
        println!(
            "EXTENSION_LIST_V1 name={} id={} supported={} forced={} value={} managed={} sticky={}",
            extension_id.name(),
            id,
            u32::from(really_supported),
            u32::from(state.forced),
            state.value,
            u32::from(managed),
            u32::from(extension_id.has_sticky_bit()),
        );
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

    for extension_id in &ExtensionId::ALL {
        // Extensions without a runtime sticky bit cannot be toggled,
        // and persisting their (always-0) value would be noise.
        if !extension_id.has_sticky_bit() {
            extensions.remove(&(*extension_id as u32));
            continue;
        }
        let id = *extension_id as u32;
        if let Ok(state) = crate::ksucalls::get_extension(id)
            && state.supported
            && !state.forced
        {
            extensions.insert(id, state.value);
            log::info!("Saved extension {} = {}", extension_id.name(), state.value);
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
    let extension_id = parse_extension_id(id)?;

    let state = crate::ksucalls::get_extension(extension_id as u32)
        .with_context(|| format!("Failed to get extension {id}"))?;

    if state.forced {
        println!("forced");
        return Ok(());
    }

    let managed_extensions_map = crate::module::get_managed_extensions().unwrap_or_default();
    let is_managed = managed_extensions_map
        .values()
        .any(|exts| exts.iter().any(|e| e == extension_id.name()));

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
    if extension_id == ExtensionId::Kpm && !kpm_actually_working() {
        println!("unsupported");
        return Ok(());
    }

    // SuSFS reports supported whenever the stub handler is registered,
    // but the module may not be installed. Probe it once.
    if extension_id == ExtensionId::Susfs && !susfs_actually_working() {
        println!("unsupported");
        return Ok(());
    }

    println!("supported");
    Ok(())
}

/// Forced extensions are applied by the kernel itself. Runs
/// regardless of safe mode and the persisted config.
pub fn init_forced_extensions() {
    for extension_id in ExtensionId::ALL {
        if let Ok(state) = crate::ksucalls::get_extension(extension_id as u32)
            && state.forced
        {
            log::info!(
                "Extension '{}' is forced to {} by boot config, skip loading",
                extension_id.name(),
                state.value
            );
            on_extension_applied(extension_id, state.value);
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
                    if let Ok(ext_id) = parse_extension_id(ext_name) {
                        let ext_id_u32 = ext_id as u32;
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
