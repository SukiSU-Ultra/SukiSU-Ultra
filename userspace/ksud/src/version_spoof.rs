//! Userspace persistence and ioctl wrapper for kernel version overrides.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::defs;
use crate::extension_id::ExtensionId;
use crate::ksu_uapi;
use crate::ksucalls::extension_io;

const CONFIG_PATH: &str = const_format::concatcp!(defs::WORKING_DIR, ".version_spoof_config");
const MAX_FULL_VERSION: usize = 254;
const WARNING_HIDDEN_PATH: &str =
    const_format::concatcp!(defs::WORKING_DIR, ".version_spoof_warning_hidden");

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct VersionSpoofConfig {
    version: Option<u32>,
    full: Option<String>,
    uapi: Option<u32>,
}

#[derive(Debug, Serialize)]
struct VersionSpoofView {
    version: u32,
    full: String,
    uapi: u32,
    #[serde(rename = "defaultVersion")]
    default_version: u32,
    #[serde(rename = "defaultFull")]
    default_full: String,
    #[serde(rename = "defaultUapi")]
    default_uapi: u32,
}

fn load() -> Result<VersionSpoofConfig> {
    let path = Path::new(CONFIG_PATH);
    if !path.exists() {
        return Ok(VersionSpoofConfig::default());
    }
    let text = fs::read_to_string(path).context("failed to read version spoof config")?;
    serde_json::from_str(&text).context("failed to parse version spoof config")
}

fn save(config: &VersionSpoofConfig) -> Result<()> {
    fs::create_dir_all(Path::new(defs::WORKING_DIR))?;
    let text = serde_json::to_string(config)?;
    let mut temp = tempfile::NamedTempFile::new_in(defs::WORKING_DIR)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temp.write_all(text.as_bytes())?;
    temp.as_file().sync_all()?;
    temp.persist(CONFIG_PATH)
        .context("failed to persist version spoof config")?;
    Ok(())
}

fn defaults() -> Result<VersionSpoofView> {
    let mut cmd = ksu_uapi::ksu_version_spoof_cmd {
        op: ksu_uapi::KSU_VERSION_SPOOF_IO_GET,
        mask: 0,
        working_version: 0,
        uapi_version: 0,
        full_version: [0; 255],
        default_working_version: 0,
        default_uapi_version: 0,
        default_full_version: [0; 255],
    };
    // SAFETY: cmd uses the generated extension UAPI layout and remains alive for the call.
    unsafe { extension_io(ExtensionId::VersionSpoof as u32, &raw mut cmd) }?;
    Ok(VersionSpoofView {
        version: cmd.default_working_version,
        full: String::from_utf8(
            cmd.default_full_version
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b.to_ne_bytes()[0])
                .collect(),
        )?,
        uapi: cmd.default_uapi_version,
        default_version: cmd.default_working_version,
        default_full: String::from_utf8(
            cmd.default_full_version
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b.to_ne_bytes()[0])
                .collect(),
        )?,
        default_uapi: cmd.default_uapi_version,
    })
}

fn apply(config: &VersionSpoofConfig) -> Result<()> {
    let default = defaults()?;
    let version = config
        .version
        .filter(|value| *value != default.default_version);
    let uapi = config.uapi.filter(|value| *value != default.default_uapi);
    let full = config
        .full
        .as_deref()
        .filter(|value| value != &default.default_full);
    let mut cmd = ksu_uapi::ksu_version_spoof_cmd {
        op: ksu_uapi::KSU_VERSION_SPOOF_IO_SET,
        mask: 0,
        working_version: version.unwrap_or_default(),
        uapi_version: uapi.unwrap_or_default(),
        full_version: [0; 255],
        default_working_version: 0,
        default_uapi_version: 0,
        default_full_version: [0; 255],
    };
    if version.is_some() {
        cmd.mask |= ksu_uapi::KSU_VERSION_SPOOF_WORKING_VERSION;
    }
    if uapi.is_some() {
        cmd.mask |= ksu_uapi::KSU_VERSION_SPOOF_UAPI_VERSION;
    }
    if let Some(full) = full {
        if full.len() > MAX_FULL_VERSION || full.as_bytes().contains(&0) {
            bail!("full version must be at most {MAX_FULL_VERSION} bytes and contain no NUL");
        }
        cmd.mask |= ksu_uapi::KSU_VERSION_SPOOF_FULL_VERSION;
        for (dst, src) in cmd.full_version.iter_mut().zip(full.bytes()) {
            *dst = src as _;
        }
    }
    unsafe { extension_io(ExtensionId::VersionSpoof as u32, &raw mut cmd) }?;
    Ok(())
}

fn ensure_compatibility_acknowledged(acknowledged: bool) -> Result<()> {
    anyhow::ensure!(
        acknowledged,
        "version overrides require --acknowledge-compatibility; custom UAPI/version values may break Manager and ksud compatibility"
    );
    Ok(())
}

pub fn set(
    version: Option<u32>,
    full: Option<String>,
    uapi: Option<u32>,
    acknowledge_compatibility: bool,
) -> Result<()> {
    ensure_compatibility_acknowledged(acknowledge_compatibility)?;
    let default = defaults()?;
    let config = VersionSpoofConfig {
        version: version.filter(|value| *value != default.default_version),
        full: full.filter(|value| *value != default.default_full),
        uapi: uapi.filter(|value| *value != default.default_uapi),
    };
    apply(&config)?;
    save(&config)?;
    println!("version spoof configuration applied and saved");
    Ok(())
}

pub fn reset() -> Result<()> {
    let mut cmd = ksu_uapi::ksu_version_spoof_cmd {
        op: ksu_uapi::KSU_VERSION_SPOOF_IO_RESET,
        mask: 0,
        working_version: 0,
        uapi_version: 0,
        full_version: [0; 255],
        default_working_version: 0,
        default_uapi_version: 0,
        default_full_version: [0; 255],
    };
    unsafe { extension_io(ExtensionId::VersionSpoof as u32, &raw mut cmd) }?;
    match fs::remove_file(CONFIG_PATH) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("runtime reset, but saved overrides could not be removed"),
    }
    println!("{}", serde_json::to_string(&defaults()?)?);
    Ok(())
}

pub fn print_config() -> Result<()> {
    let mut cmd = ksu_uapi::ksu_version_spoof_cmd {
        op: ksu_uapi::KSU_VERSION_SPOOF_IO_GET,
        mask: 0,
        working_version: 0,
        uapi_version: 0,
        full_version: [0; 255],
        default_working_version: 0,
        default_uapi_version: 0,
        default_full_version: [0; 255],
    };
    // SAFETY: cmd has the generated UAPI layout and lives across the ioctl.
    unsafe { extension_io(ExtensionId::VersionSpoof as u32, &raw mut cmd) }?;
    let full = cmd
        .full_version
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b.to_ne_bytes()[0])
        .collect::<Vec<_>>();
    let effective_full = String::from_utf8(full)?;
    let view = VersionSpoofView {
        version: cmd.working_version,
        full: effective_full,
        uapi: cmd.uapi_version,
        default_version: cmd.default_working_version,
        default_full: String::from_utf8(
            cmd.default_full_version
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b.to_ne_bytes()[0])
                .collect(),
        )?,
        default_uapi: cmd.default_uapi_version,
    };
    println!("{}", serde_json::to_string(&view)?);
    Ok(())
}

pub fn apply_saved() -> Result<()> {
    let config = load()?;
    if config.version.is_some() || config.full.is_some() || config.uapi.is_some() {
        apply(&config)?;
    }
    Ok(())
}

pub fn warning_hidden() -> Result<bool> {
    match fs::read_to_string(WARNING_HIDDEN_PATH) {
        Ok(value) => Ok(value.trim() == "true"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("failed to read version warning setting"),
    }
}

pub fn set_warning_hidden(hidden: bool) -> Result<()> {
    fs::create_dir_all(Path::new(defs::WORKING_DIR))?;
    fs::write(
        WARNING_HIDDEN_PATH,
        if hidden { "true\n" } else { "false\n" },
    )
    .context("failed to save version warning setting")?;
    println!("{hidden}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ensure_compatibility_acknowledged;

    #[test]
    fn version_changes_require_explicit_acknowledgement() {
        assert!(ensure_compatibility_acknowledged(false).is_err());
        assert!(ensure_compatibility_acknowledged(true).is_ok());
    }
}
