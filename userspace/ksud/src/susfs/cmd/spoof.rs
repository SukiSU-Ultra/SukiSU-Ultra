//! Kernel-level spoofing setters.
//!
//! Each function here corresponds to one SuSFS "set" command: uname
//! spoofing, log toggles, mount-point hiding, and cmdline/bootconfig
//! spoofing.

use anyhow::{Context, Result};

use crate::susfs::abi::consts::{
    CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING, CMD_SUSFS_ENABLE_LOG,
    CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS, CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG,
    CMD_SUSFS_SET_UNAME, ERR_CMD_NOT_SUPPORTED, NEW_UTS_LEN, SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE,
};
use crate::susfs::abi::{
    send, SusfsAvcLogSpoofing, SusfsCmdlineOrBootconfig, SusfsHideSusMnts, SusfsLog, SusfsUname,
};
use crate::susfs::util::{canonicalize, read_file};

// ── uname ─────────────────────────────────────────────────────────────────────

/// Spoof the kernel `uname(2)` release / version strings.
pub fn set_uname(release: &str, version: &str) -> Result<()> {
    let mut cmd = SusfsUname {
        release: [0; NEW_UTS_LEN + 1],
        version: [0; NEW_UTS_LEN + 1],
        err: ERR_CMD_NOT_SUPPORTED,
    };

    let release_bytes = release.as_bytes();
    let version_bytes = version.as_bytes();
    if release_bytes.len() >= cmd.release.len() || version_bytes.len() >= cmd.version.len() {
        anyhow::bail!("uname string too long");
    }
    cmd.release[..release_bytes.len()].copy_from_slice(release_bytes);
    cmd.version[..version_bytes.len()].copy_from_slice(version_bytes);

    send(CMD_SUSFS_SET_UNAME, &mut cmd, "set_uname")
}

// ── log toggles ───────────────────────────────────────────────────────────────

/// Enable or disable the SuSFS kernel log.
pub fn enable_log(enabled: bool) -> Result<()> {
    let mut cmd = SusfsLog {
        enabled: u32::from(enabled),
        err: ERR_CMD_NOT_SUPPORTED,
    };
    send(CMD_SUSFS_ENABLE_LOG, &mut cmd, "enable_log")
}

/// Enable or disable SuSFS's AVC-log spoofing hook.
pub fn enable_avc_log_spoofing(enabled: bool) -> Result<()> {
    let mut cmd = SusfsAvcLogSpoofing {
        enabled: u32::from(enabled),
        err: ERR_CMD_NOT_SUPPORTED,
    };
    send(
        CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING,
        &mut cmd,
        "enable_avc_log_spoofing",
    )
}

/// Toggle hiding of SuSFS mount points from non-SU processes.
pub fn hide_sus_mnts_for_non_su_procs(enabled: bool) -> Result<()> {
    let mut cmd = SusfsHideSusMnts {
        enabled: u32::from(enabled),
        err: ERR_CMD_NOT_SUPPORTED,
    };
    send(
        CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS,
        &mut cmd,
        "hide_sus_mnts_for_non_su_procs",
    )
}

// ── cmdline / bootconfig ─────────────────────────────────────────────────────

/// Spoof `/proc/cmdline` (non-GKI) or `/proc/bootconfig` (GKI) from the
/// contents of the file at `path`.
///
/// The file is read in full and copied into a fixed-size kernel buffer
/// (`SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE` bytes); paths that resolve
/// outside the filesystem are rejected via [`canonicalize`].
pub fn set_cmdline_or_bootconfig(path: &str) -> Result<()> {
    let resolved = canonicalize(path)?;
    let display = resolved.display().to_string();

    let bytes = read_file(&resolved)
        .with_context(|| format!("failed to read cmdline/bootconfig file: '{display}'"))?;

    if bytes.len() >= SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE {
        anyhow::bail!(
            "file too large ({} bytes, max {})",
            bytes.len(),
            SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE - 1
        );
    }

    let mut cmd = SusfsCmdlineOrBootconfig {
        fake_cmdline_or_bootconfig: [0; SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE],
        err: ERR_CMD_NOT_SUPPORTED,
    };
    cmd.fake_cmdline_or_bootconfig[..bytes.len()].copy_from_slice(&bytes);

    send(
        CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG,
        &mut cmd,
        "set_cmdline_or_bootconfig",
    )
}
