//! Extension ids shared by the extension manager and the manager UI.
//!
//! Mirrors `enum ksu_extension_id` in `uapi/extension.h`. Each id is a
//! kernel handler with a richer UI than a single 1-bit feature; it is
//! probed at runtime for support via `KSU_IOCTL_EXTENSION / GET`.

#![cfg_attr(not(target_os = "android"), allow(dead_code))]

use anyhow::{Result, bail};

/// Identifier of a registered extension handler in the kernel.
///
/// Adding a new entry here must be matched in:
///   - `uapi/extension.h::ksu_extension_id`
///   - `kernel/extension/extension.c::ksu_extension_register_all`
///   - the Kotlin `ExtensionId` enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ExtensionId {
    Kpm = 0,
    CpuSpoof = 1,
    UmountPaths = 2,
    DynamicManager = 3,
}

impl ExtensionId {
    /// All known extension ids in declaration order.
    pub const ALL: [Self; 4] = [
        Self::Kpm,
        Self::CpuSpoof,
        Self::UmountPaths,
        Self::DynamicManager,
    ];

    /// Decode a u32 from the kernel uapi. `None` means "unknown /
    /// future extension"; callers treat that as not supported.
    pub const fn from_u32(id: u32) -> Option<Self> {
        match id {
            0 => Some(Self::Kpm),
            1 => Some(Self::CpuSpoof),
            2 => Some(Self::UmountPaths),
            3 => Some(Self::DynamicManager),
            _ => None,
        }
    }

    /// Whether this extension exposes a runtime sticky bit at all.
    ///
    /// `true` means the kernel can be told "enable / disable" via
    /// `ksu_extension_set`, and the current value is meaningful when
    /// probed via `ksu_extension_get`. `false` means the extension is
    /// either purely io-driven (CPU spoof, umount paths) or whose
    /// availability is fixed at kernel build time (KPM): the sticky
    /// value is always 0 and should be displayed as "Available"
    /// rather than "Disabled".
    pub const fn has_sticky_bit(self) -> bool {
        matches!(self, Self::DynamicManager)
    }

    /// Short identifier used in CLI output and on-disk config.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Kpm => "kpm",
            Self::CpuSpoof => "cpu_spoof",
            Self::UmountPaths => "umount_paths",
            Self::DynamicManager => "dynamic_manager",
        }
    }

    /// Human-readable label suitable for UI cards. The Kotlin side
    /// maps by [`Self::name`] to a localised string.
    #[allow(dead_code)] // exposed for external ksud callers
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Kpm => "KPM (Kernel Patch Module)",
            Self::CpuSpoof => "CPU identity spoofing",
            Self::UmountPaths => "Umount path manager",
            Self::DynamicManager => "Dynamic manager",
        }
    }

    /// Long-form description shown next to the toggle / probe entry.
    pub const fn description(self) -> &'static str {
        match self {
            Self::Kpm => {
                "KPM lets the manager load third-party kernel patch modules (.kpm) at runtime. Requires a KPM-capable kernel build."
            }
            Self::CpuSpoof => {
                "Override the reported MIDR, BogoMIPS, ELF hwcap and vDSO clock mode for processes spawned after the call. Hides the real SoC from apps that fingerprint the CPU."
            }
            Self::UmountPaths => {
                "Manage the list of mount points that kernel will umount on app start (e.g. /system, /vendor, /product overlays). Paths are matched as exact strings."
            }
            Self::DynamicManager => {
                "Allow more than one app to act as the KernelSU manager. Each candidate is authenticated by its signing certificate."
            }
        }
    }
}

pub fn parse_extension_id(name: &str) -> Result<ExtensionId> {
    match name {
        "kpm" | "0" => Ok(ExtensionId::Kpm),
        "cpu_spoof" | "1" => Ok(ExtensionId::CpuSpoof),
        "umount_paths" | "2" => Ok(ExtensionId::UmountPaths),
        "dynamic_manager" | "3" => Ok(ExtensionId::DynamicManager),
        _ => bail!("Unknown extension: {name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u32_round_trip() {
        for ext in ExtensionId::ALL {
            assert_eq!(ExtensionId::from_u32(ext as u32), Some(ext));
        }
    }

    #[test]
    fn unknown_ids_rejected() {
        assert_eq!(ExtensionId::from_u32(99), None);
        assert_eq!(ExtensionId::from_u32(u32::MAX), None);
    }

    #[test]
    fn parse_known_names() {
        for ext in ExtensionId::ALL {
            assert_eq!(parse_extension_id(ext.name()).unwrap(), ext);
            assert_eq!(parse_extension_id(&(ext as u32).to_string()).unwrap(), ext);
        }
    }

    #[test]
    fn parse_unknown_name_errors() {
        assert!(parse_extension_id("nope").is_err());
    }
}
