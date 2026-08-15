//! `#[repr(C)]` structs mirroring the SuSFS kernel UAPI.
//!
//! Field order, types, and sizes must match the kernel-side declarations
//! exactly because the syscall passes them by raw pointer.

use super::consts::{
    NEW_UTS_LEN, SUSFS_ENABLED_FEATURES_SIZE, SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE,
    SUSFS_MAX_PATHNAME, SUSFS_MAX_VARIANT_BUFSIZE, SUSFS_MAX_VERSION_BUFSIZE,
};

#[repr(C)]
pub(crate) struct SusfsVersion {
    pub(crate) susfs_version: [u8; SUSFS_MAX_VERSION_BUFSIZE],
    pub(crate) err: i32,
}

#[repr(C)]
pub(crate) struct SusfsFeatures {
    pub(crate) enabled_features: [u8; SUSFS_ENABLED_FEATURES_SIZE],
    pub(crate) err: i32,
}

#[repr(C)]
pub(crate) struct SusfsVariant {
    pub(crate) susfs_variant: [u8; SUSFS_MAX_VARIANT_BUFSIZE],
    pub(crate) err: i32,
}

#[repr(C)]
pub(crate) struct SusfsUname {
    pub(crate) release: [u8; NEW_UTS_LEN + 1],
    pub(crate) version: [u8; NEW_UTS_LEN + 1],
    pub(crate) err: i32,
}

#[repr(C)]
pub(crate) struct SusfsLog {
    pub(crate) enabled: u32,
    pub(crate) err: i32,
}

#[repr(C)]
pub(crate) struct SusfsAvcLogSpoofing {
    pub(crate) enabled: u32,
    pub(crate) err: i32,
}

#[repr(C)]
pub(crate) struct SusfsHideSusMnts {
    pub(crate) enabled: u32,
    pub(crate) err: i32,
}

#[repr(C)]
pub(crate) struct SusfsOpenRedirect {
    pub(crate) target_pathname: [u8; SUSFS_MAX_PATHNAME],
    pub(crate) redirected_pathname: [u8; SUSFS_MAX_PATHNAME],
    pub(crate) uid_scheme: u32,
    pub(crate) err: i32,
}

#[repr(C)]
pub(crate) struct SusfsKstat {
    pub(crate) is_statically: u32,
    pub(crate) target_ino: u64,
    pub(crate) target_pathname: [u8; SUSFS_MAX_PATHNAME],
    pub(crate) spoofed_ino: u64,
    pub(crate) spoofed_dev: u64,
    pub(crate) spoofed_nlink: u32,
    pub(crate) spoofed_size: u64,
    pub(crate) spoofed_atime_tv_sec: i64,
    pub(crate) spoofed_atime_tv_nsec: u64,
    pub(crate) spoofed_mtime_tv_sec: i64,
    pub(crate) spoofed_mtime_tv_nsec: u64,
    pub(crate) spoofed_ctime_tv_sec: i64,
    pub(crate) spoofed_ctime_tv_nsec: u64,
    pub(crate) spoofed_blocks: u64,
    pub(crate) spoofed_blksize: i64,
    pub(crate) flags: u32,
    pub(crate) err: i32,
}

#[repr(C)]
pub(crate) struct SusfsMap {
    pub(crate) target_pathname: [u8; SUSFS_MAX_PATHNAME],
    pub(crate) err: i32,
}

#[repr(C)]
pub(crate) struct SusfsSusPath {
    pub(crate) target_pathname: [u8; SUSFS_MAX_PATHNAME],
    pub(crate) err: i32,
}

#[repr(C)]
pub(crate) struct SusfsCmdlineOrBootconfig {
    pub(crate) fake_cmdline_or_bootconfig: [u8; SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE],
    pub(crate) err: i32,
}
