//! `#[repr(C)]` structs mirroring the SuSFS kernel UAPI.
//!
//! Field order, types, and sizes must match the kernel-side declarations
//! exactly because the syscall passes them by raw pointer.

use super::consts::{
    NEW_UTS_LEN, SUSFS_ENABLED_FEATURES_SIZE, SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE,
    SUSFS_MAX_PATHNAME, SUSFS_MAX_VARIANT_BUFSIZE, SUSFS_MAX_VERSION_BUFSIZE,
};

#[repr(C)]
pub struct SusfsVersion {
    pub susfs_version: [u8; SUSFS_MAX_VERSION_BUFSIZE],
    pub err: i32,
}

#[repr(C)]
pub struct SusfsFeatures {
    pub enabled_features: [u8; SUSFS_ENABLED_FEATURES_SIZE],
    pub err: i32,
}

#[repr(C)]
pub struct SusfsVariant {
    pub susfs_variant: [u8; SUSFS_MAX_VARIANT_BUFSIZE],
    pub err: i32,
}

#[repr(C)]
pub struct SusfsUname {
    pub release: [u8; NEW_UTS_LEN + 1],
    pub version: [u8; NEW_UTS_LEN + 1],
    pub err: i32,
}

#[repr(C)]
pub struct SusfsLog {
    pub enabled: u32,
    pub err: i32,
}

#[repr(C)]
pub struct SusfsAvcLogSpoofing {
    pub enabled: u32,
    pub err: i32,
}

#[repr(C)]
pub struct SusfsHideSusMnts {
    pub enabled: u32,
    pub err: i32,
}

#[repr(C)]
pub struct SusfsOpenRedirect {
    pub target_pathname: [u8; SUSFS_MAX_PATHNAME],
    pub redirected_pathname: [u8; SUSFS_MAX_PATHNAME],
    pub uid_scheme: u32,
    pub err: i32,
}

#[repr(C)]
pub struct SusfsKstat {
    pub is_statically: u32,
    pub target_ino: u64,
    pub target_pathname: [u8; SUSFS_MAX_PATHNAME],
    pub spoofed_ino: u64,
    pub spoofed_dev: u64,
    pub spoofed_nlink: u32,
    pub spoofed_size: u64,
    pub spoofed_atime_tv_sec: i64,
    pub spoofed_atime_tv_nsec: u64,
    pub spoofed_mtime_tv_sec: i64,
    pub spoofed_mtime_tv_nsec: u64,
    pub spoofed_ctime_tv_sec: i64,
    pub spoofed_ctime_tv_nsec: u64,
    pub spoofed_blocks: u64,
    pub spoofed_blksize: i64,
    pub flags: u32,
    pub err: i32,
}

#[repr(C)]
pub struct SusfsMap {
    pub target_pathname: [u8; SUSFS_MAX_PATHNAME],
    pub err: i32,
}

#[repr(C)]
pub struct SusfsSusPath {
    pub target_pathname: [u8; SUSFS_MAX_PATHNAME],
    pub err: i32,
}

#[repr(C)]
pub struct SusfsCmdlineOrBootconfig {
    pub fake_cmdline_or_bootconfig: [u8; SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE],
    pub err: i32,
}
