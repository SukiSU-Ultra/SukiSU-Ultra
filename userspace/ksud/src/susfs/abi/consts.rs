//! SuSFS syscall constants.
//!
//! Magic numbers / command IDs / buffer sizes shared between every other
//! submodule. Mirrors `susfs_defs.h` from the official `ksu_susfs` userspace
//! tool.

#![allow(clippy::unreadable_literal)]

/// `reboot(2)` magic #1 expected by the SuSFS kernel module.
pub(crate) const KSU_INSTALL_MAGIC1: u32 = 0xDEAD_BEEF;

/// `reboot(2)` magic #2 expected by the SuSFS kernel module.
pub(crate) const SUSFS_MAGIC: u32 = 0xFAFA_FAFA;

/// Sentinel value returned in `err` when the command is not supported by the
/// running kernel.
pub(crate) const ERR_CMD_NOT_SUPPORTED: i32 = 126;

// ── buffer sizes ──────────────────────────────────────────────────────────────

pub(crate) const SUSFS_MAX_VERSION_BUFSIZE: usize = 16;
pub(crate) const SUSFS_ENABLED_FEATURES_SIZE: usize = 8192;
pub(crate) const SUSFS_MAX_VARIANT_BUFSIZE: usize = 16;
pub(crate) const NEW_UTS_LEN: usize = 64;
pub(crate) const SUSFS_MAX_PATHNAME: usize = 256;
pub(crate) const SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE: usize = 8192;

// ── command IDs (internal — only the syscall dispatcher cares) ───────────────

pub(crate) const CMD_SUSFS_ADD_SUS_PATH: u32 = 0x55550;
pub(crate) const CMD_SUSFS_ADD_SUS_PATH_LOOP: u32 = 0x55553;
pub(crate) const CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS: u32 = 0x55561;
pub(crate) const CMD_SUSFS_ADD_SUS_KSTAT: u32 = 0x55570;
pub(crate) const CMD_SUSFS_UPDATE_SUS_KSTAT: u32 = 0x55571;
pub(crate) const CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY: u32 = 0x55572;
pub(crate) const CMD_SUSFS_SET_UNAME: u32 = 0x55590;
pub(crate) const CMD_SUSFS_ENABLE_LOG: u32 = 0x555_a0;
pub(crate) const CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG: u32 = 0x555_b0;
pub(crate) const CMD_SUSFS_ADD_OPEN_REDIRECT: u32 = 0x555_c0;
pub(crate) const CMD_SUSFS_SHOW_VERSION: u32 = 0x555_e1;
pub(crate) const CMD_SUSFS_SHOW_ENABLED_FEATURES: u32 = 0x555_e2;
pub(crate) const CMD_SUSFS_SHOW_VARIANT: u32 = 0x555_e3;
pub(crate) const CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING: u32 = 0x60010;
pub(crate) const CMD_SUSFS_ADD_SUS_MAP: u32 = 0x60020;

/// Mask of every stat member that is spoofed automatically when the kernel
/// re-stats the target path.
pub(crate) const KSTAT_AUTO_SPOOF: u32 = (1 << 0)   // ino
    | (1 << 1)                                      // dev
    | (1 << 4)                                      // atime sec
    | (1 << 5)                                      // atime nsec
    | (1 << 6)                                      // mtime sec
    | (1 << 7)                                      // mtime nsec
    | (1 << 8)                                      // ctime sec
    | (1 << 9)                                      // ctime nsec
    | (1 << 10)                                     // blocks
    | (1 << 11);                                    // blksize

/// Same as [`KSTAT_AUTO_SPOOF`] but also spoofs `nlink` and `size` — used by
/// `update_sus_kstat_full_clone`.
pub(crate) const KSTAT_AUTO_SPOOF_FULL_CLONE: u32 = KSTAT_AUTO_SPOOF | (1 << 2) | (1 << 3);
