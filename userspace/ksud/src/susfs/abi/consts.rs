//! SuSFS syscall constants.
//!
//! Magic numbers / command IDs / buffer sizes shared between every other
//! submodule. Mirrors `susfs_defs.h` from the official `ksu_susfs` userspace
//! tool.

/// `reboot(2)` magic #1 expected by the SuSFS kernel module.
pub const KSU_INSTALL_MAGIC1: u32 = 0xDEAD_BEEF;

/// `reboot(2)` magic #2 expected by the SuSFS kernel module.
pub const SUSFS_MAGIC: u32 = 0xFAFA_FAFA;

/// Sentinel value returned in `err` when the command is not supported by the
/// running kernel.
pub const ERR_CMD_NOT_SUPPORTED: i32 = 126;

// ── buffer sizes ──────────────────────────────────────────────────────────────

pub const SUSFS_MAX_VERSION_BUFSIZE: usize = 16;
pub const SUSFS_ENABLED_FEATURES_SIZE: usize = 8192;
pub const SUSFS_MAX_VARIANT_BUFSIZE: usize = 16;
pub const NEW_UTS_LEN: usize = 64;
pub const SUSFS_MAX_PATHNAME: usize = 256;
pub const SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE: usize = 8192;

// ── command IDs (internal — only the syscall dispatcher cares) ───────────────

pub const CMD_SUSFS_ADD_SUS_PATH: u32 = 0x0005_5550;
pub const CMD_SUSFS_ADD_SUS_PATH_LOOP: u32 = 0x0005_5553;
pub const CMD_SUSFS_HIDE_SUS_MOUNTS_FOR_NON_SU_PROCS: u32 = 0x0005_5561;
pub const CMD_SUSFS_ADD_SUS_KSTAT: u32 = 0x0005_5570;
pub const CMD_SUSFS_UPDATE_SUS_KSTAT: u32 = 0x0005_5571;
pub const CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY: u32 = 0x0005_5572;
pub const CMD_SUSFS_SET_UNAME: u32 = 0x0005_5590;
pub const CMD_SUSFS_ENABLE_LOG: u32 = 0x0005_55A0;
pub const CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG: u32 = 0x0005_55B0;
pub const CMD_SUSFS_ADD_OPEN_REDIRECT: u32 = 0x0005_55C0;
pub const CMD_SUSFS_SHOW_VERSION: u32 = 0x0005_55E1;
pub const CMD_SUSFS_SHOW_ENABLED_FEATURES: u32 = 0x0005_55E2;
pub const CMD_SUSFS_SHOW_VARIANT: u32 = 0x0005_55E3;
pub const CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING: u32 = 0x0006_0010;
pub const CMD_SUSFS_ADD_SUS_MAP: u32 = 0x0006_0020;

/// Mask of every stat member that is spoofed automatically when the kernel
/// re-stats the target path.
pub const KSTAT_AUTO_SPOOF: u32 = (1 << 0)   // ino
    | (1 << 1)                                      // dev
    | (1 << 4)                                      // atime sec
    | (1 << 5)                                      // atime nsec
    | (1 << 6)                                      // mtime sec
    | (1 << 7)                                      // mtime nsec
    | (1 << 8)                                      // ctime sec
    | (1 << 9)                                      // ctime nsec
    | (1 << 10)                                     // blocks
    | (1 << 11); // blksize

/// Same as [`KSTAT_AUTO_SPOOF`] but also spoofs `nlink` and `size` — used by
/// `update_sus_kstat_full_clone`.
pub const KSTAT_AUTO_SPOOF_FULL_CLONE: u32 = KSTAT_AUTO_SPOOF | (1 << 2) | (1 << 3);
