#![allow(clippy::unreadable_literal)]
use anyhow::{Context, anyhow};
use libc::SYS_reboot;
#[cfg(target_os = "android")]
use rustix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use rustix::fs::MetadataExt;

const SUSFS_MAX_VERSION_BUFSIZE: usize = 16;
const SUSFS_ENABLED_FEATURES_SIZE: usize = 8192;
const SUSFS_MAX_LEN_PATHNAME: usize = 256;
const ERR_CMD_NOT_SUPPORTED: i32 = 126;
const KSU_INSTALL_MAGIC1: u32 = 0xDEADBEEF;
const SUSFS_MAGIC: u32 = 0xFAFAFAFA;

// Command IDs
const CMD_SUSFS_SHOW_VERSION: u32 = 0x555e1;
const CMD_SUSFS_SHOW_ENABLED_FEATURES: u32 = 0x555e2;
const CMD_SUSFS_ADD_SUS_PATH: u32 = 0x55550;
const CMD_SUSFS_ADD_SUS_PATH_LOOP: u32 = 0x55553;
const CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS: u32 = 0x55561;
const CMD_SUSFS_ADD_SUS_MAP: u32 = 0x60020;
const CMD_SUSFS_ENABLE_LOG: u32 = 0x555a0;
const CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG: u32 = 0x555b0;
const CMD_SUSFS_SET_UNAME: u32 = 0x555c0;
const CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING: u32 = 0x555d0;
const CMD_SUSFS_ADD_SUS_KSTAT: u32 = 0x55570;
const CMD_SUSFS_UPDATE_SUS_KSTAT: u32 = 0x55571;
const CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY: u32 = 0x55572;

#[repr(C)]
struct SusfsVersion {
    susfs_version: [u8; SUSFS_MAX_VERSION_BUFSIZE],
    err: i32,
}

#[repr(C)]
struct SusfsFeatures {
    enabled_features: [u8; SUSFS_ENABLED_FEATURES_SIZE],
    err: i32,
}

#[repr(C)]
struct SusfsSusPath {
    target_pathname: [u8; SUSFS_MAX_LEN_PATHNAME],
    err: i32,
}

#[repr(C)]
struct SusfsHideMounts {
    enabled: bool,
    err: i32,
}

#[repr(C)]
struct SusfsSusMap {
    target_pathname: [u8; SUSFS_MAX_LEN_PATHNAME],
    err: i32,
}

#[repr(C)]
struct SusfsEnableLog {
    enabled: bool,
    err: i32,
}

#[repr(C)]
struct SusfsSetUname {
    uname: [u8; 64],
    build_time: [u8; 64],
    err: i32,
}

#[repr(C)]
struct SusfsEnableAvcLogSpoofing {
    enabled: bool,
    err: i32,
}

#[repr(C)]
struct SusfsSusKstat {
    is_statically: bool,
    target_ino: u64,
    target_pathname: [u8; SUSFS_MAX_LEN_PATHNAME],
    spoofed_ino: u64,
    spoofed_dev: u64,
    spoofed_nlink: u32,
    spoofed_size: i64,
    spoofed_atime_tv_sec: i64,
    spoofed_atime_tv_nsec: u64,
    spoofed_mtime_tv_sec: i64,
    spoofed_mtime_tv_nsec: u64,
    spoofed_ctime_tv_sec: i64,
    spoofed_ctime_tv_nsec: u64,
    spoofed_blocks: i64,
    spoofed_blksize: i64,
    flags: i32,
    err: i32,
}

const KSTAT_SPOOF_INO: i32 = 1 << 0;
const KSTAT_SPOOF_DEV: i32 = 1 << 1;
const KSTAT_SPOOF_NLINK: i32 = 1 << 2;
const KSTAT_SPOOF_SIZE: i32 = 1 << 3;
const KSTAT_SPOOF_ATIME_TV_SEC: i32 = 1 << 4;
const KSTAT_SPOOF_ATIME_TV_NSEC: i32 = 1 << 5;
const KSTAT_SPOOF_MTIME_TV_SEC: i32 = 1 << 6;
const KSTAT_SPOOF_MTIME_TV_NSEC: i32 = 1 << 7;
const KSTAT_SPOOF_CTIME_TV_SEC: i32 = 1 << 8;
const KSTAT_SPOOF_CTIME_TV_NSEC: i32 = 1 << 9;
const KSTAT_SPOOF_BLOCKS: i32 = 1 << 10;
const KSTAT_SPOOF_BLKSIZE: i32 = 1 << 11;
const KSTAT_AUTO_SPOOF: i32 = KSTAT_SPOOF_INO
    | KSTAT_SPOOF_DEV
    | KSTAT_SPOOF_ATIME_TV_SEC
    | KSTAT_SPOOF_ATIME_TV_NSEC
    | KSTAT_SPOOF_MTIME_TV_SEC
    | KSTAT_SPOOF_MTIME_TV_NSEC
    | KSTAT_SPOOF_CTIME_TV_SEC
    | KSTAT_SPOOF_CTIME_TV_NSEC
    | KSTAT_SPOOF_BLKSIZE
    | KSTAT_SPOOF_BLOCKS;
const KSTAT_AUTO_SPOOF_FULL_CLONE: i32 = KSTAT_AUTO_SPOOF | KSTAT_SPOOF_NLINK | KSTAT_SPOOF_SIZE;

pub fn get_susfs_version() -> String {
    let mut cmd = SusfsVersion {
        susfs_version: [0; SUSFS_MAX_VERSION_BUFSIZE],
        err: ERR_CMD_NOT_SUPPORTED,
    };

    unsafe {
        libc::syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            CMD_SUSFS_SHOW_VERSION,
            &mut cmd,
        )
    };

    let ver = cmd.susfs_version.iter().position(|&b| b == 0).unwrap_or(16);
    let ver = String::from_utf8(cmd.susfs_version[..ver].to_vec())
        .unwrap_or_else(|_| "<invalid>".to_string());

    if ver.starts_with('v') {
        ver
    } else {
        "unsupport".to_string()
    }
}

pub fn get_susfs_status() -> bool {
    get_susfs_version() != "unsupport"
}

pub fn get_susfs_features() -> String {
    let mut cmd = SusfsFeatures {
        enabled_features: [0; SUSFS_ENABLED_FEATURES_SIZE],
        err: ERR_CMD_NOT_SUPPORTED,
    };

    unsafe {
        libc::syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            CMD_SUSFS_SHOW_ENABLED_FEATURES,
            &mut cmd,
        )
    };

    let features = cmd
        .enabled_features
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(16);
    String::from_utf8(cmd.enabled_features[..features].to_vec())
        .unwrap_or_else(|_| "<invalid>".to_string())
}

pub fn add_sus_path(path: &str) -> anyhow::Result<()> {
    let mut cmd = SusfsSusPath {
        target_pathname: [0; SUSFS_MAX_LEN_PATHNAME],
        err: ERR_CMD_NOT_SUPPORTED,
    };

    let path_bytes = path.as_bytes();
    let copy_len = path_bytes.len().min(SUSFS_MAX_LEN_PATHNAME - 1);
    cmd.target_pathname[..copy_len].copy_from_slice(&path_bytes[..copy_len]);

    unsafe {
        libc::syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            CMD_SUSFS_ADD_SUS_PATH,
            &mut cmd,
        )
    };

    if cmd.err == ERR_CMD_NOT_SUPPORTED {
        Err(anyhow!("Command not supported"))
    } else if cmd.err != 0 {
        Err(anyhow!("Error: {}", cmd.err))
    } else {
        Ok(())
    }
}

pub fn add_sus_path_loop(path: &str) -> anyhow::Result<()> {
    let mut cmd = SusfsSusPath {
        target_pathname: [0; SUSFS_MAX_LEN_PATHNAME],
        err: ERR_CMD_NOT_SUPPORTED,
    };

    let path_bytes = path.as_bytes();
    let copy_len = path_bytes.len().min(SUSFS_MAX_LEN_PATHNAME - 1);
    cmd.target_pathname[..copy_len].copy_from_slice(&path_bytes[..copy_len]);

    unsafe {
        libc::syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            CMD_SUSFS_ADD_SUS_PATH_LOOP,
            &mut cmd,
        )
    };

    if cmd.err == ERR_CMD_NOT_SUPPORTED {
        Err(anyhow!("Command not supported"))
    } else if cmd.err != 0 {
        Err(anyhow!("Error: {}", cmd.err))
    } else {
        Ok(())
    }
}

pub fn hide_sus_mnts_for_non_su_procs(enabled: bool) -> anyhow::Result<()> {
    let mut cmd = SusfsHideMounts {
        enabled,
        err: ERR_CMD_NOT_SUPPORTED,
    };

    unsafe {
        libc::syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS,
            &mut cmd,
        )
    };

    if cmd.err == ERR_CMD_NOT_SUPPORTED {
        Err(anyhow!("Command not supported"))
    } else if cmd.err != 0 {
        Err(anyhow!("Error: {}", cmd.err))
    } else {
        Ok(())
    }
}

pub fn add_sus_map(path: &str) -> anyhow::Result<()> {
    let mut cmd = SusfsSusMap {
        target_pathname: [0; SUSFS_MAX_LEN_PATHNAME],
        err: ERR_CMD_NOT_SUPPORTED,
    };

    let path_bytes = path.as_bytes();
    let copy_len = path_bytes.len().min(SUSFS_MAX_LEN_PATHNAME - 1);
    cmd.target_pathname[..copy_len].copy_from_slice(&path_bytes[..copy_len]);

    unsafe {
        libc::syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            CMD_SUSFS_ADD_SUS_MAP,
            &mut cmd,
        )
    };

    if cmd.err == ERR_CMD_NOT_SUPPORTED {
        Err(anyhow!("Command not supported"))
    } else if cmd.err != 0 {
        Err(anyhow!("Error: {}", cmd.err))
    } else {
        Ok(())
    }
}

pub fn enable_log(enabled: bool) -> anyhow::Result<()> {
    let mut cmd = SusfsEnableLog {
        enabled,
        err: ERR_CMD_NOT_SUPPORTED,
    };

    unsafe {
        libc::syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            CMD_SUSFS_ENABLE_LOG,
            &mut cmd,
        )
    };

    if cmd.err == ERR_CMD_NOT_SUPPORTED {
        Err(anyhow!("Command not supported"))
    } else if cmd.err != 0 {
        Err(anyhow!("Error: {}", cmd.err))
    } else {
        Ok(())
    }
}

pub fn enable_avc_log_spoofing(enabled: bool) -> anyhow::Result<()> {
    let mut cmd = SusfsEnableAvcLogSpoofing {
        enabled,
        err: ERR_CMD_NOT_SUPPORTED,
    };

    unsafe {
        libc::syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING,
            &mut cmd,
        )
    };

    if cmd.err == ERR_CMD_NOT_SUPPORTED {
        Err(anyhow!("Command not supported"))
    } else if cmd.err != 0 {
        Err(anyhow!("Error: {}", cmd.err))
    } else {
        Ok(())
    }
}

pub fn set_uname(uname: &str, build_time: &str) -> anyhow::Result<()> {
    let mut cmd = SusfsSetUname {
        uname: [0; 64],
        build_time: [0; 64],
        err: ERR_CMD_NOT_SUPPORTED,
    };

    let uname_bytes = uname.as_bytes();
    let copy_len = uname_bytes.len().min(63);
    cmd.uname[..copy_len].copy_from_slice(&uname_bytes[..copy_len]);

    let build_time_bytes = build_time.as_bytes();
    let copy_len = build_time_bytes.len().min(63);
    cmd.build_time[..copy_len].copy_from_slice(&build_time_bytes[..copy_len]);

    unsafe {
        libc::syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            CMD_SUSFS_SET_UNAME,
            &mut cmd,
        )
    };

    if cmd.err == ERR_CMD_NOT_SUPPORTED {
        Err(anyhow!("Command not supported"))
    } else if cmd.err != 0 {
        Err(anyhow!("Error: {}", cmd.err))
    } else {
        Ok(())
    }
}

pub fn add_sus_kstat(path: &str) -> anyhow::Result<()> {
    let stat_result = std::fs::metadata(path).context(format!("Failed to stat path: {path}"))?;

    let mut cmd = SusfsSusKstat {
        is_statically: false,
        target_ino: stat_result.ino() as u64,
        target_pathname: [0; SUSFS_MAX_LEN_PATHNAME],
        spoofed_ino: stat_result.ino() as u64,
        spoofed_dev: stat_result.dev() as u64,
        spoofed_nlink: stat_result.nlink() as u32,
        spoofed_size: stat_result.size() as i64,
        spoofed_atime_tv_sec: stat_result.atime(),
        spoofed_atime_tv_nsec: stat_result.atime_nsec() as u64,
        spoofed_mtime_tv_sec: stat_result.mtime(),
        spoofed_mtime_tv_nsec: stat_result.mtime_nsec() as u64,
        spoofed_ctime_tv_sec: stat_result.ctime(),
        spoofed_ctime_tv_nsec: stat_result.ctime_nsec() as u64,
        spoofed_blocks: stat_result.blocks() as i64,
        spoofed_blksize: stat_result.blksize() as i64,
        flags: KSTAT_AUTO_SPOOF,
        err: ERR_CMD_NOT_SUPPORTED,
    };

    let path_bytes = path.as_bytes();
    let copy_len = path_bytes.len().min(SUSFS_MAX_LEN_PATHNAME - 1);
    cmd.target_pathname[..copy_len].copy_from_slice(&path_bytes[..copy_len]);

    unsafe {
        libc::syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            CMD_SUSFS_ADD_SUS_KSTAT,
            &mut cmd,
        )
    };

    if cmd.err == ERR_CMD_NOT_SUPPORTED {
        Err(anyhow!("Command not supported"))
    } else if cmd.err != 0 {
        Err(anyhow!("Error: {}", cmd.err))
    } else {
        Ok(())
    }
}

pub fn update_sus_kstat(path: &str) -> anyhow::Result<()> {
    let stat_result = std::fs::metadata(path).context(format!("Failed to stat path: {path}"))?;

    let mut cmd = SusfsSusKstat {
        is_statically: false,
        target_ino: stat_result.ino() as u64,
        target_pathname: [0; SUSFS_MAX_LEN_PATHNAME],
        spoofed_ino: stat_result.ino() as u64,
        spoofed_dev: stat_result.dev() as u64,
        spoofed_nlink: stat_result.nlink() as u32,
        spoofed_size: stat_result.size() as i64,
        spoofed_atime_tv_sec: stat_result.atime(),
        spoofed_atime_tv_nsec: stat_result.atime_nsec() as u64,
        spoofed_mtime_tv_sec: stat_result.mtime(),
        spoofed_mtime_tv_nsec: stat_result.mtime_nsec() as u64,
        spoofed_ctime_tv_sec: stat_result.ctime(),
        spoofed_ctime_tv_nsec: stat_result.ctime_nsec() as u64,
        spoofed_blocks: stat_result.blocks() as i64,
        spoofed_blksize: stat_result.blksize() as i64,
        flags: KSTAT_AUTO_SPOOF,
        err: ERR_CMD_NOT_SUPPORTED,
    };

    let path_bytes = path.as_bytes();
    let copy_len = path_bytes.len().min(SUSFS_MAX_LEN_PATHNAME - 1);
    cmd.target_pathname[..copy_len].copy_from_slice(&path_bytes[..copy_len]);

    unsafe {
        libc::syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            CMD_SUSFS_UPDATE_SUS_KSTAT,
            &mut cmd,
        )
    };

    if cmd.err == ERR_CMD_NOT_SUPPORTED {
        Err(anyhow!("Command not supported"))
    } else if cmd.err != 0 {
        Err(anyhow!("Error: {}", cmd.err))
    } else {
        Ok(())
    }
}

pub fn update_sus_kstat_full_clone(path: &str) -> anyhow::Result<()> {
    let stat_result = std::fs::metadata(path).context(format!("Failed to stat path: {path}"))?;

    let mut cmd = SusfsSusKstat {
        is_statically: false,
        target_ino: stat_result.ino() as u64,
        target_pathname: [0; SUSFS_MAX_LEN_PATHNAME],
        spoofed_ino: stat_result.ino() as u64,
        spoofed_dev: stat_result.dev() as u64,
        spoofed_nlink: stat_result.nlink() as u32,
        spoofed_size: stat_result.size() as i64,
        spoofed_atime_tv_sec: stat_result.atime(),
        spoofed_atime_tv_nsec: stat_result.atime_nsec() as u64,
        spoofed_mtime_tv_sec: stat_result.mtime(),
        spoofed_mtime_tv_nsec: stat_result.mtime_nsec() as u64,
        spoofed_ctime_tv_sec: stat_result.ctime(),
        spoofed_ctime_tv_nsec: stat_result.ctime_nsec() as u64,
        spoofed_blocks: stat_result.blocks() as i64,
        spoofed_blksize: stat_result.blksize() as i64,
        flags: KSTAT_AUTO_SPOOF_FULL_CLONE,
        err: ERR_CMD_NOT_SUPPORTED,
    };

    let path_bytes = path.as_bytes();
    let copy_len = path_bytes.len().min(SUSFS_MAX_LEN_PATHNAME - 1);
    cmd.target_pathname[..copy_len].copy_from_slice(&path_bytes[..copy_len]);

    unsafe {
        libc::syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            CMD_SUSFS_UPDATE_SUS_KSTAT,
            &mut cmd,
        )
    };

    if cmd.err == ERR_CMD_NOT_SUPPORTED {
        Err(anyhow!("Command not supported"))
    } else if cmd.err != 0 {
        Err(anyhow!("Error: {}", cmd.err))
    } else {
        Ok(())
    }
}

pub fn add_sus_kstat_statically(
    path: &str,
    ino: Option<u64>,
    dev: Option<u64>,
    nlink: Option<u32>,
    size: Option<i64>,
    atime: Option<i64>,
    atime_nsec: Option<u64>,
    mtime: Option<i64>,
    mtime_nsec: Option<u64>,
    ctime: Option<i64>,
    ctime_nsec: Option<u64>,
    blocks: Option<i64>,
    blksize: Option<i64>,
) -> anyhow::Result<()> {
    let stat_result = std::fs::metadata(path).context(format!("Failed to stat path: {path}"))?;

    let mut flags: i32 = 0;
    let mut spoofed_ino = stat_result.ino() as u64;
    let mut spoofed_dev = stat_result.dev() as u64;
    let mut spoofed_nlink: u32 = stat_result.nlink() as u32;
    let mut spoofed_size = stat_result.size() as i64;
    let mut atime_secs = stat_result.atime();
    let mut atime_nanosecs: u64 = stat_result.atime_nsec() as u64;
    let mut mtime_secs = stat_result.mtime();
    let mut mtime_nanosecs: u64 = stat_result.mtime_nsec() as u64;
    let mut ctime_secs = stat_result.ctime();
    let mut ctime_nanosecs: u64 = stat_result.ctime_nsec() as u64;
    let mut spoofed_blocks: i64 = stat_result.blocks() as i64;
    let mut spoofed_blksize = stat_result.blksize() as i64;

    if let Some(v) = ino {
        spoofed_ino = v;
        flags |= KSTAT_SPOOF_INO;
    }
    if let Some(v) = dev {
        spoofed_dev = v;
        flags |= KSTAT_SPOOF_DEV;
    }
    if let Some(v) = nlink {
        spoofed_nlink = v;
        flags |= KSTAT_SPOOF_NLINK;
    }
    if let Some(v) = size {
        spoofed_size = v;
        flags |= KSTAT_SPOOF_SIZE;
    }
    if let Some(v) = atime {
        atime_secs = v;
        flags |= KSTAT_SPOOF_ATIME_TV_SEC;
    }
    if let Some(v) = atime_nsec {
        atime_nanosecs = v;
        flags |= KSTAT_SPOOF_ATIME_TV_NSEC;
    }
    if let Some(v) = mtime {
        mtime_secs = v;
        flags |= KSTAT_SPOOF_MTIME_TV_SEC;
    }
    if let Some(v) = mtime_nsec {
        mtime_nanosecs = v;
        flags |= KSTAT_SPOOF_MTIME_TV_NSEC;
    }
    if let Some(v) = ctime {
        ctime_secs = v;
        flags |= KSTAT_SPOOF_CTIME_TV_SEC;
    }
    if let Some(v) = ctime_nsec {
        ctime_nanosecs = v;
        flags |= KSTAT_SPOOF_CTIME_TV_NSEC;
    }
    if let Some(v) = blocks {
        spoofed_blocks = v;
        flags |= KSTAT_SPOOF_BLOCKS;
    }
    if let Some(v) = blksize {
        spoofed_blksize = v;
        flags |= KSTAT_SPOOF_BLKSIZE;
    }

    let mut cmd = SusfsSusKstat {
        is_statically: true,
        target_ino: stat_result.ino() as u64,
        target_pathname: [0; SUSFS_MAX_LEN_PATHNAME],
        spoofed_ino,
        spoofed_dev,
        spoofed_nlink,
        spoofed_size,
        spoofed_atime_tv_sec: atime_secs,
        spoofed_atime_tv_nsec: atime_nanosecs,
        spoofed_mtime_tv_sec: mtime_secs,
        spoofed_mtime_tv_nsec: mtime_nanosecs,
        spoofed_ctime_tv_sec: ctime_secs,
        spoofed_ctime_tv_nsec: ctime_nanosecs,
        spoofed_blocks,
        spoofed_blksize,
        flags,
        err: ERR_CMD_NOT_SUPPORTED,
    };

    let path_bytes = path.as_bytes();
    let copy_len = path_bytes.len().min(SUSFS_MAX_LEN_PATHNAME - 1);
    cmd.target_pathname[..copy_len].copy_from_slice(&path_bytes[..copy_len]);

    unsafe {
        libc::syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY,
            &mut cmd,
        )
    };

    if cmd.err == ERR_CMD_NOT_SUPPORTED {
        Err(anyhow!("Command not supported"))
    } else if cmd.err != 0 {
        Err(anyhow!("Error: {}", cmd.err))
    } else {
        Ok(())
    }
}
