use anyhow::Result;
use libc::SYS_reboot;

const SUSFS_MAX_VERSION_BUFSIZE: usize = 16;
const SUSFS_ENABLED_FEATURES_SIZE: usize = 8192;
const ERR_CMD_NOT_SUPPORTED: i32 = 126;
const KSU_INSTALL_MAGIC1: u32 = 0xDEADBEEF;
const CMD_SUSFS_SHOW_VERSION: u32 = 0x555e1;
const CMD_SUSFS_SHOW_ENABLED_FEATURES: u32 = 0x555e2;
const SUSFS_MAGIC: u32 = 0xFAFAFAFA;

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

pub fn get_susfs_version() -> usize {
    let mut cmd = SusfsVersion {
        susfs_version: [0; SUSFS_MAX_VERSION_BUFSIZE],
        err: ERR_CMD_NOT_SUPPORTED,
    };

    let ret = unsafe {
        libc::syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            CMD_SUSFS_SHOW_VERSION,
            &mut cmd,
        )
    };

    if ret < 0 {
        return 0;
    }

    let ver = cmd.susfs_version.iter().position(|&b| b == 0).unwrap_or(16);
    std::str::from_utf8(&cmd.susfs_version[..ver]).unwrap_or("<invalid>");

    ver
}

pub fn get_susfs_status() -> bool {
    if get_susfs_version() < 0 { false } else { true }
}

pub fn get_susfs_features() {
    let mut cmd = SusfsFeatures {
        enabled_features: [0; SUSFS_ENABLED_FEATURES_SIZE],
        err: ERR_CMD_NOT_SUPPORTED,
    };

    let ret = unsafe {
        libc::syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            CMD_SUSFS_SHOW_ENABLED_FEATURES,
            &mut cmd,
        )
    };

    if ret < 0 {
        return;
    }

    let features = cmd
        .enabled_features
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(16);
    std::str::from_utf8(&cmd.enabled_features[..features]).unwrap_or("<invalid>");
    println!("{}", features);
}
