#![allow(clippy::unreadable_literal)]
use crate::ksu_uapi;
use std::fs;
use std::os::fd::RawFd;
use std::sync::OnceLock;

// Global driver fd cache
static DRIVER_FD: OnceLock<RawFd> = OnceLock::new();
static INFO_CACHE: OnceLock<ksu_uapi::ksu_get_info_cmd> = OnceLock::new();

fn scan_driver_fd() -> Option<RawFd> {
    let fd_dir = fs::read_dir("/proc/self/fd").ok()?;

    for entry in fd_dir.flatten() {
        if let Ok(fd_num) = entry.file_name().to_string_lossy().parse::<i32>() {
            let link_path = format!("/proc/self/fd/{fd_num}");
            if let Ok(target) = fs::read_link(&link_path) {
                let target_str = target.to_string_lossy();
                if target_str.contains("[ksu_driver]") {
                    return Some(fd_num);
                }
            }
        }
    }

    None
}

// Get cached driver fd
fn init_driver_fd() -> Option<RawFd> {
    let fd = scan_driver_fd();
    if fd.is_none() {
        let mut fd = -1;
        unsafe {
            libc::syscall(
                libc::SYS_reboot,
                ksu_uapi::KSU_INSTALL_MAGIC1,
                ksu_uapi::KSU_INSTALL_MAGIC2,
                0,
                &mut fd,
            );
        };
        if fd >= 0 { Some(fd) } else { None }
    } else {
        fd
    }
}

// ioctl wrapper using libc
pub fn ksuctl<T>(request: u32, arg: *mut T) -> std::io::Result<i32> {
    use std::io;

    let fd = *DRIVER_FD.get_or_init(|| init_driver_fd().unwrap_or(-1));
    unsafe {
        let ret = libc::ioctl(fd as libc::c_int, request as i32, arg);
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    }
}

// API implementations
fn get_info() -> ksu_uapi::ksu_get_info_cmd {
    *INFO_CACHE.get_or_init(|| {
        let mut cmd = ksu_uapi::ksu_get_info_cmd {
            version: 0,
            flags: 0,
            features: 0,
        };
        let _ = ksuctl(ksu_uapi::KSU_IOCTL_GET_INFO, &raw mut cmd);
        cmd
    })
}

pub fn get_version() -> i32 {
    get_info().version as i32
}

pub fn is_late_load() -> bool {
    get_info().flags & ksu_uapi::KSU_GET_INFO_FLAG_LATE_LOAD != 0
}

pub fn grant_root() -> std::io::Result<()> {
    ksuctl(ksu_uapi::KSU_IOCTL_GRANT_ROOT, std::ptr::null_mut::<u8>())?;
    Ok(())
}

fn report_event(event: u32) {
    let mut cmd = ksu_uapi::ksu_report_event_cmd { event };
    let _ = ksuctl(ksu_uapi::KSU_IOCTL_REPORT_EVENT, &raw mut cmd);
}

pub fn report_post_fs_data() {
    report_event(ksu_uapi::EVENT_POST_FS_DATA);
}

pub fn report_boot_complete() {
    report_event(ksu_uapi::EVENT_BOOT_COMPLETED);
}

pub fn report_module_mounted() {
    report_event(ksu_uapi::EVENT_MODULE_MOUNTED);
}

pub fn check_kernel_safemode() -> bool {
    let mut cmd = ksu_uapi::ksu_check_safemode_cmd { in_safe_mode: 0 };
    let _ = ksuctl(ksu_uapi::KSU_IOCTL_CHECK_SAFEMODE, &raw mut cmd);
    cmd.in_safe_mode != 0
}

pub fn set_sepolicy(payload: *const u8, payload_len: u64) -> std::io::Result<i32> {
    let mut ioctl_cmd = crate::ksu_uapi::ksu_set_sepolicy_cmd {
        data_len: payload_len,
        data: payload as u64,
    };

    ksuctl(ksu_uapi::KSU_IOCTL_SET_SEPOLICY, &raw mut ioctl_cmd)
}

/// Get feature value and support status from kernel
/// Returns (value, supported)
pub fn get_feature(feature_id: u32) -> std::io::Result<(u64, bool)> {
    let mut cmd = ksu_uapi::ksu_get_feature_cmd {
        feature_id,
        value: 0,
        supported: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_GET_FEATURE, &raw mut cmd)?;
    Ok((cmd.value, cmd.supported != 0))
}

/// Set feature value in kernel
pub fn set_feature(feature_id: u32, value: u64) -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_set_feature_cmd { feature_id, value };
    ksuctl(ksu_uapi::KSU_IOCTL_SET_FEATURE, &raw mut cmd)?;
    Ok(())
}

pub fn get_wrapped_fd(fd: RawFd) -> std::io::Result<RawFd> {
    let mut cmd = ksu_uapi::ksu_get_wrapper_fd_cmd {
        fd: fd as u32,
        flags: 0,
    };
    let result = ksuctl(ksu_uapi::KSU_IOCTL_GET_WRAPPER_FD, &raw mut cmd)?;
    Ok(result)
}

/// Get mark status for a process (pid=0 returns total marked count)
pub fn mark_get(pid: i32) -> std::io::Result<u32> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_GET,
        pid,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(cmd.result)
}

/// Mark a process (pid=0 marks all processes)
pub fn mark_set(pid: i32) -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_MARK,
        pid,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(())
}

/// Unmark a process (pid=0 unmarks all processes)
pub fn mark_unset(pid: i32) -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_UNMARK,
        pid,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(())
}

/// Refresh mark for all running processes
pub fn mark_refresh() -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_REFRESH,
        pid: 0,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(())
}

pub fn nuke_ext4_sysfs(mnt: &str) -> anyhow::Result<()> {
    let c_mnt = std::ffi::CString::new(mnt)?;
    let mut ioctl_cmd = ksu_uapi::ksu_nuke_ext4_sysfs_cmd {
        arg: c_mnt.as_ptr() as u64,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_NUKE_EXT4_SYSFS, &raw mut ioctl_cmd)?;
    Ok(())
}

/// Wipe all entries from umount list
pub fn umount_list_wipe() -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_add_try_umount_cmd {
        arg: 0,
        flags: 0,
        mode: ksu_uapi::KSU_UMOUNT_WIPE,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_ADD_TRY_UMOUNT, &raw mut cmd)?;
    Ok(())
}

/// Add mount point to umount list
pub fn umount_list_add(path: &str, flags: u32) -> anyhow::Result<()> {
    let c_path = std::ffi::CString::new(path)?;
    let mut cmd = ksu_uapi::ksu_add_try_umount_cmd {
        arg: c_path.as_ptr() as u64,
        flags,
        mode: ksu_uapi::KSU_UMOUNT_ADD,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_ADD_TRY_UMOUNT, &raw mut cmd)?;
    Ok(())
}

/// Delete mount point from umount list
pub fn umount_list_del(path: &str) -> anyhow::Result<()> {
    let c_path = std::ffi::CString::new(path)?;
    let mut cmd = ksu_uapi::ksu_add_try_umount_cmd {
        arg: c_path.as_ptr() as u64,
        flags: 0,
        mode: ksu_uapi::KSU_UMOUNT_DEL,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_ADD_TRY_UMOUNT, &raw mut cmd)?;
    Ok(())
}

/// Set current process's process group to init_group (pgid = 0)
pub fn set_init_pgrp() -> std::io::Result<()> {
    ksuctl(
        ksu_uapi::KSU_IOCTL_SET_INIT_PGRP,
        std::ptr::null_mut::<u8>(),
    )?;
    Ok(())
}

const SULOG_ENTRY_MAX: usize = 250;
const SULOG_ENTRY_SIZE: usize = 8;
const SULOG_BUFSIZ: usize = SULOG_ENTRY_MAX * SULOG_ENTRY_SIZE;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ListTryUmountCmd {
    arg: u64,
    buf_size: u32,
    _padding: u32,
}

/// List all mount points in umount list
pub fn umount_list_list() -> anyhow::Result<String> {
    const BUF_SIZE: usize = 4096;
    let mut buffer = vec![0u8; BUF_SIZE];
    let mut cmd = ListTryUmountCmd {
        arg: buffer.as_mut_ptr() as u64,
        buf_size: BUF_SIZE as u32,
        _padding: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_LIST_TRY_UMOUNT, &raw mut cmd)?;

    // Find null terminator or end of buffer
    let len = buffer.iter().position(|&b| b == 0).unwrap_or(BUF_SIZE);
    let result = String::from_utf8_lossy(&buffer[..len]).to_string();
    Ok(result)
}

#[repr(C)]
struct SulogEntryRcvPtr {
    index: u64,
    buf: u64,
    uptime: u64,
}

/// Fetch sulog from kernel and save to `/data/adb/ksu/log/sulog.log`
pub fn dump_sulog_to_file() -> anyhow::Result<()> {
    use std::io::Write;

    // Prepare buffers and pointers
    let mut buffer = vec![0u8; SULOG_BUFSIZ];
    let mut index: u8 = 0;
    let mut uptime: u32 = 0;

    // Allocate recv struct on heap so pointer is stable
    let mut recv = SulogEntryRcvPtr {
        index: 0,
        buf: 0,
        uptime: 0,
    };
    // pointer-to-pointer required by kernel handler
    let recv_ptr: *mut SulogEntryRcvPtr = &raw mut recv;

    unsafe {
        (*recv_ptr).index = (&raw mut index) as u64;
        (*recv_ptr).buf = buffer.as_mut_ptr() as u64;
        (*recv_ptr).uptime = (&raw mut uptime) as u64;

        // Use ioctl to request sulog dump from kernel
        let res = ksuctl(ksu_uapi::KSU_IOCTL_GET_SULOG_DUMP, &raw mut recv);
        if let Err(e) = res {
            return Err(e.into());
        }
    }

    // Parse buffer entries and format log
    let mut lines: Vec<String> = Vec::new();
    // index is the next write index; start from index and walk through SULOG_ENTRY_MAX entries
    for i in 0..SULOG_ENTRY_MAX {
        let idx = ((index as usize) + i) % SULOG_ENTRY_MAX;
        let off = idx * SULOG_ENTRY_SIZE;
        let s_time = u32::from_le_bytes(buffer[off..off + 4].try_into().unwrap_or([0u8; 4]));
        let data = u32::from_le_bytes(buffer[off + 4..off + 8].try_into().unwrap_or([0u8; 4]));
        if s_time == 0 && data == 0 {
            // empty slot
            continue;
        }
        let uid = data & 0x00FF_FFFF;
        let sym = ((data >> 24) & 0xFF) as u8;
        let sym_char = if sym.is_ascii_graphic() {
            sym as char
        } else {
            '?'
        };
        lines.push(format!("uptime_s={s_time} uid={uid} sym={sym_char}\n"));
    }

    // Prepare directory
    let log_dir = "/data/adb/ksu/log";
    let log_path = format!("{log_dir}/sulog.log");

    // Ensure log_dir is a directory (remove if it's a file)
    if std::path::Path::new(log_dir).exists() && !std::path::Path::new(log_dir).is_dir() {
        std::fs::remove_file(log_dir)?;
    }
    std::fs::create_dir_all(log_dir)?;

    // Directly overwrite the log file
    let mut file = std::fs::File::create(&log_path)?;
    for line in lines {
        file.write_all(line.as_bytes())?;
    }
    file.flush()?;

    Ok(())
}
