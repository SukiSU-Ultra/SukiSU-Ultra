use anyhow::{Context, Result};
use log::{error, info, warn};

use std::{
    env,
    ffi::CString,
    fs::{self, File},
    io,
    os::unix::fs::MetadataExt,
    os::unix::io::AsRawFd,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{feature::FeatureId, ksucalls};
use libc;
use signal_hook::low_level::register;

const K: u32 = b'K' as u32;
const KSU_IOCTL_UID_SCANNER: i32 = libc::_IOWR::<()>(K, 105);

const UID_SCANNER_OP_REGISTER_PID: u32 = 1;
const UID_SCANNER_OP_UPDATE_UID_LIST: u32 = 2;

const USER_DATA_BASE_PATH: &str = "/data/user_de";
const MAX_USERS: usize = 8;

#[repr(C)]
struct UidListEntry {
    uid: u32,
    package_name: [u8; 256],
}

impl Default for UidListEntry {
    fn default() -> Self {
        Self { uid: 0, package_name: [0u8; 256] }
    }
}

#[repr(C)]
#[derive(Default)]
struct RegisterUidScannerCmd {
    operation: u32, // UID_SCANNER_OP_*
    pid: i32,       // daemon PID (for REGISTER_PID operation)
    entries_ptr: u64, // pointer to array of UidListEntry (for UPDATE_UID_LIST)
    count: u32,     // number of entries (for UPDATE_UID_LIST)
}

fn perform_scan_update() {
    match perform_uid_scan() {
        Ok(count) => info!("uid_scanner: scan completed, {count} entries"),
        Err(e) => error!("uid_scanner: scan failed: {e}"),
    }
}

fn scan_signal_handler() {
    // Signal received, perform scan directly
    perform_scan_update();
}

/// Register UID scanner daemon with kernel
fn register_uid_scanner_daemon(pid: i32) -> Result<()> {
    let mut cmd = RegisterUidScannerCmd {
        operation: UID_SCANNER_OP_REGISTER_PID,
        pid,
        entries_ptr: 0,
        count: 0,
    };
    ksucalls::ksuctl(KSU_IOCTL_UID_SCANNER, &raw mut cmd)?;
    Ok(())
}

fn register_with_kernel() -> Result<()> {
    let pid = std::process::id() as i32;
    register_uid_scanner_daemon(pid)
        .with_context(|| "failed to register daemon PID with kernel")?;
    info!("uid_scanner: registered with kernel (pid={})", pid);
    Ok(())
}

/// Update UID list in kernel
fn update_uid_list_in_kernel(entries: &[(u32, String)]) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }

    // Convert entries to kernel format
    let mut kernel_entries: Vec<UidListEntry> = Vec::with_capacity(entries.len());
    for (uid, pkg) in entries {
        let mut entry = UidListEntry::default();
        entry.uid = *uid;
        
        let pkg_bytes = pkg.as_bytes();
        let copy_len = pkg_bytes.len().min(255); // Leave room for null terminator
        entry.package_name[..copy_len].copy_from_slice(&pkg_bytes[..copy_len]);
        entry.package_name[copy_len] = 0; // Null terminator
        
        kernel_entries.push(entry);
    }

    let mut cmd = RegisterUidScannerCmd {
        operation: UID_SCANNER_OP_UPDATE_UID_LIST,
        pid: 0,
        entries_ptr: kernel_entries.as_ptr() as u64,
        count: kernel_entries.len() as u32,
    };

    ksucalls::ksuctl(KSU_IOCTL_UID_SCANNER, &raw mut cmd)
        .with_context(|| "failed to update UID list in kernel")?;

    Ok(())
}

fn get_users_from_pm(user_dirs: &mut Vec<PathBuf>) {
    let output = Command::new("sh")
        .arg("-c")
        .arg("pm list users 2>/dev/null | grep 'UserInfo{' | sed 's/.*UserInfo{\\([0-9]*\\):.*/\\1/'")
        .output();

    let Ok(output) = output else { return };
    if !output.status.success() {
        return;
    }

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if user_dirs.len() >= MAX_USERS {
            break;
        }
        if let Ok(user_id) = line.trim().parse::<i32>() {
            if user_id >= 0 {
                let path = PathBuf::from(format!("{USER_DATA_BASE_PATH}/{user_id}"));
                if path.exists() {
                    user_dirs.push(path);
                }
            }
        }
    }
}

fn get_users_from_directory_scan(user_dirs: &mut Vec<PathBuf>) {
    let dir = Path::new(USER_DATA_BASE_PATH);
    let Ok(entries) = fs::read_dir(dir) else {
        warn!(
            "uid_scanner: directory open failed {}",
            USER_DATA_BASE_PATH
        );
        user_dirs.push(PathBuf::from(format!("{USER_DATA_BASE_PATH}/0")));
        return;
    };

    for entry in entries.flatten() {
        if user_dirs.len() >= MAX_USERS {
            break;
        }

        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }

        if let Ok(user_id) = name.parse::<i32>() {
            if user_id >= 0 {
                user_dirs.push(entry.path());
            }
        }
    }

    if user_dirs.is_empty() {
        user_dirs.push(PathBuf::from(format!("{USER_DATA_BASE_PATH}/0")));
    }
}

fn get_user_directories() -> Vec<PathBuf> {
    let mut user_dirs = Vec::new();

    get_users_from_pm(&mut user_dirs);
    if user_dirs.is_empty() {
        get_users_from_directory_scan(&mut user_dirs);
    }

    user_dirs
}

fn perform_uid_scan() -> Result<usize> {
    let mut entries: Vec<(u32, String)> = Vec::new();

    let user_dirs = get_user_directories();
    info!(
        "uid_scanner: scan started, {} user directories",
        user_dirs.len()
    );

    for user_dir in &user_dirs {
        let Ok(apps) = fs::read_dir(user_dir) else {
            warn!("uid_scanner: failed to open {}", user_dir.display());
            continue;
        };

        for entry in apps.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else {
                warn!("uid_scanner: stat failed {}", path.display());
                continue;
            };

            if !meta.is_dir() {
                continue;
            }

            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };

            let uid = meta.uid();
            entries.push((uid, name.to_string()));
        }
    }

    info!("uid_scanner: scan complete, found {} packages", entries.len());

    // Send UID list directly to kernel via IOCTL
    update_uid_list_in_kernel(&entries)
        .with_context(|| "failed to update UID list in kernel")?;

    info!("uid_scanner: updated {} entries in kernel", entries.len());

    Ok(entries.len())
}

fn setup_signal_handler() -> Result<()> {
    unsafe {
        register(libc::SIGUSR1, scan_signal_handler)
            .map_err(|e| anyhow::anyhow!("failed to register SIGUSR1 handler: {}", e))?;
    }
    info!("uid_scanner: SIGUSR1 signal handler installed");
    Ok(())
}

/// Check if we're running as uid_scanner daemon
pub fn is_daemon_mode() -> bool {
    env::var("KSU_UID_SCANNER_DAEMON").is_ok()
}

fn daemon_main() -> Result<()> {
    match crate::ksucalls::get_feature(FeatureId::UidScanner as u32) {
        Ok((value, supported)) => {
            if !supported || value == 0 {
                info!("uid_scanner: feature disabled, skip starting daemon");
                return Ok(());
            }
        }
        Err(_) => {
            info!("uid_scanner: failed to check feature status, skip starting daemon");
            return Ok(());
        }
    }
    
    // Register PID with kernel so it can send us signals
    register_with_kernel()?;

    // Setup signal handler
    setup_signal_handler()?;

    info!("uid_scanner: daemon starting");

    // Perform initial scan
    perform_scan_update();

    // Main loop: wait for signals
    loop {
        thread::park();
    }
}

pub fn run_daemon() -> Result<()> {
    if is_daemon_mode() {
        if let Err(e) = daemon_main() {
            error!("uid_scanner daemon error: {e}");
            std::process::exit(1);
        }
        return Ok(());
    }

    let exe_path = env::current_exe()
        .context("failed to get current executable path")?;
    
    let mut command = Command::new(&exe_path);
    
    #[cfg(unix)]
    {
        command = command.process_group(0);
        
        command = unsafe {
            command.pre_exec(|| {
                use crate::utils::switch_cgroups;
                
                switch_cgroups();
                
                let dev_null = File::open("/dev/null")
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                let null_fd = dev_null.as_raw_fd();
                
                unsafe {
                    if libc::dup2(null_fd, libc::STDIN_FILENO) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::dup2(null_fd, libc::STDOUT_FILENO) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::dup2(null_fd, libc::STDERR_FILENO) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                
                Ok(())
            })
        };
    }
    
    command = command.env("KSU_UID_SCANNER_DAEMON", "1");
    
    command.spawn()
        .context("failed to spawn uid_scanner daemon process")?;
    
    Ok(())
}

/// One-shot scan, intended for manual invocation from CLI/manager.
pub fn scan_once() -> Result<()> {
    perform_scan_update();
    Ok(())
}

pub fn start_uid_scanner_service() -> Result<()> {
    // Wait for /sdcard/Android directory to be mounted
    let android_dir = Path::new("/sdcard/Android");
    while !android_dir.exists() || !android_dir.is_dir() {
        thread::sleep(Duration::from_secs(1));
    }
    
    run_daemon()?;
    info!("uid_scanner: daemon started in background");
    Ok(())
}
