use anyhow::{Context, Result};
use log::{error, info, warn};
use std::ffi::CString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::ksucalls;
#[cfg(target_os = "android")]
use libc;

const K: u32 = b'K' as u32;
const KSU_IOCTL_UID_SCANNER: i32 = libc::_IOWR::<()>(K, 105);

const UID_SCANNER_OP_REGISTER_PID: u32 = 1;
const UID_SCANNER_OP_UPDATE_UID_LIST: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UidListEntry {
    uid: u32,
    package_name: [u8; 256],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RegisterUidScannerCmd {
    operation: u32, // UID_SCANNER_OP_*
    pid: i32,       // daemon PID (for REGISTER_PID operation)
    entries_ptr: u64, // pointer to array of UidListEntry (for UPDATE_UID_LIST)
    count: u32,     // number of entries (for UPDATE_UID_LIST)
}

/// Register UID scanner daemon with kernel
pub fn register_uid_scanner_daemon(pid: i32) -> std::io::Result<()> {
    let mut cmd = RegisterUidScannerCmd {
        operation: UID_SCANNER_OP_REGISTER_PID,
        pid,
        entries_ptr: 0,
        count: 0,
    };
    ksucalls::ksuctl(KSU_IOCTL_REGISTER_UID_SCANNER, &raw mut cmd)?;
    Ok(())
}

/// Unregister UID scanner daemon from kernel
pub fn unregister_uid_scanner_daemon() -> std::io::Result<()> {
    register_uid_scanner_daemon(0)
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

    ksucalls::ksuctl(KSU_IOCTL_REGISTER_UID_SCANNER, &raw mut cmd)
        .with_context(|| "failed to update UID list in kernel")?;

    Ok(())
}

#[cfg(target_os = "android")]
unsafe extern "C" fn scan_signal_handler(_sig: libc::c_int) {
    // Signal received, perform scan directly
    perform_scan_update();
}

const USER_DATA_BASE_PATH: &str = "/data/user_de";
const MAX_USERS: usize = 8;

fn is_kernel_enabled() -> bool {
    use crate::feature::FeatureId;
    
    match crate::ksucalls::get_feature(FeatureId::UidScanner as u32) {
        Ok((value, supported)) => {
            if !supported {
                info!("uid_scanner: feature not supported by kernel");
                return false;
            }
            let enabled = value != 0;
            if !enabled {
                info!("uid_scanner: kernel feature disabled (uid_scanner=0)");
            }
            enabled
        }
        Err(e) => {
            warn!("uid_scanner: failed to get feature status: {}, treating as disabled", e);
            false
        }
    }
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
    let mut entries = Vec::<(u32, String)>::new();

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

#[cfg(target_os = "android")]
fn generate_random_process_name() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let pid = std::process::id();
    // Generate a random-looking name using timestamp and PID
    format!("ksu{:x}{:x}", timestamp & 0xffff, pid & 0xffff)
}

#[cfg(target_os = "android")]
fn set_process_name(name: &str) -> Result<()> {
    let cname = CString::new(name)?;
    unsafe {
        // PR_SET_NAME sets the process name (visible in /proc/pid/comm)
        if libc::prctl(libc::PR_SET_NAME, cname.as_ptr() as libc::c_ulong, 0, 0, 0) != 0 {
            anyhow::bail!("prctl PR_SET_NAME failed: {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn register_with_kernel() -> Result<()> {
    let pid = std::process::id() as i32;
    register_uid_scanner_daemon(pid)
        .with_context(|| "failed to register daemon PID with kernel")?;
    info!("uid_scanner: registered with kernel (pid={})", pid);
    Ok(())
}

#[cfg(target_os = "android")]
fn setup_signal_handler() -> Result<()> {
    unsafe {
        if libc::signal(libc::SIGUSR1, scan_signal_handler as usize)
            == libc::SIG_ERR
        {
            anyhow::bail!("failed to set SIGUSR1 handler");
        }
        info!("uid_scanner: SIGUSR1 signal handler installed");
    }
    Ok(())
}

fn perform_scan_update() {
    match perform_uid_scan() {
        Ok(count) => info!("uid_scanner: scan completed, {count} entries"),
        Err(e) => error!("uid_scanner: scan failed: {e}"),
    }
}

#[cfg(target_os = "android")]
fn daemon_main() -> Result<()> {
    // Generate random process name and set it
    let random_name = generate_random_process_name();
    set_process_name(&random_name)?;
    info!("uid_scanner: process name set to: {}", random_name);

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

#[cfg(not(target_os = "android"))]
fn daemon_main() -> Result<()> {
    // Non-Android platforms: just run directly
    register_with_kernel()?;
    info!("uid_scanner: daemon starting");
    perform_scan_update();
    loop {
        thread::park();
    }
}

pub fn run_daemon() -> Result<()> {
    // Check if kernel flag is enabled before starting
    if !is_kernel_enabled() {
        info!("uid_scanner: kernel flag disabled, daemon will not start");
        return Ok(());
    }

    #[cfg(target_os = "android")]
    {
        // Fork a child process to run the daemon
        let pid = unsafe { libc::fork() };
        
        match pid {
            -1 => {
                // Fork failed
                let err = std::io::Error::last_os_error();
                anyhow::bail!("fork failed: {}", err);
            }
            0 => {
                // Child process: run daemon
                // This process is now independent and will be reparented to init
                std::process::exit(match daemon_main() {
                    Ok(_) => 0,
                    Err(e) => {
                        error!("uid_scanner daemon error: {e}");
                        1
                    }
                });
            }
            _ => {
                // Parent process: return immediately
                info!("uid_scanner: daemon forked with PID {}", pid);
                Ok(())
            }
        }
    }

    #[cfg(not(target_os = "android"))]
    {
        // Non-Android: run directly
        daemon_main()
    }
}

/// One-shot scan, intended for manual invocation from CLI/manager.
pub fn scan_once() -> Result<()> {
    perform_scan_update();
    Ok(())
}
