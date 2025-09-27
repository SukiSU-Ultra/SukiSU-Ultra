use anyhow::{Context, Result};
use libc::{prctl, PR_SET_NAME, uid_t, pid_t};
use log::{info, warn, error, debug};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use crate::{ksucalls, utils};

const KERNEL_SU_OPTION: u32 = 0xDEADBEEF;
const CMD_SU_ESCALATION_REQUEST: u32 = 50;
const CMD_UID_GRANTED_ROOT: u32 = 12;

const SU_PATHS: &[&str] = &[
    "/system/bin/su",
    "/vendor/bin/su", 
    "/product/bin/su",
    "/system_ext/bin/su",
    "/odm/bin/su",
    "/system/xbin/su",
    "/system_ext/xbin/su"
];

static RUNNING: AtomicBool = AtomicBool::new(false);

/// Process monitoring structure
#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: pid_t,
    uid: uid_t,
    cmdline: String,
    exe_path: String,
}

impl ProcessInfo {
    /// Create ProcessInfo from PID
    fn from_pid(pid: pid_t) -> Option<Self> {
        let uid = get_process_uid(pid)?;
        let cmdline = read_process_cmdline(pid).unwrap_or_default();
        let exe_path = read_process_exe(pid).unwrap_or_default();
        
        Some(ProcessInfo {
            pid,
            uid,
            cmdline,
            exe_path,
        })
    }
    
    /// Check if this process is attempting to execute su
    fn is_su_execution(&self) -> bool {
        // Check if any argument contains su path
        if self.cmdline.contains("su") {
            for path in SU_PATHS {
                if self.cmdline.contains(path) || self.exe_path == *path {
                    debug!("su execution detected in PID {}: {}", self.pid, self.cmdline);
                    return true;
                }
            }
        }
        false
    }
    
    /// Check if UID is authorized for su access
    fn is_authorized(&self) -> bool {
        is_allow_uid(self.uid)
    }
}

/// Read process UID from /proc/PID/status
fn get_process_uid(pid: pid_t) -> Option<uid_t> {
    let status_path = format!("/proc/{}/status", pid);
    let file = File::open(status_path).ok()?;
    let reader = BufReader::new(file);
    
    for line in reader.lines() {
        if let Ok(line) = line {
            if line.starts_with("Uid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    return parts[1].parse::<uid_t>().ok();
                }
            }
        }
    }
    None
}

/// Read process command line from /proc/PID/cmdline
fn read_process_cmdline(pid: pid_t) -> Option<String> {
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    fs::read_to_string(cmdline_path)
        .map(|s| s.replace('\0', " ").trim().to_string())
        .ok()
}

/// Read process executable path from /proc/PID/exe
fn read_process_exe(pid: pid_t) -> Option<String> {
    let exe_path = format!("/proc/{}/exe", pid);
    fs::read_link(exe_path)
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
}

/// Request kernel escalation for target process
fn request_kernel_escalation(uid: uid_t, pid: pid_t) -> Result<bool> {
    let mut result: u32 = 0;
    
    let ret = unsafe {
        prctl(
            KERNEL_SU_OPTION as i32,
            CMD_SU_ESCALATION_REQUEST as libc::c_ulong,
            uid as libc::c_ulong,
            pid as libc::c_ulong,
            &mut result as *mut u32 as libc::c_ulong,
        )
    };
    
    if ret == 0 && result == KERNEL_SU_OPTION {
        info!("cmd_su: escalation request successful for UID {} PID {}", uid, pid);
        Ok(true)
    } else {
        warn!("cmd_su: escalation request failed for UID {} PID {}, ret: {}", uid, pid, ret);
        Ok(false)
    }
}

/// Replace su execution with ksud
fn hijack_su_execution(process: &ProcessInfo) -> Result<()> {
    info!("cmd_su: hijacking su execution for PID {} UID {}", process.pid, process.uid);
    
    // Request kernel escalation first
    match request_kernel_escalation(process.uid, process.pid) {
        Ok(true) => {
            info!("cmd_su: kernel escalation granted for UID {} PID {}", process.uid, process.pid);
            
            // The kernel has already escalated privileges for the target process
            // The process should now have root access and can execute ksud
            
            debug!("cmd_su: su hijack completed for UID {} PID {}", process.uid, process.pid);
            Ok(())
        }
        Ok(false) => {
            warn!("cmd_su: kernel escalation denied for UID {} PID {}", process.uid, process.pid);
            Ok(())
        }
        Err(e) => {
            error!("cmd_su: escalation request error: {}", e);
            Ok(())
        }
    }
}

/// Monitor /proc for new processes
fn monitor_processes() -> Result<()> {
    info!("cmd_su: starting process monitor");
    
    let mut previous_pids = std::collections::HashSet::new();
    
    // Get initial process list
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries {
            if let Ok(entry) = entry {
                if let Ok(filename) = entry.file_name().into_string() {
                    if let Ok(pid) = filename.parse::<pid_t>() {
                        previous_pids.insert(pid);
                    }
                }
            }
        }
    }
    
    while RUNNING.load(Ordering::Relaxed) {
        let mut current_pids = std::collections::HashSet::new();
        
        // Scan current processes
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries {
                if let Ok(entry) = entry {
                    if let Ok(filename) = entry.file_name().into_string() {
                        if let Ok(pid) = filename.parse::<pid_t>() {
                            current_pids.insert(pid);
                            
                            // Check for new processes
                            if !previous_pids.contains(&pid) {
                                if let Some(process) = ProcessInfo::from_pid(pid) {
                                    if process.is_su_execution() && process.is_authorized() {
                                        debug!("cmd_su: detected authorized su execution: PID {} UID {} CMD {}",
                                               process.pid, process.uid, process.cmdline);
                                        
                                        if let Err(e) = hijack_su_execution(&process) {
                                            error!("cmd_su: failed to hijack su execution: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        previous_pids = current_pids;
        thread::sleep(Duration::from_millis(50)); // 50ms polling interval
    }
    
    info!("cmd_su: process monitor stopped");
    Ok(())
}

/// Alternative inotify-based monitoring for more efficient detection
fn monitor_executions_inotify() -> Result<()> {
    info!("cmd_su: starting inotify-based execution monitor");
    
    // Create inotify instance
    let inotify_fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if inotify_fd < 0 {
        return Err(anyhow::anyhow!("Failed to create inotify instance"));
    }
    
    // Watch su binary paths
    let mut watch_descriptors = Vec::new();
    for su_path in SU_PATHS {
        if Path::new(su_path).exists() {
            let path_cstr = CString::new(*su_path)?;
            let wd = unsafe {
                libc::inotify_add_watch(
                    inotify_fd,
                    path_cstr.as_ptr(),
                    libc::IN_ACCESS | libc::IN_OPEN
                )
            };
            
            if wd >= 0 {
                watch_descriptors.push(wd);
                debug!("cmd_su: watching {}", su_path);
            } else {
                warn!("cmd_su: failed to watch {}", su_path);
            }
        }
    }
    
    let mut buffer = [0u8; 4096];
    
    while RUNNING.load(Ordering::Relaxed) {
        let len = unsafe {
            libc::read(inotify_fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len())
        };
        
        if len > 0 {
            // Process inotify events - when su binary is accessed
            debug!("cmd_su: su binary access detected, scanning for authorized processes");
            
            // Scan recent processes for su executions
            scan_recent_su_executions()?;
        }
        
        thread::sleep(Duration::from_millis(10));
    }
    
    // Cleanup
    for wd in watch_descriptors {
        unsafe { libc::inotify_rm_watch(inotify_fd, wd as u32); }
    }
    unsafe { libc::close(inotify_fd); }
    
    info!("cmd_su: inotify monitor stopped");
    Ok(())
}

/// Scan for recent su executions when triggered by inotify
fn scan_recent_su_executions() -> Result<()> {
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries {
            if let Ok(entry) = entry {
                if let Ok(filename) = entry.file_name().into_string() {
                    if let Ok(pid) = filename.parse::<pid_t>() {
                        if let Some(process) = ProcessInfo::from_pid(pid) {
                            if process.is_su_execution() && process.is_authorized() {
                                debug!("cmd_su: found authorized su process: PID {} UID {}", 
                                       process.pid, process.uid);
                                
                                if let Err(e) = hijack_su_execution(&process) {
                                    error!("cmd_su: failed to hijack su execution: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Start su command hijacking daemon
pub fn start_cmd_su_daemon() -> Result<()> {
    if RUNNING.load(Ordering::Relaxed) {
        warn!("cmd_su: daemon already running");
        return Ok(());
    }
    
    // Check if KSU is available
    if ksucalls::get_version() <= 0 {
        return Err(anyhow::anyhow!("KSU not available, cannot start cmd_su daemon"));
    }
    
    info!("cmd_su: starting su command hijacking daemon");
    RUNNING.store(true, Ordering::Relaxed);
    
    // Set process name for easier identification
    let name = CString::new("ksu_cmd_su").context("Failed to create process name")?;
    unsafe {
        prctl(PR_SET_NAME, name.as_ptr() as libc::c_ulong, 0, 0, 0);
    }
    
    
    // Use inotify for more efficient monitoring if available
    let monitor_thread = if Path::new("/proc/sys/fs/inotify").exists() {
        thread::Builder::new()
            .name("cmd_su_inotify".to_string())
            .spawn(move || {
                if let Err(e) = monitor_executions_inotify() {
                    error!("cmd_su: inotify monitor error: {}", e);
                    // Fallback to process scanning
                    if let Err(e) = monitor_processes() {
                        error!("cmd_su: process monitor error: {}", e);
                    }
                }
            })?
    } else {
        thread::Builder::new()
            .name("cmd_su_monitor".to_string())
            .spawn(move || {
                if let Err(e) = monitor_processes() {
                    error!("cmd_su: monitor error: {}", e);
                }
            })?
    };
    
    info!("cmd_su: daemon started successfully");
    
    // The thread will run in the background
    std::mem::forget(monitor_thread);
    
    Ok(())
}

/// Stop su command hijacking daemon
pub fn stop_cmd_su_daemon() {
    if !RUNNING.load(Ordering::Relaxed) {
        return;
    }
    
    info!("cmd_su: stopping su command hijacking daemon");
    RUNNING.store(false, Ordering::Relaxed);
    
    // Give some time for threads to cleanup
    thread::sleep(Duration::from_millis(100));
    
    info!("cmd_su: daemon stopped");
}

pub fn is_allow_uid(uid: u32) -> bool {
    // Check through KSU allowlist system
    // This would normally interface with the KSU kernel module
    // For now, we'll implement a basic check
    
    // Allow root
    if uid == 0 {
        return true;
    }
    
    // Allow system uid
    if uid == 1000 {
        return true;
    }
    
    // Check if it's an app uid that's in the allowlist
    // This is where you'd interface with KSU's allowlist
    // For this implementation, we'll use a placeholder
    check_ksu_allowlist(uid)
}

fn check_ksu_allowlist(uid: u32) -> bool {
    let mut result: u32 = 0;
    let ret = unsafe {
        libc::prctl(
            KERNEL_SU_OPTION as i32,
            CMD_UID_GRANTED_ROOT as libc::c_ulong,
            uid as libc::c_ulong,
            0,
            &mut result as *mut u32 as libc::c_ulong,
        )
    };
    
    ret == 0 && result == KERNEL_SU_OPTION
}

/// Check if daemon is running
pub fn is_daemon_running() -> bool {
    RUNNING.load(Ordering::Relaxed)
}