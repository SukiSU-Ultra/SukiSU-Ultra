use anyhow::{bail, Context, Result};
use log::{debug, error, info, warn};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Mutex,
    os::unix::fs::PermissionsExt
};
use libc::c_long;

const SU_PATHS: &[&str] = &[
    "/system/bin/su",
    "/vendor/bin/su",
    "/product/bin/su",
    "/system_ext/bin/su",
    "/odm/bin/su",
    "/system/xbin/su",
    "/system_ext/xbin/su",
];
const KSUD_PATH: &str = "/data/adb/ksud";
const SH_PATH: &str = "/system/bin/sh";

const KERNEL_SU_OPTION: u32 = 0xDEADBEEF;
const CMD_UID_GRANTED_ROOT: u32 = 12;
const CMD_GRANT_ROOT: u32 = 0;
const CMD_SU_ESCALATION_REQUEST: u32 = 50;

#[inline]
fn get_current_uid() -> Result<u32> {
    Ok(unsafe { libc::getuid() })
}

#[inline]
fn get_current_pid() -> u32 {
    unsafe { libc::getpid() as u32 }
}

fn prctl_ksu(cmd: u32, arg2: u64, arg3: u64, arg4: u64) -> Result<u32> {
    let mut result: u32 = 0;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_prctl,
            KERNEL_SU_OPTION as c_long,
            cmd as c_long,
            arg2 as c_long,
            arg3 as c_long,
            arg4 as c_long,
            &mut result as *mut u32 as c_long,
        )
    };
    if ret != 0 {
        bail!("prctl failed: {}", ret);
    }
    if result != KERNEL_SU_OPTION {
        bail!("kernel module not found");
    }
    Ok(result)
}

fn ksucalls_is_uid_allowed(uid: u32) -> bool {
    let mut allowed = false;
    prctl_ksu(
        CMD_UID_GRANTED_ROOT,
        uid as u64,
        0,
        &mut allowed as *mut bool as u64,
    )
    .is_ok_and(|_| allowed)
}

fn ksucalls_grant_root_access() -> Result<()> {
    prctl_ksu(CMD_GRANT_ROOT, 0, 0, 0)?;
    Ok(())
}

fn ksucalls_request_su_escalation(pid: u32, uid: u32) -> Result<()> {
    prctl_ksu(CMD_SU_ESCALATION_REQUEST, uid as u64, pid as u64, 0)?;
    Ok(())
}

pub struct SuHijacker {
    original_binaries: Vec<(PathBuf, Vec<u8>)>,
    hijack_active: bool,
}

impl SuHijacker {
    pub fn new() -> Self {
        Self {
            original_binaries: Vec::new(),
            hijack_active: false,
        }
    }

    pub fn init_su_hijack(&mut self) -> Result<()> {
        info!("Initializing su hijack system");
        self.backup_original_binaries()?;
        self.install_hijack_wrappers()?;
        self.setup_hijack_monitoring()?;
        self.hijack_active = true;
        info!("Su hijack system initialized");
        Ok(())
    }

    fn backup_original_binaries(&mut self) -> Result<()> {
        info!("Backing up original su binaries");
        for su in SU_PATHS {
            let p = Path::new(su);
            if p.exists() {
                match fs::read(p) {
                    Ok(data) => {
                        self.original_binaries.push((p.to_path_buf(), data));
                        debug!("Backed up: {}", su);
                    }
                    Err(e) => warn!("Backup {} failed: {}", su, e),
                }
            }
        }
        info!("Backed up {} binaries", self.original_binaries.len());
        Ok(())
    }

    fn install_hijack_wrappers(&self) -> Result<()> {
        info!("Installing hijack wrappers");
        for su in SU_PATHS {
            let p = Path::new(su);
            if p.exists() && self.create_hijack_wrapper(p).is_err() {
                warn!("Wrapper for {} failed", su);
            }
        }
        Ok(())
    }

    fn create_hijack_wrapper(&self, su_path: &Path) -> Result<()> {
        let script = format!("#!/system/bin/sh\n# KernelSU su hijack wrapper\n{}\n", KSUD_PATH);
        fs::write(su_path, script.as_bytes())
            .with_context(|| format!("write wrapper {}", su_path.display()))?;
        let mut perms = fs::metadata(su_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(su_path, perms)?;
        Ok(())
    }

    fn setup_hijack_monitoring(&self) -> Result<()> {
        info!("Setting up su access monitoring");
        std::thread::spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let Ok(output) = Command::new("ps")
                .args(&["-A", "-o", "pid,ppid,uid,cmd"])
                .output()
            else {
                continue;
            };
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                if line.contains("su") && !line.contains("ksud") {
                    if let Some((pid, uid)) = Self::parse_process_info(line) {
                        Self::handle_privilege_escalation(pid, uid);
                    }
                }
            }
        });
        Ok(())
    }

    fn parse_process_info(line: &str) -> Option<(u32, u32)> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            if let (Ok(pid), Ok(uid)) = (parts[0].parse::<u32>(), parts[2].parse::<u32>()) {
                return Some((pid, uid));
            }
        }
        None
    }

    fn handle_privilege_escalation(pid: u32, uid: u32) {
        debug!("Handle escalation PID:{} UID:{}", pid, uid);
        if ksucalls_is_uid_allowed(uid) {
            info!("Grant root for UID:{}", uid);
            if let Err(e) = ksucalls_request_su_escalation(pid, uid) {
                error!("Kernel escalation failed: {}", e);
            }
        } else {
            warn!("Su access denied for UID:{}", uid);
        }
    }

    pub fn restore_original_binaries(&mut self) -> Result<()> {
        if !self.hijack_active {
            return Ok(());
        }
        info!("Restoring original su binaries");
        for (path, data) in &self.original_binaries {
            if fs::write(path, data).is_err() {
                warn!("Restore {} failed", path.display());
                continue;
            }
            if let Ok(meta) = fs::metadata(path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o755);
                let _ = fs::set_permissions(path, perms);
            }
            debug!("Restored: {}", path.display());
        }
        self.hijack_active = false;
        Ok(())
    }

    pub fn cleanup(&mut self) -> Result<()> {
        if self.hijack_active {
            self.restore_original_binaries()?;
        }
        self.original_binaries.clear();
        info!("SuHijacker cleanup completed");
        Ok(())
    }
}

static HIJACKER: Mutex<Option<SuHijacker>> = Mutex::new(None);

pub fn init_global_su_hijacker() -> Result<()> {
    let mut g = HIJACKER.lock().unwrap();
    if g.is_none() {
        let mut h = SuHijacker::new();
        h.init_su_hijack()?;
        *g = Some(h);
    }
    Ok(())
}

pub fn cleanup_global_su_hijacker() -> Result<()> {
    let mut g = HIJACKER.lock().unwrap();
    if let Some(ref mut h) = g.as_mut() {
        h.cleanup()?;
    }
    *g = None;
    Ok(())
}

pub fn handle_su_execution(args: &[String]) -> Result<()> {
    info!("Su execution intercepted: {:?}", args);
    let uid = get_current_uid()?;
    if ksucalls_is_uid_allowed(uid) {
        info!("Su access granted for UID:{}", uid);
        ksucalls_grant_root_access()?;
        let status = Command::new(KSUD_PATH)
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .with_context(|| format!("execute {}", KSUD_PATH))?;
        std::process::exit(status.code().unwrap_or(1));
    } else {
        warn!("Su access denied for UID:{}", uid);
        let status = Command::new(SH_PATH)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .with_context(|| format!("execute {}", SH_PATH))?;
        std::process::exit(status.code().unwrap_or(1));
    }
}