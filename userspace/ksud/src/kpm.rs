use std::{
    ffi::{CStr, CString, OsStr},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow, bail};
use notify::{RecursiveMode, Watcher};

use crate::ksucalls::ksuctl;

pub const KPM_DIR: &str = "/data/adb/kpm";

const KPM_LOAD: u64 = 1;
const KPM_UNLOAD: u64 = 2;
const KPM_NUM: u64 = 3;
const KPM_LIST: u64 = 4;
const KPM_INFO: u64 = 5;
const KPM_CONTROL: u64 = 6;
const KPM_VERSION: u64 = 7;

const KSU_IOCTL_KPM: u32 = 0xc0004bc8; // _IOC(_IOC_READ|_IOC_WRITE, 'K', 200, 0)

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct KsuKpmCmd {
    pub control_code: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub result_code: u64,
}

fn kpm_ioctl(cmd: &mut KsuKpmCmd) -> std::io::Result<()> {
    ksuctl(KSU_IOCTL_KPM, cmd as *mut _)?;
    Ok(())
}

/// Convert raw kernel return code to `Result`.
#[inline(always)]
fn check_ret(rc: i32) -> Result<i32> {
    if rc < 0 {
        bail!("KPM error: {}", std::io::Error::from_raw_os_error(-rc));
    }
    Ok(rc)
}

/// Load a `.kpm` into kernel space.
pub fn kpm_load(path: &str, args: Option<&str>) -> Result<()> {
    let path_c = CString::new(path)?;
    let args_c = args.map(CString::new).transpose()?;

    let mut result: i32 = -1;
    let mut cmd = KsuKpmCmd {
        control_code: KPM_LOAD,
        arg1: path_c.as_ptr() as u64,
        arg2: args_c.as_ref().map_or(0, |s| s.as_ptr() as u64),
        result_code: &mut result as *mut i32 as u64,
    };

    kpm_ioctl(&mut cmd)?;
    check_ret(result)?;
    println!("Success");
    Ok(())
}

/// Unload by module name.
pub fn kpm_unload(name: &str) -> Result<()> {
    let name_c = CString::new(name)?;

    let mut result: i32 = -1;
    let mut cmd = KsuKpmCmd {
        control_code: KPM_UNLOAD,
        arg1: name_c.as_ptr() as u64,
        arg2: 0,
        result_code: &mut result as *mut i32 as u64,
    };

    kpm_ioctl(&mut cmd)?;
    check_ret(result)?;
    Ok(())
}

/// Return loaded module count.
pub fn kpm_num() -> Result<i32> {
    let mut result: i32 = -1;
    let mut cmd = KsuKpmCmd {
        control_code: KPM_NUM,
        arg1: 0,
        arg2: 0,
        result_code: &mut result as *mut i32 as u64,
    };

    kpm_ioctl(&mut cmd)?;
    let n = check_ret(result)?;
    println!("{n}");
    Ok(n)
}

/// Print name list of loaded modules.
pub fn kpm_list() -> Result<()> {
    let mut buf = vec![0u8; 1024];

    let mut result: i32 = -1;
    let mut cmd = KsuKpmCmd {
        control_code: KPM_LIST,
        arg1: buf.as_mut_ptr() as u64,
        arg2: buf.len() as u64,
        result_code: &mut result as *mut i32 as u64,
    };

    kpm_ioctl(&mut cmd)?;
    check_ret(result)?;
    print!("{}", buf2str(&buf));
    Ok(())
}

/// Print single module info.
pub fn kpm_info(name: &str) -> Result<()> {
    let name_c = CString::new(name)?;
    let mut buf = vec![0u8; 256];

    let mut result: i32 = -1;
    let mut cmd = KsuKpmCmd {
        control_code: KPM_INFO,
        arg1: name_c.as_ptr() as u64,
        arg2: buf.as_mut_ptr() as u64,
        result_code: &mut result as *mut i32 as u64,
    };

    kpm_ioctl(&mut cmd)?;
    check_ret(result)?;
    println!("{}", buf2str(&buf));
    Ok(())
}

/// Send control string to a module; returns kernel answer.
pub fn kpm_control(name: &str, args: &str) -> Result<i32> {
    let name_c = CString::new(name)?;
    let args_c = CString::new(args)?;

    let mut result: i32 = -1;
    let mut cmd = KsuKpmCmd {
        control_code: KPM_CONTROL,
        arg1: name_c.as_ptr() as u64,
        arg2: args_c.as_ptr() as u64,
        result_code: &mut result as *mut i32 as u64,
    };

    kpm_ioctl(&mut cmd)?;
    check_ret(result)
}

/// Print loader version string.
pub fn kpm_version_loader() -> Result<()> {
    let mut buf = vec![0u8; 1024];

    let mut result: i32 = -1;
    let mut cmd = KsuKpmCmd {
        control_code: KPM_VERSION,
        arg1: buf.as_mut_ptr() as u64,
        arg2: buf.len() as u64,
        result_code: &mut result as *mut i32 as u64,
    };

    kpm_ioctl(&mut cmd)?;
    check_ret(result)?;
    print!("{}", buf2str(&buf));
    Ok(())
}

/// Validate loader version; empty or "Error*" => fail.
pub fn check_kpm_version() -> Result<String> {
    let mut buf = vec![0u8; 1024];

    let mut result: i32 = -1;
    let mut cmd = KsuKpmCmd {
        control_code: KPM_VERSION,
        arg1: buf.as_mut_ptr() as u64,
        arg2: buf.len() as u64,
        result_code: &mut result as *mut i32 as u64,
    };

    kpm_ioctl(&mut cmd)?;
    check_ret(result)?;
    let ver = buf2str(&buf);
    if ver.is_empty() {
        bail!("KPM: invalid version response: {ver}");
    }
    log::info!("KPM: version check ok: {ver}");
    Ok(ver)
}

/// Create `/data/adb/kpm` with 0o777 if missing.
pub fn ensure_kpm_dir() -> Result<()> {
    fs::create_dir_all(KPM_DIR)?;
    let meta = fs::metadata(KPM_DIR)?;

    if meta.permissions().mode() & 0o777 != 0o777 {
        fs::set_permissions(KPM_DIR, fs::Permissions::from_mode(0o777))?;
    }
    Ok(())
}

/// Start file watcher for hot-(un)load.
pub fn start_kpm_watcher() -> Result<()> {
    check_kpm_version()?; // bails if loader too old
    ensure_kpm_dir()?;

    if crate::utils::is_safe_mode() {
        log::warn!("KPM: safe-mode – removing all modules");
        remove_all_kpms()?;
        return Ok(());
    }

    let mut watcher = notify::recommended_watcher(|res: Result<_, _>| match res {
        Ok(evt) => handle_kpm_event(evt),
        Err(e) => log::error!("KPM: watcher error: {e:?}"),
    })?;
    watcher.watch(Path::new(KPM_DIR), RecursiveMode::NonRecursive)?;
    log::info!("KPM: watcher active on {KPM_DIR}");
    Ok(())
}

fn handle_kpm_event(evt: notify::Event) {
    if let notify::EventKind::Create(_) = evt.kind {
        for p in evt.paths {
            if let Some(ex) = p.extension()
                && ex == OsStr::new("kpm")
                && load_kpm(&p).is_err()
            {
                log::warn!("KPM: failed to load {}", p.display());
            }
        }
    }
}

/// Load single `.kpm` file.
pub fn load_kpm(path: &Path) -> Result<()> {
    let s = path.to_str().ok_or_else(|| anyhow!("bad path"))?;
    kpm_load(s, None)
}

/// Unload module and delete file.
pub fn unload_kpm(name: &str) -> Result<()> {
    kpm_unload(name)?;

    if let Some(p) = find_kpm_file(name)? {
        let _ = fs::remove_file(&p);
        log::info!("KPM: deleted {}", p.display());
    }

    Ok(())
}

/// Locate `/data/adb/kpm/<name>.kpm`.
fn find_kpm_file(name: &str) -> Result<Option<PathBuf>> {
    let dir = Path::new(KPM_DIR);

    if !dir.is_dir() {
        return Ok(None);
    }

    for entry in fs::read_dir(dir)? {
        let p = entry?.path();
        if let Some(ex) = p.extension()
            && ex == OsStr::new("kpm")
            && let Some(fs) = p.file_stem()
            && fs == OsStr::new(name)
        {
            return Ok(Some(p));
        }
    }
    Ok(None)
}

/// Remove every `.kpm` file and unload it.
pub fn remove_all_kpms() -> Result<()> {
    let dir = Path::new(KPM_DIR);
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let p = entry?.path();
        if let Some(ex) = p.extension()
            && ex == OsStr::new("kpm")
            && let Some(name) = p.file_stem().and_then(|s| s.to_str())
            && let Err(e) = unload_kpm(name)
        {
            log::error!("KPM: unload {name} failed: {e}");
        }
    }
    Ok(())
}

/// Bulk-load existing `.kpm`s at boot.
pub fn load_kpm_modules() -> Result<()> {
    check_kpm_version()?;
    ensure_kpm_dir()?;

    let dir = Path::new(KPM_DIR);
    if !dir.is_dir() {
        return Ok(());
    }

    let (mut ok, mut ng) = (0, 0);

    for entry in fs::read_dir(dir)? {
        let p = entry?.path();
        if let Some(ex) = p.extension()
            && ex == OsStr::new("kpm")
        {
            match load_kpm(&p) {
                Ok(_) => ok += 1,
                Err(e) => {
                    log::warn!("KPM: load {} failed: {e}", p.display());
                    ng += 1;
                }
            }
        }
    }
    log::info!("KPM: bulk-load done – ok: {ok}, failed: {ng}");
    Ok(())
}

/// Convert zero-padded kernel buffer to owned String.
fn buf2str(buf: &[u8]) -> String {
    // SAFETY: buffer is always NUL-terminated by kernel.
    unsafe {
        CStr::from_ptr(buf.as_ptr().cast())
            .to_string_lossy()
            .into_owned()
    }
}
