use anyhow::{Result, anyhow, bail};
use libc::{c_int, c_ulong, prctl};
use notify::{RecursiveMode, Watcher};
use std::{
    ffi::{CStr, CString, OsStr},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    ptr,
};

pub const KPM_DIR: &str = "/data/adb/kpm";

// SukiSU KPM prctl command space
const KSU_OPTIONS: c_int = 0xdeadbeef_u32 as c_int;
const SUKISU_KPM_LOAD: c_int = 28;
const SUKISU_KPM_UNLOAD: c_int = 29;
const SUKISU_KPM_NUM: c_int = 30;
const SUKISU_KPM_LIST: c_int = 31;
const SUKISU_KPM_INFO: c_int = 32;
const SUKISU_KPM_CONTROL: c_int = 33;
const SUKISU_KPM_VERSION: c_int = 34;

/// Convert raw kernel return code to `Result`.
#[inline(always)]
fn check_out(rc: c_int) -> Result<c_int> {
    if rc < 0 {
        bail!("KPM error: {}", std::io::Error::from_raw_os_error(-rc));
    }
    Ok(rc)
}

/// Load a `.kpm` into kernel space.
pub fn kpm_load(path: &str, args: Option<&str>) -> Result<()> {
    let path_c = CString::new(path)?;
    let args_c = args.map(CString::new).transpose()?;

    let mut rc: c_int = -1;
    // SAFETY: pointers live through the prctl; null-check done by CString.
    unsafe {
        prctl(
            KSU_OPTIONS,
            SUKISU_KPM_LOAD,
            path_c.as_ptr() as c_ulong,
            args_c.as_ref().map_or(ptr::null(), |s| s.as_ptr()) as c_ulong,
            &mut rc as *mut c_int as c_ulong,
        );
    }
    check_out(rc)?;
    println!("Success");
    Ok(())
}

/// Unload by module name.
pub fn kpm_unload(name: &str) -> Result<()> {
    let name_c = CString::new(name)?;
    let mut rc = -1;
    unsafe {
        prctl(
            KSU_OPTIONS,
            SUKISU_KPM_UNLOAD,
            name_c.as_ptr() as c_ulong,
            0,
            &mut rc as *mut _ as c_ulong,
        );
    }
    check_out(rc)?;
    Ok(())
}

/// Return loaded module count.
pub fn kpm_num() -> Result<i32> {
    let mut rc = -1;
    unsafe {
        prctl(
            KSU_OPTIONS,
            SUKISU_KPM_NUM,
            0,
            0,
            &mut rc as *mut _ as c_ulong,
        )
    };
    let n = check_out(rc)?;
    println!("{n}");
    Ok(n)
}

/// Print name list of loaded modules.
pub fn kpm_list() -> Result<()> {
    let mut buf = vec![0u8; 1024];
    let mut rc = -1;
    unsafe {
        prctl(
            KSU_OPTIONS,
            SUKISU_KPM_LIST,
            buf.as_mut_ptr() as c_ulong,
            buf.len() as c_ulong,
            &mut rc as *mut _ as c_ulong,
        );
    }
    check_out(rc)?;
    print!("{}", buf2str(&buf));
    Ok(())
}

/// Print single module info.
pub fn kpm_info(name: &str) -> Result<()> {
    let name_c = CString::new(name)?;
    let mut buf = vec![0u8; 256];
    let mut rc = -1;
    unsafe {
        prctl(
            KSU_OPTIONS,
            SUKISU_KPM_INFO,
            name_c.as_ptr() as c_ulong,
            buf.as_mut_ptr() as c_ulong,
            &mut rc as *mut _ as c_ulong,
        );
    }
    check_out(rc)?;
    println!("{}", buf2str(&buf));
    Ok(())
}

/// Send control string to a module; returns kernel answer.
pub fn kpm_control(name: &str, args: &str) -> Result<i32> {
    let name_c = CString::new(name)?;
    let args_c = CString::new(args)?;
    let mut rc = -1;
    unsafe {
        prctl(
            KSU_OPTIONS,
            SUKISU_KPM_CONTROL,
            name_c.as_ptr() as c_ulong,
            args_c.as_ptr() as c_ulong,
            &mut rc as *mut _ as c_ulong,
        );
    }
    check_out(rc)
}

/// Print loader version string.
pub fn kpm_version_loader() -> Result<()> {
    let mut buf = vec![0u8; 1024];
    let mut rc = -1;
    unsafe {
        prctl(
            KSU_OPTIONS,
            SUKISU_KPM_VERSION,
            buf.as_mut_ptr() as c_ulong,
            buf.len() as c_ulong,
            &mut rc as *mut _ as c_ulong,
        );
    }
    check_out(rc)?;
    print!("{}", buf2str(&buf));
    Ok(())
}

/// Validate loader version; empty or "Error*" => fail.
pub fn check_kpm_version() -> Result<String> {
    let mut buf = vec![0u8; 1024];
    let mut rc = -1;
    unsafe {
        prctl(
            KSU_OPTIONS,
            SUKISU_KPM_VERSION,
            buf.as_mut_ptr() as c_ulong,
            buf.len() as c_ulong,
            &mut rc as *mut _ as c_ulong,
        );
    }
    check_out(rc)?;
    let ver = buf2str(&buf);
    if ver.is_empty() || ver.starts_with("Error") {
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
            if p.extension() == Some(OsStr::new("kpm")) && load_kpm(&p).is_err() {
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
        if p.extension() == Some(OsStr::new("kpm")) && p.file_stem() == Some(OsStr::new(name)) {
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
        if p.extension() == Some(OsStr::new("kpm"))
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
        if p.extension() == Some(OsStr::new("kpm")) {
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
