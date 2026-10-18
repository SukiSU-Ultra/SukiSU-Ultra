/*
 * KPM (Kernel Patch Module) operations.
 *
 * Reached via the new single-extension ioctl KSU_IOCTL_EXTENSION with
 * extension_id=KSU_EXTENSION_KPM. The user payload is a struct ksu_kpm_cmd
 * forwarded verbatim to kernel/extension/kpm.c::do_kpm().
 */
use std::{
    ffi::{CStr, CString, OsStr},
    fs, io,
    os::unix::fs::PermissionsExt,
    path::Path,
};

use anyhow::{Result, bail};

use crate::ksu_uapi;
use crate::ksucalls::{extension_io, get_extension};

const KPM_DIR: &str = "/data/adb/kpm";

fn kpm_io<T>(control_code: u32, arg1: u64, arg2: u64) -> Result<i32> {
    let mut ret = -1i32;
    let mut cmd = ksu_uapi::ksu_kpm_cmd {
        control_code: control_code as u64,
        arg1,
        arg2,
        result_code: &raw mut ret as u64,
    };
    let result = unsafe { extension_io(ksu_uapi::KSU_EXTENSION_KPM as u32, &raw mut cmd)? };
    if result < 0 {
        return Err(anyhow::anyhow!(io::Error::from_raw_os_error(-result)));
    }
    Ok(ret)
}

pub fn enabled() -> Result<bool> {
    let state = get_extension(ksu_uapi::KSU_EXTENSION_KPM as u32)?;
    Ok(state.supported && state.value != 0)
}

pub fn load_module<P>(path: P, args: Option<&str>) -> Result<()>
where
    P: AsRef<Path>,
{
    let path = CString::new(path.as_ref().to_string_lossy().to_string())?;
    let args = args.map_or_else(|| CString::new(String::new()), CString::new)?;

    let ret = kpm_io(
        ksu_uapi::SUKISU_KPM_LOAD,
        path.as_ptr() as u64,
        args.as_ptr() as u64,
    )?;
    if ret < 0 {
        println!("Failed to load kpm: {}", io::Error::from_raw_os_error(ret));
    }
    Ok(())
}

pub fn list() -> Result<()> {
    let mut buf = vec![0u8; 1024];

    let ret = kpm_io(
        ksu_uapi::SUKISU_KPM_LIST,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    )?;
    if ret < 0 {
        println!(
            "Failed to get kpm list: {}",
            io::Error::from_raw_os_error(ret)
        );
        return Ok(());
    }

    println!("{}", buf2str(&buf));

    Ok(())
}

pub fn unload_module(name: String) -> Result<()> {
    let name = CString::new(name)?;

    let ret = kpm_io(ksu_uapi::SUKISU_KPM_UNLOAD, name.as_ptr() as u64, 0)?;
    if ret < 0 {
        println!(
            "Failed to unload kpm: {}",
            io::Error::from_raw_os_error(ret)
        );
    }
    Ok(())
}

pub fn info(name: String) -> Result<()> {
    let name = CString::new(name)?;
    let mut buf = vec![0u8; 256];

    let ret = kpm_io(
        ksu_uapi::SUKISU_KPM_INFO,
        name.as_ptr() as u64,
        buf.as_mut_ptr() as u64,
    )?;
    if ret < 0 {
        println!(
            "Failed to get kpm info: {}",
            io::Error::from_raw_os_error(ret)
        );
        return Ok(());
    }
    println!("{}", buf2str(&buf));
    Ok(())
}

pub fn control(name: String, args: String) -> Result<i32> {
    let name = CString::new(name)?;
    let args = CString::new(args)?;

    let ret = kpm_io(
        ksu_uapi::SUKISU_KPM_CONTROL,
        name.as_ptr() as u64,
        args.as_ptr() as u64,
    )?;
    if ret < 0 {
        println!(
            "Failed to control kpm: {}",
            io::Error::from_raw_os_error(ret)
        );
    }

    Ok(ret)
}

pub fn num() -> Result<i32> {
    let ret = kpm_io(ksu_uapi::SUKISU_KPM_NUM, 0, 0)?;
    if ret < 0 {
        return Ok(ret);
    }
    println!("{ret}");
    Ok(ret)
}

pub fn version() -> Result<()> {
    let mut buf = vec![0u8; 1024];

    let ret = kpm_io(
        ksu_uapi::SUKISU_KPM_VERSION,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    )?;
    if ret < 0 {
        println!(
            "Failed to get kpm version: {}",
            io::Error::from_raw_os_error(ret)
        );
        return Ok(());
    }

    let binding = buf2str(&buf);
    let ver = binding.trim();

    print!("{ver}");
    Ok(())
}

pub fn check_version() -> Result<String> {
    let mut buf = vec![0u8; 1024];

    let ret = kpm_io(
        ksu_uapi::SUKISU_KPM_VERSION,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    )?;
    if ret < 0 {
        println!(
            "Failed to get kpm version: {}",
            io::Error::from_raw_os_error(ret)
        );
        return Ok(String::new());
    }

    let binding = buf2str(&buf);
    let ver = binding.trim();

    if ver.is_empty() {
        bail!("KPM: invalid version response: {ver}");
    }
    log::info!("KPM: version check ok: {ver}");
    Ok(ver.to_string())
}

fn ensure_dir() -> Result<()> {
    let dir = Path::new(KPM_DIR);

    if !dir.exists() {
        let _ = fs::create_dir_all(KPM_DIR);
    }

    if dir.metadata()?.permissions().mode() != 0o777 {
        fs::set_permissions(KPM_DIR, fs::Permissions::from_mode(0o777))?;
    }

    Ok(())
}

pub fn booted_load() -> Result<()> {
    check_version()?;
    ensure_dir()?;

    if crate::utils::is_safe_mode() {
        log::warn!("KPM: safe-mode – all modules won't load");
        return Ok(());
    }

    load_all_modules()?;

    Ok(())
}

fn load_all_modules() -> Result<()> {
    let dir = Path::new(KPM_DIR);

    if !dir.is_dir() {
        return Ok(());
    }

    for entry in dir.read_dir()? {
        let p = entry?.path();

        if let Some(ex) = p.extension()
            && ex == OsStr::new("kpm")
        {
            load_module(p, None)?;
        }
    }
    Ok(())
}

/// Convert zero-padded kernel buffer to owned String.
/// DON'T REMOVE!!! we must use this method, because kernel use \0 to end of buffer
/// if directly to_string_lossy, we will get a lot of uninit data
/// refer: res = copy_to_user(arg1, &buffer, len + 1);
fn buf2str(buf: &[u8]) -> String {
    // SAFETY: buffer is always NUL-terminated by kernel.
    unsafe {
        CStr::from_ptr(buf.as_ptr().cast())
            .to_string_lossy()
            .into_owned()
    }
}
