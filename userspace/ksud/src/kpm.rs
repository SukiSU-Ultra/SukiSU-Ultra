use std::{
    ffi::{CString, OsStr},
    fs, io,
    os::unix::fs::PermissionsExt,
    path::Path,
};

use anyhow::{Result, bail};
use rustix::path::Arg;

use crate::ksucalls::ksuctl;

const KPM_DIR: &str = "/data/adb/kpm";
const KPM_LOAD: u64 = 1;
const KPM_UNLOAD: u64 = 2;
const KPM_NUM: u64 = 3;
const KPM_LIST: u64 = 4;
const KPM_INFO: u64 = 5;
const KPM_CONTROL: u64 = 6;
const KPM_VERSION: u64 = 7;

const K: u32 = b'K' as u32;
const KSU_IOCTL_KPM: i32 = libc::_IOWR::<()>(K, 200);

#[repr(C)]
struct KsuKpmCmd {
    pub control_code: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub result_code: u64,
}

pub fn load_module<P>(path: P, args: Option<&str>) -> Result<()>
where
    P: AsRef<Path>,
{
    let path = CString::new(path.as_ref().to_string_lossy().to_string())?;
    let args = args.map_or_else(|| CString::new(String::new()), CString::new)?;

    let mut ret = -1;
    let mut cmd = KsuKpmCmd {
        control_code: KPM_LOAD,
        arg1: path.as_ptr() as u64,
        arg2: args.as_ptr() as u64,
        result_code: &raw mut ret as u64,
    };

    ksuctl(KSU_IOCTL_KPM, &raw mut cmd)?;

    if ret < 0 {
        println!("Failed to load kpm: {}", io::Error::from_raw_os_error(ret));
    }
    Ok(())
}

pub fn list() -> Result<()> {
    let mut buf = vec![0u8; 1024];

    let mut ret = -1;
    let mut cmd = KsuKpmCmd {
        control_code: KPM_LIST,
        arg1: buf.as_mut_ptr() as u64,
        arg2: buf.len() as u64,
        result_code: &raw mut ret as u64,
    };

    ksuctl(KSU_IOCTL_KPM, &raw mut cmd)?;

    if ret < 0 {
        println!(
            "Failed to get kpm list: {}",
            io::Error::from_raw_os_error(ret)
        );
        return Ok(());
    }

    println!("{}", buf.to_string_lossy());

    Ok(())
}

pub fn unload_module(name: String) -> Result<()> {
    let name = CString::new(name)?;

    let mut ret = -1;
    let mut cmd = KsuKpmCmd {
        control_code: KPM_UNLOAD,
        arg1: name.as_ptr() as u64,
        arg2: 0,
        result_code: &raw mut ret as u64,
    };

    ksuctl(KSU_IOCTL_KPM, &raw mut cmd)?;

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

    let mut ret = -1;
    let mut cmd = KsuKpmCmd {
        control_code: KPM_INFO,
        arg1: name.as_ptr() as u64,
        arg2: buf.as_mut_ptr() as u64,
        result_code: &raw mut ret as u64,
    };

    ksuctl(KSU_IOCTL_KPM, &raw mut cmd)?;

    if ret < 0 {
        println!(
            "Failed to get kpm info: {}",
            io::Error::from_raw_os_error(ret)
        );
        return Ok(());
    }
    println!("{}", buf.to_string_lossy());
    Ok(())
}

pub fn control(name: String, args: String) -> Result<i32> {
    let name = CString::new(name)?;
    let args = CString::new(args)?;

    let mut ret = -1;
    let mut cmd = KsuKpmCmd {
        control_code: KPM_CONTROL,
        arg1: name.as_ptr() as u64,
        arg2: args.as_ptr() as u64,
        result_code: &raw mut ret as u64,
    };

    ksuctl(KSU_IOCTL_KPM, &raw mut cmd)?;

    if ret < 0 {
        println!(
            "Failed to control kpm: {}",
            io::Error::from_raw_os_error(ret)
        );
    }

    Ok(ret)
}

pub fn num() -> Result<i32> {
    let mut ret = -1;
    let mut cmd = KsuKpmCmd {
        control_code: KPM_NUM,
        arg1: 0,
        arg2: 0,
        result_code: &raw mut ret as u64,
    };

    ksuctl(KSU_IOCTL_KPM, &raw mut cmd)?;

    if ret < 0 {
        println!(
            "Failed to get kpm num: {}",
            io::Error::from_raw_os_error(ret)
        );
        return Ok(ret);
    }
    println!("{ret}");
    Ok(ret)
}

pub fn version() -> Result<()> {
    let mut buf = vec![0u8; 1024];

    let mut ret = -1;
    let mut cmd = KsuKpmCmd {
        control_code: KPM_VERSION,
        arg1: buf.as_mut_ptr() as u64,
        arg2: buf.len() as u64,
        result_code: &raw mut ret as u64,
    };

    ksuctl(KSU_IOCTL_KPM, &raw mut cmd)?;

    if ret < 0 {
        println!(
            "Failed to get kpm version: {}",
            io::Error::from_raw_os_error(ret)
        );
        return Ok(());
    }

    print!("{}", buf.to_string_lossy());
    Ok(())
}

pub fn check_version() -> Result<String> {
    let mut buf = vec![0u8; 1024];

    let mut ret = -1;
    let mut cmd = KsuKpmCmd {
        control_code: KPM_VERSION,
        arg1: buf.as_mut_ptr() as u64,
        arg2: buf.len() as u64,
        result_code: &raw mut ret as u64,
    };

    ksuctl(KSU_IOCTL_KPM, &raw mut cmd)?;

    if ret < 0 {
        println!(
            "Failed to get kpm version: {}",
            io::Error::from_raw_os_error(ret)
        );
        return Ok(String::new());
    }
    let ver = buf.to_string_lossy();
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
