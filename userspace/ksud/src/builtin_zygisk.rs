#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]

use crate::defs::{BUILTIN_ZYGISK_DIR, BUILTIN_ZYGISK_FLAG};
use crate::restorecon::setsyscon;
use crate::utils::{ensure_dir_exists, ensure_file_exists};
use anyhow::{Context, Result};
use log::{error, info, warn};
use std::fs::{self, File, Permissions};
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, lchown};
use std::path::Path;
use std::process::Command;

const BUILTIN_ZYGISK_SEPOLICY: &str = r"
type zygisk_file file_type
typeattribute zygisk_file mlstrustedobject
allow domain zygisk_file dir {search getattr}
allow domain zygisk_file sock_file {read write getattr open}
allow system_server zygisk_file sock_file {read write}
allow system_server zygote unix_stream_socket connectto
allow zygote magisk lnk_file read
allow zygote unlabeled file {read open}
allow zygote zygote capability sys_chroot
allow zygote su dir search
allow zygote su {lnk_file file} read
allow domain adb_data_file dir search
allow zygote zygote process execmem
allow system_server system_server process execmem
allow zygote tmpfs file *
allow zygote appdomain_tmpfs file *
allow domain tmpfs file {open getattr map read execute}
allow zygote magisk memfd_file {getattr read write map execute}
allow zygote su memfd_file {getattr read write map execute}
allow domain magisk memfd_file {getattr read write map execute}
allow domain su memfd_file {getattr read write map execute}
allow zygote proc file *
allow zygote nsfs file *
allow system_server tmpfs file {getattr read write map execute}
allow system_server magisk memfd_file {getattr read write map execute}
allow system_server su memfd_file {getattr read write map execute}
allow system_server system_server_tmpfs file {getattr read write map execute}
";

pub fn is_enabled() -> bool {
    Path::new(BUILTIN_ZYGISK_FLAG).exists()
}

pub fn enable() -> Result<()> {
    ensure_file_exists(BUILTIN_ZYGISK_FLAG)?;
    info!("Built-in Zygisk has been enabled");
    Ok(())
}

pub fn disable() -> Result<()> {
    let flag = Path::new(BUILTIN_ZYGISK_FLAG);
    if flag.exists() {
        fs::remove_file(flag).with_context(|| "Failed to remove builtin zygisk flag")?;
    }
    info!("Built-in Zygisk has been disabled");
    Ok(())
}

pub fn is_monitor_running() -> bool {
    crate::module::is_process_running_matching(|comm| {
        comm == "zygisk-ptrace" || comm == "zygisk-ptrace64" || comm == "zygisk-ptrace32"
    })
}

pub fn is_daemon_running() -> bool {
    crate::module::is_process_running_matching(|comm| {
        comm == "zygiskd" || comm == "zygiskd64" || comm == "zygiskd32"
    })
}

pub fn apply_sepolicy() -> Result<()> {
    if !is_enabled() {
        return Ok(());
    }
    info!("Applying built-in Zygisk SELinux rules");
    if let Err(e) = crate::sepolicy::live_patch(BUILTIN_ZYGISK_SEPOLICY.trim()) {
        warn!("Failed to live patch built-in Zygisk sepolicy: {e}");
    }
    Ok(())
}

fn set_sys_perm<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    ensure_dir_exists(path)?;
    fs::set_permissions(path, Permissions::from_mode(0o555))?;
    let _ = setsyscon(path);
    let _ = lchown(path, Some(1000), Some(1000));
    Ok(())
}

fn install_lib<P: AsRef<Path>>(dest: P, data: &[u8]) -> Result<()> {
    let dest = dest.as_ref();
    if let Some(parent) = dest.parent() {
        set_sys_perm(parent)?;
    }
    let tmp_dest = dest.with_extension("new");
    {
        let mut file = File::create(&tmp_dest)?;
        file.write_all(data)?;
        file.flush()?;
    }
    fs::set_permissions(&tmp_dest, Permissions::from_mode(0o644))?;
    let _ = setsyscon(&tmp_dest);
    let _ = lchown(&tmp_dest, Some(1000), Some(1000));
    fs::rename(&tmp_dest, dest)?;
    Ok(())
}

fn ensure_executable<P: AsRef<Path>>(dest: P, data: &[u8]) -> Result<()> {
    let dest = dest.as_ref();
    if let Some(parent) = dest.parent() {
        ensure_dir_exists(parent)?;
    }
    {
        let mut file = File::create(dest)?;
        file.write_all(data)?;
        file.flush()?;
    }
    fs::set_permissions(dest, Permissions::from_mode(0o755))?;
    Ok(())
}

pub fn bootstrap() -> Result<()> {
    if !is_enabled() {
        return Ok(());
    }

    info!("Bootstrapping built-in Zygisk");
    let work_dir = Path::new(BUILTIN_ZYGISK_DIR);
    set_sys_perm(work_dir)?;
    set_sys_perm(work_dir.join("lib"))?;
    set_sys_perm(work_dir.join("lib64"))?;
    ensure_dir_exists(work_dir.join("bin"))?;

    // Create a virtual module.prop in work_dir for tracer/daemon metadata
    let module_prop_path = work_dir.join("module.prop");
    let module_prop_content = "id=zygisksu\nname=Built-in Zygisk\nversion=v2.5\nversionCode=100\nauthor=SukiSU-Ultra\ndescription=Built-in Zygisk powered by BuiltZygisk\n";
    let _ = fs::write(module_prop_path, module_prop_content);

    // Extract assets if present in binary assets
    let is_64bit = cfg!(target_pointer_width = "64");
    if let Ok(data) = crate::assets::get_asset_data("zygisk-ptrace") {
        let tracer_dst = if is_64bit {
            work_dir.join("bin/zygisk-ptrace64")
        } else {
            work_dir.join("bin/zygisk-ptrace32")
        };
        let _ = ensure_executable(&tracer_dst, &data);
    }
    if let Ok(data) = crate::assets::get_asset_data("zygiskd") {
        let daemon_dst = if is_64bit {
            work_dir.join("bin/zygiskd64")
        } else {
            work_dir.join("bin/zygiskd32")
        };
        let _ = ensure_executable(&daemon_dst, &data);
    }
    if let Ok(data) = crate::assets::get_asset_data("libzygisk.so") {
        let lib_dst = if is_64bit {
            work_dir.join("lib64/libzygisk.so")
        } else {
            work_dir.join("lib/libzygisk.so")
        };
        let _ = install_lib(&lib_dst, &data);
    }
    if let Ok(data) = crate::assets::get_asset_data("libzygisk64.so") {
        let lib_dst = work_dir.join("lib64/libzygisk.so");
        let _ = install_lib(&lib_dst, &data);
    }
    if let Ok(data) = crate::assets::get_asset_data("libzygisk32.so") {
        let lib_dst = work_dir.join("lib/libzygisk.so");
        let _ = install_lib(&lib_dst, &data);
    }

    // Launch monitor in background if tracer binary exists
    let tracer64 = work_dir.join("bin/zygisk-ptrace64");
    let tracer32 = work_dir.join("bin/zygisk-ptrace32");
    let tracer = if tracer64.exists() {
        Some(tracer64)
    } else if tracer32.exists() {
        Some(tracer32)
    } else {
        None
    };

    if let Some(tracer_bin) = tracer {
        info!("Starting BuiltZygisk monitor: {}", tracer_bin.display());
        let mut cmd = Command::new(&tracer_bin);
        cmd.arg("monitor");
        #[cfg(target_os = "android")]
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        if let Err(e) = cmd.spawn() {
            error!("Failed to spawn BuiltZygisk monitor: {e}");
        }
    } else {
        warn!(
            "BuiltZygisk tracer binary not found in {}",
            work_dir.display()
        );
    }

    Ok(())
}

pub fn rearm() -> Result<()> {
    if !is_enabled() {
        return Ok(());
    }

    // Only rearm if zygote is already active
    let has_zygote = crate::module::is_process_running_matching(|comm| {
        comm == "zygote" || comm == "zygote64" || comm == "app_process" || comm == "app_process64"
    });

    if !has_zygote {
        return Ok(());
    }

    let work_dir = Path::new(BUILTIN_ZYGISK_DIR);
    let tracer64 = work_dir.join("bin/zygisk-ptrace64");
    let tracer32 = work_dir.join("bin/zygisk-ptrace32");
    let tracer = if tracer64.exists() {
        tracer64
    } else if tracer32.exists() {
        tracer32
    } else {
        return Ok(());
    };

    info!("Rearming BuiltZygisk via ctl rearm");
    let _ = Command::new(tracer).args(["ctl", "rearm"]).status();
    Ok(())
}

pub fn shutdown() -> Result<()> {
    if !is_enabled() {
        return Ok(());
    }

    let work_dir = Path::new(BUILTIN_ZYGISK_DIR);
    let tracer64 = work_dir.join("bin/zygisk-ptrace64");
    let tracer32 = work_dir.join("bin/zygisk-ptrace32");
    let tracer = if tracer64.exists() {
        tracer64
    } else if tracer32.exists() {
        tracer32
    } else {
        return Ok(());
    };

    info!("Stopping BuiltZygisk via ctl exit");
    let _ = Command::new(tracer).args(["ctl", "exit"]).status();
    Ok(())
}
