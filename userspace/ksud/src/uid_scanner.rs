use std::{
    fs,
    io::Write,
    os::unix::{
        fs::{PermissionsExt, symlink},
        process::CommandExt,
    },
    path::Path,
    process::{Command, Stdio},
};

use anyhow::Result;
use log::{info, warn};

pub fn start_uid_scanner_daemon() -> Result<()> {
    const SCANNER_PATH: &str = "/data/adb/uid_scanner";
    const LINK_DIR: &str = "/data/adb/ksu/bin";
    const LINK_PATH: &str = "/data/adb/ksu/bin/uid_scanner";
    const SERVICE_DIR: &str = "/data/adb/service.d";
    const SERVICE_PATH: &str = "/data/adb/service.d/uid_scanner.sh";

    if !Path::new(SCANNER_PATH).exists() {
        warn!("uid scanner binary not found at {}", SCANNER_PATH);
        return Ok(());
    }

    if let Err(e) = fs::set_permissions(SCANNER_PATH, fs::Permissions::from_mode(0o755)) {
        warn!("failed to set permissions for {}: {}", SCANNER_PATH, e);
    }

    #[cfg(unix)]
    {
        if let Err(e) = fs::create_dir_all(LINK_DIR) {
            warn!("failed to create {}: {}", LINK_DIR, e);
        } else if !Path::new(LINK_PATH).exists() {
            match symlink(SCANNER_PATH, LINK_PATH) {
                Ok(_) => info!("created symlink {} -> {}", SCANNER_PATH, LINK_PATH),
                Err(e) => warn!("failed to create symlink: {}", e),
            }
        }
    }

    if let Err(e) = fs::create_dir_all(SERVICE_DIR) {
        warn!("failed to create {}: {}", SERVICE_DIR, e);
    } else if !Path::new(SERVICE_PATH).exists() {
        let content = r#"#!/system/bin/sh
# KSU uid_scanner auto-restart script
until [ -d "/sdcard/Android" ]; do sleep 1; done
sleep 10
/data/adb/uid_scanner restart
"#;
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(SERVICE_PATH)
            .and_then(|mut f| {
                f.write_all(content.as_bytes())?;
                f.sync_all()?;
                fs::set_permissions(SERVICE_PATH, fs::Permissions::from_mode(0o755))
            }) {
            Ok(_) => info!("created service script {}", SERVICE_PATH),
            Err(e) => warn!("failed to write {}: {}", SERVICE_PATH, e),
        }
    }

    info!("starting uid scanner daemon with highest priority");
    let mut cmd = Command::new(SCANNER_PATH);
    cmd.arg("start")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir("/");

    unsafe {
        cmd.pre_exec(|| {
            libc::nice(-20);
            libc::setsid();
            Ok(())
        });
    }

    match cmd.spawn() {
        Ok(child) => {
            info!("uid scanner daemon started with pid: {}", child.id());
            std::mem::drop(child);
        }
        Err(e) => warn!("failed to start uid scanner daemon: {}", e),
    }

    Ok(())
}
