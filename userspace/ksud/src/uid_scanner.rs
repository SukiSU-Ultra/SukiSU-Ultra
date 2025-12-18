use anyhow::{Context, Result};
use log::{error, info, warn};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

const USER_DATA_BASE_PATH: &str = "/data/user_de";
const USER_UID_BASE_DIR: &str = "/data/adb/ksu/user_uid";
const UID_LIST_PATH: &str = "/data/adb/ksu/user_uid/uid_list";
const CONFIG_FILE_PATH: &str = "/data/adb/ksu/user_uid/uid_scanner.conf";
const REQUEST_FILE_PATH: &str = "/data/adb/ksu/user_uid/scan_request";
const STATE_FILE_PATH: &str = "/data/adb/ksu/user_uid/.state";

const MAX_USERS: usize = 8;
const DEFAULT_SCAN_INTERVAL_SECS: u64 = 300;

#[derive(Clone, Debug)]
struct ScannerConfig {
    multi_user_scan: bool,
    auto_scan: bool,
    scan_interval_secs: u64,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            multi_user_scan: false,
            auto_scan: true,
            scan_interval_secs: DEFAULT_SCAN_INTERVAL_SECS,
        }
    }
}

fn is_kernel_enabled() -> bool {
    let path = Path::new(STATE_FILE_PATH);
    let mut buf = [0u8; 1];

    match File::open(path).and_then(|mut f| f.read_exact(&mut buf)) {
        Ok(()) => {
            let enabled = buf[0] == b'1';
            if !enabled {
                info!("uid_scanner: kernel flag disabled (ksu_uid_scanner_enabled=0)");
            }
            enabled
        }
        Err(e) => {
            info!(
                "uid_scanner: kernel state not available ({}), treating as disabled",
                e
            );
            false
        }
    }
}

fn ensure_directory_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)
            .with_context(|| format!("failed to create directory {}", path.display()))?;
    }
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o777);
    fs::set_permissions(path, perms)?;
    Ok(())
}

fn load_config() -> Result<ScannerConfig> {
    let path = Path::new(CONFIG_FILE_PATH);
    if !path.exists() {
        let cfg = ScannerConfig::default();
        save_config(&cfg)?;
        info!("uid_scanner: config not found, created default config");
        return Ok(cfg);
    }

    let file = File::open(path).with_context(|| "failed to open uid_scanner config")?;
    let reader = BufReader::new(file);

    let mut cfg = ScannerConfig::default();

    for line in reader.lines() {
        let line = line.unwrap_or_default();
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut parts = line.splitn(2, '=');
        let key = parts.next().unwrap_or_default().trim();
        let value = parts.next().unwrap_or_default().trim();

        match key {
            "multi_user_scan" => {
                cfg.multi_user_scan = value == "1";
            }
            "auto_scan" => {
                cfg.auto_scan = value == "1";
            }
            "scan_interval" => {
                if let Ok(v) = value.parse::<u64>() {
                    cfg.scan_interval_secs = v.max(1);
                }
            }
            _ => (),
        }
    }

    info!(
        "uid_scanner: config loaded (multi_user_scan={}, auto_scan={}, interval={}s)",
        cfg.multi_user_scan, cfg.auto_scan, cfg.scan_interval_secs
    );

    Ok(cfg)
}

fn save_config(cfg: &ScannerConfig) -> Result<()> {
    let dir = Path::new(USER_UID_BASE_DIR);
    ensure_directory_exists(dir)?;

    let mut file =
        File::create(CONFIG_FILE_PATH).with_context(|| "failed to create uid_scanner config")?;

    writeln!(file, "# UID Scanner Configuration")?;
    writeln!(file, "multi_user_scan={}", if cfg.multi_user_scan { 1 } else { 0 })?;
    writeln!(file, "auto_scan={}", if cfg.auto_scan { 1 } else { 0 })?;
    writeln!(file, "scan_interval={}", cfg.scan_interval_secs)?;

    file.flush()?;
    file.sync_all().ok();

    info!("uid_scanner: config saved");
    Ok(())
}

pub fn set_multi_user_scan(enabled: bool) -> Result<()> {
    let mut cfg = load_config().unwrap_or_default();
    cfg.multi_user_scan = enabled;
    save_config(&cfg)?;
    info!("uid_scanner: multi_user_scan set to {}", enabled);
    Ok(())
}

pub fn get_multi_user_scan() -> bool {
    load_config().map(|c| c.multi_user_scan).unwrap_or(false)
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

fn get_user_directories(cfg: &ScannerConfig) -> Vec<PathBuf> {
    let mut user_dirs = Vec::new();

    if !cfg.multi_user_scan {
        user_dirs.push(PathBuf::from(format!("{USER_DATA_BASE_PATH}/0")));
        return user_dirs;
    }

    get_users_from_pm(&mut user_dirs);
    if user_dirs.is_empty() {
        get_users_from_directory_scan(&mut user_dirs);
    }

    user_dirs
}

fn perform_uid_scan(cfg: &ScannerConfig) -> Result<usize> {
    let dir = Path::new(USER_UID_BASE_DIR);
    ensure_directory_exists(dir)?;

    let mut entries = Vec::<(u32, String)>::new();

    let user_dirs = get_user_directories(cfg);
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

    let mut file =
        File::create(UID_LIST_PATH).with_context(|| "failed to open uid_list for write")?;

    for (uid, pkg) in &entries {
        writeln!(file, "{uid} {pkg}")?;
    }

    file.flush()?;
    file.sync_all().ok();

    info!(
        "uid_scanner: whitelist written {} entries to {}",
        entries.len(),
        UID_LIST_PATH
    );

    Ok(entries.len())
}

fn check_kernel_request() -> bool {
    let path = Path::new(REQUEST_FILE_PATH);
    if !path.exists() {
        return false;
    }

    let mut buf = String::new();
    if let Ok(mut file) = File::open(path) {
        if file.read_to_string(&mut buf).is_ok()
            && buf.starts_with("RESCAN")
        {
            // best-effort cleanup
            let _ = fs::remove_file(path);
            info!("uid_scanner: kernel rescan request detected");
            return true;
        }
    }

    false
}

fn perform_scan_update(cfg: &ScannerConfig) {
    match perform_uid_scan(cfg) {
        Ok(_) => info!("uid_scanner: scan completed successfully"),
        Err(e) => error!("uid_scanner: scan failed: {e}"),
    }
}

pub fn run_daemon() -> Result<()> {
    let dir = Path::new(USER_UID_BASE_DIR);
    ensure_directory_exists(dir)?;

    // Relax directory perms for kernel and other tools
    let mut perms = fs::metadata(dir)?.permissions();
    perms.set_mode(0o777);
    fs::set_permissions(dir, perms)?;

    info!("uid_scanner: daemon starting");

    let mut cfg = load_config().unwrap_or_default();

    let mut kernel_enabled = is_kernel_enabled();

    if kernel_enabled {
        if cfg.auto_scan {
            perform_scan_update(&cfg);
        } else {
            info!("uid_scanner: auto_scan disabled, waiting for manual or kernel requests");
        }
    } else {
        info!("uid_scanner: kernel disabled, initial scan skipped");
    }

    loop {
        // Reload config & kernel flag periodically to pick up runtime changes
        if let Ok(new_cfg) = load_config() {
            cfg = new_cfg;
        }
        kernel_enabled = is_kernel_enabled();

        if kernel_enabled && (cfg.auto_scan || check_kernel_request()) {
            perform_scan_update(&cfg);
        }

        thread::sleep(Duration::from_secs(cfg.scan_interval_secs));
    }
}

/// One-shot scan, intended for manual invocation from CLI/manager.
pub fn scan_once() -> Result<()> {
    let cfg = load_config().unwrap_or_default();
    perform_scan_update(&cfg);
    Ok(())
}
