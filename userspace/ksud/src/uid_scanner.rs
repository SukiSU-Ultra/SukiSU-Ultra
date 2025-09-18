use anyhow::{Context, Result};
use log::{info, warn};
use std::fs;
use std::path::Path;
use std::process::Command;

const SCANNER_PATH: &str = "/data/adb/uid_scanner";
const RC_SCRIPT_PATH: &str = "/data/adb/ksu_uid_scanner.rc";

/// Setup UID scanner daemon as a system service via rc script
pub fn setup_uid_scanner_service() -> Result<()> {
    // Check if uid scanner binary exists
    if !Path::new(SCANNER_PATH).exists() {
        warn!("uid scanner binary not found at {}", SCANNER_PATH);
        return Ok(());
    }

    info!("setting up uid scanner service");

    // Create rc script content
    let rc_content = format!(r#"service ksu_uid_scanner /data/adb/uid_scanner start
    class core
    user root
    group root
    priority -20
    ioprio rt 4
    writepid /dev/cpuset/foreground/tasks
    seclabel u:r:su:s0
    oneshot
    disabled

service ksu_uid_scanner_daemon /data/adb/uid_scanner start
    class main
    user root
    group root
    priority -20
    ioprio rt 4
    writepid /dev/cpuset/foreground/tasks
    seclabel u:r:su:s0
    restart
    disabled
"#);

    // Write rc script
    fs::write(RC_SCRIPT_PATH, rc_content)
        .with_context(|| "Failed to write rc script")?;

    // Set proper permissions for rc script
    if let Err(e) = fs::set_permissions(RC_SCRIPT_PATH, std::fs::Permissions::from_mode(0o644)) {
        warn!("failed to set rc script permissions: {}", e);
    }

    // Import rc script into init
    import_rc_script(RC_SCRIPT_PATH)?;

    // Start the daemon service
    start_service("ksu_uid_scanner_daemon")?;

    info!("uid scanner service setup completed");
    Ok(())
}

/// Import rc script into Android init system
fn import_rc_script(script_path: &str) -> Result<()> {
    info!("importing rc script: {}", script_path);

    let output = Command::new("setprop")
        .args(&["ctl.import", script_path])
        .output()
        .with_context(|| "Failed to execute setprop")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("setprop failed: {}", stderr));
    }

    // Wait a moment for import to complete
    std::thread::sleep(std::time::Duration::from_millis(500));

    info!("rc script imported successfully");
    Ok(())
}

/// Start a system service
fn start_service(service_name: &str) -> Result<()> {
    info!("starting service: {}", service_name);

    let output = Command::new("setprop")
        .args(&["ctl.start", service_name])
        .output()
        .with_context(|| "Failed to execute setprop")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("start service failed: {}", stderr));
    }

    info!("service {} started successfully", service_name);
    Ok(())
}

/// Stop UID scanner service
pub fn stop_uid_scanner_service() -> Result<()> {
    info!("stopping uid scanner service");

    let output = Command::new("setprop")
        .args(&["ctl.stop", "ksu_uid_scanner_daemon"])
        .output()
        .with_context(|| "Failed to execute setprop")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("stop service failed: {}", stderr);
    } else {
        info!("uid scanner service stopped");
    }

    Ok(())
}

/// Start UID scanner service manually
pub fn start_uid_scanner_service() -> Result<()> {
    start_service("ksu_uid_scanner_daemon")
}

/// Restart UID scanner service
pub fn restart_uid_scanner_service() -> Result<()> {
    info!("restarting uid scanner service");
    
    // Stop first, ignore errors
    let _ = stop_uid_scanner_service();
    
    // Wait a moment
    std::thread::sleep(std::time::Duration::from_millis(1000));
    
    // Start again
    start_uid_scanner_service()
}

/// Get UID scanner service status
pub fn get_uid_scanner_status() -> Result<()> {
    info!("checking uid scanner service status");
    
    // Check if RC script exists
    let rc_exists = Path::new(RC_SCRIPT_PATH).exists();
    println!("RC script exists: {}", rc_exists);
    
    // Check if binary exists
    let binary_exists = Path::new(SCANNER_PATH).exists();
    println!("UID scanner binary exists: {}", binary_exists);
    
    // Try to get service status via getprop
    let output = Command::new("getprop")
        .args(&["init.svc.ksu_uid_scanner_daemon"])
        .output();
        
    match output {
        Ok(output) => {
            let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("Service status: {}", if status.is_empty() { "unknown" } else { &status });
        }
        Err(e) => {
            warn!("failed to get service status: {}", e);
            println!("Service status: unknown");
        }
    }
    
    // Try to find process
    let output = Command::new("pgrep")
        .args(&["-f", "uid_scanner"])
        .output();
        
    match output {
        Ok(output) => {
            let pids = String::from_utf8_lossy(&output.stdout).trim();
            if pids.is_empty() {
                println!("Process: not running");
            } else {
                println!("Process PIDs: {}", pids);
            }
        }
        Err(_) => {
            println!("Process: unknown (pgrep not available)");
        }
    }
    
    Ok(())
}

/// Remove UID scanner service (remove RC script and stop service)
pub fn remove_uid_scanner_service() -> Result<()> {
    info!("removing uid scanner service");
    
    // Stop service first
    let _ = stop_uid_scanner_service();
    
    // Remove RC script
    if Path::new(RC_SCRIPT_PATH).exists() {
        fs::remove_file(RC_SCRIPT_PATH)
            .with_context(|| "Failed to remove RC script")?;
        info!("RC script removed");
    }
    
    println!("UID scanner service removed successfully");
    Ok(())
}
