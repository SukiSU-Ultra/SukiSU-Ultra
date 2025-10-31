#[cfg(target_arch = "aarch64")]
use crate::kpm;
use crate::{
    assets, defs,
    defs::{KSU_MOUNT_SOURCE, NO_MOUNT_PATH, NO_TMPFS_PATH},
    ksucalls,
    module::{handle_updated_modules, prune_modules},
    restorecon, uid_scanner, utils,
    utils::find_tmp_path,
};
use anyhow::{Context, Result};
use log::{info, warn};
use rustix::fs::{MountFlags, mount};
use std::path::Path;

#[cfg(target_os = "android")]
pub fn mount_modules_systemlessly() -> Result<()> {
    crate::magic_mount::magic_mount(&find_tmp_path())
}

#[cfg(not(target_os = "android"))]
pub fn mount_modules_systemlessly() -> Result<()> {
    Ok(())
}

pub fn on_post_data_fs() -> Result<()> {
    ksucalls::report_post_fs_data();

    utils::umask(0);

    #[cfg(unix)]
    let _ = catch_bootlog("logcat", vec!["logcat"]);
    #[cfg(unix)]
    let _ = catch_bootlog("dmesg", vec!["dmesg", "-w"]);

    if utils::has_magisk() {
        warn!("Magisk detected, skip post-fs-data!");
        return Ok(());
    }

    let safe_mode = utils::is_safe_mode();

    if safe_mode {
        warn!("safe mode, skip common post-fs-data.d scripts");
    } else {
        // Then exec common post-fs-data scripts
        if let Err(e) = crate::module::exec_common_scripts("post-fs-data.d", true) {
            warn!("exec common post-fs-data scripts failed: {e}");
        }
    }

    assets::ensure_binaries(true).with_context(|| "Failed to extract bin assets")?;

    // Start UID scanner daemon with highest priority
    uid_scanner::start_uid_scanner_daemon()?;

    // tell kernel that we've mount the module, so that it can do some optimization
    ksucalls::report_module_mounted();

    // if we are in safe mode, we should disable all modules
    if safe_mode {
        warn!("safe mode, skip post-fs-data scripts and disable all modules!");
        if let Err(e) = crate::module::disable_all_modules() {
            warn!("disable all modules failed: {e}");
        }
        return Ok(());
    }

    if let Err(e) = prune_modules() {
        warn!("prune modules failed: {e}");
    }

    if let Err(e) = handle_updated_modules() {
        warn!("handle updated modules failed: {e}");
    }

    if let Err(e) = restorecon::restorecon() {
        warn!("restorecon failed: {e}");
    }

    // load sepolicy.rule
    if crate::module::load_sepolicy_rule().is_err() {
        warn!("load sepolicy.rule failed");
    }

    if let Err(e) = crate::profile::apply_sepolies() {
        warn!("apply root profile sepolicy failed: {e}");
    }

    #[cfg(target_arch = "aarch64")]
    if let Err(e) = kpm::start_kpm_watcher() {
        warn!("KPM: Failed to start KPM watcher: {e}");
    }

    #[cfg(target_arch = "aarch64")]
    if let Err(e) = kpm::load_kpm_modules() {
        warn!("KPM: Failed to load KPM modules: {e}");
    }

    let tmpfs_path = find_tmp_path();
    // for compatibility
    let no_mount = Path::new(NO_TMPFS_PATH).exists() || Path::new(NO_MOUNT_PATH).exists();

    // mount temp dir
    if !no_mount {
        if let Err(e) = mount(
            KSU_MOUNT_SOURCE,
            &tmpfs_path,
            "tmpfs",
            MountFlags::empty(),
            "",
        ) {
            warn!("do temp dir mount failed: {e}");
        }
    } else {
        info!("no tmpfs requested");
    }

    // exec modules post-fs-data scripts
    // TODO: Add timeout
    if let Err(e) = crate::module::exec_stage_script("post-fs-data", true) {
        warn!("exec post-fs-data scripts failed: {e}");
    }

    // load system.prop
    if let Err(e) = crate::module::load_system_prop() {
        warn!("load system.prop failed: {e}");
    }

    // mount module systemlessly by magic mount
    #[cfg(target_os = "android")]
    if !no_mount {
        if let Err(e) = crate::magic_mount::magic_mount(&tmpfs_path) {
            warn!("do systemless mount failed: {e}");
        }
    } else {
        info!("no mount requested");
    }

    run_stage("post-mount", true);

    Ok(())
}

fn run_stage(stage: &str, block: bool) {
    utils::umask(0);

    if utils::has_magisk() {
        warn!("Magisk detected, skip {stage}");
        return;
    }

    if crate::utils::is_safe_mode() {
        warn!("safe mode, skip {stage} scripts");
        return;
    }

    if let Err(e) = crate::module::exec_common_scripts(&format!("{stage}.d"), block) {
        warn!("Failed to exec common {stage} scripts: {e}");
    }
    if let Err(e) = crate::module::exec_stage_script(stage, block) {
        warn!("Failed to exec {stage} scripts: {e}");
    }
}

pub fn on_services() -> Result<()> {
    info!("on_services triggered!");
    run_stage("service", false);

    Ok(())
}

pub fn on_boot_completed() -> Result<()> {
    ksucalls::report_boot_complete();
    info!("on_boot_completed triggered!");

    run_stage("boot-completed", false);

    Ok(())
}

#[cfg(unix)]
fn catch_bootlog(logname: &str, command: Vec<&str>) -> Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

    let logdir = Path::new(defs::LOG_DIR);
    utils::ensure_dir_exists(logdir)?;
    let bootlog = logdir.join(format!("{logname}.log"));
    let oldbootlog = logdir.join(format!("{logname}.old.log"));

    if bootlog.exists() {
        std::fs::rename(&bootlog, oldbootlog)?;
    }

    let bootlog = std::fs::File::create(bootlog)?;

    let mut args = vec!["-s", "9", "30s"];
    args.extend_from_slice(&command);
    // timeout -s 9 30s logcat > boot.log
    let result = unsafe {
        std::process::Command::new("timeout")
            .process_group(0)
            .pre_exec(|| {
                utils::switch_cgroups();
                Ok(())
            })
            .args(args)
            .stdout(Stdio::from(bootlog))
            .spawn()
    };

    if let Err(e) = result {
        warn!("Failed to start logcat: {e:#}");
    }

    Ok(())
}
