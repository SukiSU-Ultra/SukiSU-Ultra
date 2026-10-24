//! Filesystem operations: actually write the generated module directory.

use std::process::Command;

use crate::susfs_config::{ModuleConfig, load_module_config};
use crate::susfs_module::consts::MODULE_PATH;
use crate::susfs_module::scripts::generate;
use crate::susfs_module::scripts::prop::module_prop;

/// Read the persisted config and re-install the module.
///
/// Public entry point used by `cli.rs`.
pub fn install_module() -> anyhow::Result<()> {
    let config = load_module_config()?;
    install_with_config(&config)
}

fn install_with_config(config: &ModuleConfig) -> anyhow::Result<()> {
    let module_path = MODULE_PATH;

    // Create module directory
    let out = Command::new("sh")
        .args(["-c", &format!("mkdir -p {module_path}")])
        .output()?;
    if !out.status.success() {
        anyhow::bail!("Failed to create module directory");
    }

    // Write module.prop
    let prop_content = module_prop();
    let out = Command::new("sh")
        .args([
            "-c",
            &format!("cat > {module_path}/module.prop << 'KSUEOF'\n{prop_content}\nKSUEOF"),
        ])
        .output()?;
    if !out.status.success() {
        anyhow::bail!("Failed to write module.prop");
    }

    let scripts = [
        (
            "service.sh",
            generate::service(
                &config.sus_paths,
                &config.sus_loop_paths,
                &config.sus_maps,
                &config.kstat_configs,
                &config.add_kstat_paths,
                &config.cmdline_or_bootconfig_path,
                &config.uname_value,
                &config.build_time_value,
                config.execute_in_post_fs_data,
                config.enable_log,
                config.enable_hide_bl,
                config.enable_cleanup_residue,
            ),
        ),
        (
            "post-fs-data.sh",
            generate::post_fs_data(
                &config.uname_value,
                &config.build_time_value,
                config.execute_in_post_fs_data,
                config.enable_avc_log_spoofing,
            ),
        ),
        ("post-mount.sh", generate::post_mount()),
        (
            "boot-completed.sh",
            generate::boot_completed(
                config.hide_sus_mounts_for_all_procs,
                &config.sus_paths,
                &config.sus_loop_paths,
                &config.sus_maps,
            ),
        ),
    ];

    for (name, content) in &scripts {
        let script_path = format!("{module_path}/{name}");
        let out = Command::new("sh")
            .args([
                "-c",
                &format!(
                    "cat > '{script_path}' << 'KSUEOF'\n{content}\nKSUEOF\nchmod 755 '{script_path}'"
                ),
            ])
            .output()?;
        if !out.status.success() {
            anyhow::bail!(
                "Failed to write {}: {}",
                name,
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    Ok(())
}

/// Remove the module directory wholesale.
pub fn remove_module() -> anyhow::Result<()> {
    let out = Command::new("sh")
        .args(["-c", &format!("rm -rf {MODULE_PATH}")])
        .output()?;
    if !out.status.success() {
        anyhow::bail!(
            "Failed to remove module: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// `true` iff `module.prop` already exists under [`MODULE_PATH`].
pub fn is_module_installed() -> bool {
    Command::new("sh")
        .args([
            "-c",
            &format!("test -f {MODULE_PATH}/module.prop && echo yes || echo no"),
        ])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("yes"))
}
