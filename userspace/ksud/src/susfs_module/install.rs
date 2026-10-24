//! Filesystem operations: actually write the generated module directory.

use anyhow::Context;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

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
    install_at(Path::new(MODULE_PATH), config)
}

fn install_at(module_path: &Path, config: &ModuleConfig) -> anyhow::Result<()> {
    // Create module directory, retaining mkdir -p's umask and existing-directory semantics.
    create_module_dir(module_path, false).context("Failed to create module directory")?;

    // Write module.prop
    let prop_content = module_prop();
    write_module_file(&module_path.join("module.prop"), &prop_content)
        .context("Failed to write module.prop")?;

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
        write_module_script(&module_path.join(name), content)
            .with_context(|| format!("Failed to write {name}"))?;
    }

    Ok(())
}

fn create_module_dir(path: &Path, intermediate: bool) -> io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {
            if intermediate {
                // mkdir -p restores owner write/search bits only on newly created parents.
                let mut permissions = fs::metadata(path)?.permissions();
                let mode = permissions.mode();
                if mode & 0o300 != 0o300 {
                    permissions.set_mode(mode | 0o300);
                    fs::set_permissions(path, permissions)?;
                }
            }
            Ok(())
        }
        Err(_) if path.is_dir() => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .ok_or(error)?;
            create_module_dir(parent, true)?;
            create_module_dir(path, intermediate)
        }
        Err(error) => Err(error),
    }
}

fn write_module_file(path: &Path, content: &str) -> io::Result<()> {
    // The quoted heredoc appended one newline to the literal generated content.
    fs::write(path, format!("{content}\n"))
}

fn write_module_script(path: &Path, content: &str) -> io::Result<()> {
    // Preserve the shell's final chmod status even when the preceding write fails.
    let _ = write_module_file(path, content);
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
}

/// Remove the module directory wholesale.
pub fn remove_module() -> anyhow::Result<()> {
    remove_module_at(Path::new(MODULE_PATH)).context("Failed to remove module")
}

fn remove_module_at(path: &Path) -> io::Result<()> {
    let result = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(error) => Err(error),
    };
    match result {
        // Like rm -rf, tolerate missing entries, but never follow a directory symlink.
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

/// `true` iff `module.prop` is a regular file (following links) under [`MODULE_PATH`].
pub fn is_module_installed() -> bool {
    is_module_installed_at(Path::new(MODULE_PATH))
}

fn is_module_installed_at(module_path: &Path) -> bool {
    module_path.join("module.prop").is_file()
}
