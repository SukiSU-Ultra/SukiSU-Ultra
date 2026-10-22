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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn test_config() -> ModuleConfig {
        ModuleConfig {
            uname_value: "test-uname".into(),
            build_time_value: "test-build".into(),
            execute_in_post_fs_data: false,
            sus_paths: vec!["/data/local/test path".into()],
            sus_loop_paths: Vec::new(),
            sus_maps: Vec::new(),
            enable_log: true,
            kstat_configs: Vec::new(),
            add_kstat_paths: Vec::new(),
            hide_sus_mounts_for_all_procs: true,
            enable_hide_bl: true,
            enable_cleanup_residue: false,
            enable_avc_log_spoofing: false,
            cmdline_or_bootconfig_path: String::new(),
        }
    }

    #[test]
    fn should_install_exact_generated_contents_and_script_modes() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let module_path = dir.path().join("modules/susfs");
        let config = test_config();
        install_at(&module_path, &config)?;
        let expected = [
            ("module.prop", module_prop()),
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
        for (name, content) in &expected {
            let path = module_path.join(name);
            assert_eq!(fs::read(&path)?, format!("{content}\n").as_bytes());
            if name.ends_with(".sh") {
                assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o755);
            }
        }
        assert!(is_module_installed_at(&module_path));
        fs::write(module_path.join("service.sh"), b"stale trailing content")?;
        install_at(&module_path, &config)?;
        assert_eq!(
            fs::read(module_path.join("service.sh"))?,
            format!("{}\n", expected[1].1).as_bytes()
        );
        Ok(())
    }

    #[test]
    fn should_preserve_heredoc_newlines_and_literal_characters() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("module.prop");
        for content in ["", "text", "text\n", "text\n\n", "$HOME `id` \\ ' \"\n"] {
            write_module_file(&path, content)?;
            assert_eq!(fs::read(&path)?, format!("{content}\n").as_bytes());
        }
        Ok(())
    }

    #[test]
    fn should_inherit_umask_when_creating_module_files_and_directories() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let control_dir = dir.path().join("control-dir");
        let control_file = dir.path().join("control-file");
        fs::create_dir(&control_dir)?;
        fs::write(&control_file, b"control")?;
        let dir_mode = fs::metadata(&control_dir)?.permissions().mode() & 0o777;
        let file_mode = fs::metadata(&control_file)?.permissions().mode() & 0o777;

        let parent = dir.path().join("modules");
        let module_path = parent.join("susfs");
        install_at(&module_path, &test_config())?;
        assert_eq!(
            fs::metadata(&parent)?.permissions().mode() & 0o777,
            dir_mode | 0o300
        );
        assert_eq!(
            fs::metadata(&module_path)?.permissions().mode() & 0o777,
            dir_mode
        );
        assert_eq!(
            fs::metadata(module_path.join("module.prop"))?
                .permissions()
                .mode()
                & 0o777,
            file_mode
        );
        Ok(())
    }

    #[test]
    fn should_preserve_links_and_existing_directory_and_prop_modes() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let module_path = dir.path().join("module");
        let alias = dir.path().join("alias");
        fs::create_dir(&module_path)?;
        fs::set_permissions(&module_path, fs::Permissions::from_mode(0o750))?;
        symlink(&module_path, &alias)?;
        let prop_target = dir.path().join("prop-target");
        fs::write(&prop_target, b"old")?;
        fs::set_permissions(&prop_target, fs::Permissions::from_mode(0o640))?;
        symlink(&prop_target, module_path.join("module.prop"))?;
        let script_target = dir.path().join("script-target");
        symlink(&script_target, module_path.join("service.sh"))?;
        install_at(&alias, &test_config())?;
        assert_eq!(
            fs::read(&prop_target)?,
            format!("{}\n", module_prop()).as_bytes()
        );
        assert_eq!(
            fs::metadata(&prop_target)?.permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(
            fs::metadata(&module_path)?.permissions().mode() & 0o777,
            0o750
        );
        assert!(fs::symlink_metadata(module_path.join("module.prop"))?.is_symlink());
        assert!(fs::symlink_metadata(module_path.join("service.sh"))?.is_symlink());
        assert_eq!(
            fs::metadata(&script_target)?.permissions().mode() & 0o777,
            0o755
        );
        assert!(fs::symlink_metadata(&alias)?.is_symlink());
        Ok(())
    }

    #[test]
    fn should_stop_in_original_order_when_an_operation_fails() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let module_path = dir.path().join("module");
        let config = test_config();
        fs::write(&module_path, b"not a directory")?;
        assert!(install_at(&module_path, &config).is_err());
        assert_eq!(fs::read(&module_path)?, b"not a directory");
        fs::remove_file(&module_path)?;
        fs::create_dir_all(module_path.join("module.prop"))?;
        assert!(install_at(&module_path, &config).is_err());
        assert!(!module_path.join("service.sh").exists());
        fs::remove_dir(module_path.join("module.prop"))?;
        symlink(
            dir.path().join("missing/target"),
            module_path.join("post-fs-data.sh"),
        )?;
        assert!(install_at(&module_path, &config).is_err());
        assert!(module_path.join("module.prop").is_file());
        assert!(module_path.join("service.sh").is_file());
        assert!(!module_path.join("post-mount.sh").exists());
        assert!(!module_path.join("boot-completed.sh").exists());
        Ok(())
    }

    #[test]
    fn should_return_chmod_status_even_when_script_write_fails() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("service.sh");
        fs::create_dir(&path)?;
        assert!(write_module_file(&path, "script").is_err());
        write_module_script(&path, "script")?;
        assert!(path.is_dir());
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o755);
        Ok(())
    }

    #[test]
    fn should_remove_files_trees_and_links_without_following_links() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("module");
        remove_module_at(&path)?;
        fs::write(&path, b"file")?;
        remove_module_at(&path)?;
        assert!(!path.exists());
        let target = dir.path().join("target");
        fs::create_dir(&target)?;
        fs::write(target.join("keep"), b"keep")?;
        symlink(&target, &path)?;
        remove_module_at(&path)?;
        assert!(target.join("keep").is_file());
        assert!(fs::symlink_metadata(&path).is_err());
        symlink(target.join("missing"), &path)?;
        remove_module_at(&path)?;
        assert!(fs::symlink_metadata(&path).is_err());
        symlink(target.join("keep"), &path)?;
        remove_module_at(&path)?;
        assert_eq!(fs::read(target.join("keep"))?, b"keep");
        fs::create_dir_all(path.join("nested"))?;
        fs::write(path.join("nested/file"), b"file")?;
        symlink(&target, path.join("nested/link"))?;
        remove_module_at(&path)?;
        assert!(!path.exists());
        assert_eq!(fs::read(target.join("keep"))?, b"keep");
        Ok(())
    }

    #[test]
    fn should_match_test_f_for_files_directories_and_links() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("module.prop");
        assert!(!is_module_installed_at(dir.path()));
        fs::create_dir(&path)?;
        assert!(!is_module_installed_at(dir.path()));
        fs::remove_dir(&path)?;
        symlink(dir.path(), &path)?;
        assert!(!is_module_installed_at(dir.path()));
        fs::remove_file(&path)?;
        let target = dir.path().join("target");
        symlink(&target, &path)?;
        assert!(!is_module_installed_at(dir.path()));
        fs::write(&target, b"prop")?;
        assert!(is_module_installed_at(dir.path()));
        fs::remove_file(&path)?;
        fs::write(&path, b"prop")?;
        assert!(is_module_installed_at(dir.path()));
        Ok(())
    }
}
