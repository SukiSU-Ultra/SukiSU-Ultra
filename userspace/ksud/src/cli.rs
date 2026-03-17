use anyhow::{Context, Ok, Result};
use clap::Parser;
use std::path::PathBuf;

use android_logger::Config;
use log::{LevelFilter, error, info};

use crate::boot_patch::{BootPatchArgs, BootRestoreArgs};
#[cfg(target_arch = "aarch64")]
use crate::{susfs, susfs_features};
use crate::cli::Susfs;
use crate::{apk_sign, assets, debug, defs, init_event, ksucalls, module, module_config, umount, utils};

/// KernelSU userspace cli
#[derive(Parser, Debug)]
#[command(author, version = defs::VERSION_NAME, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Manage KernelSU modules
    Module {
        #[command(subcommand)]
        command: Module,
    },

    /// Trigger `post-fs-data` event
    PostFsData,

    /// Trigger `service` event
    Services,

    /// Trigger `boot-complete` event
    BootCompleted,

    /// Load kernelsu.ko and execute late-load stage scripts
    LateLoad {
        /// Use adb root to execute late-load for jailbreaking by Magica
        #[arg(long, default_missing_value = "5555", num_args = 0..=1)]
        magica: Option<u16>,

        /// Restore adb properties after magica late-load
        #[arg(long)]
        post_magica: bool,
    },

    #[cfg(target_arch = "aarch64")]
    /// Susfs
    Susfs {
        #[command(subcommand)]
        command: Susfs,
    },

    /// Install KernelSU userspace component to system
    Install {
        #[arg(long, default_value = None)]
        magiskboot: Option<PathBuf>,
    },

    /// Uninstall KernelSU modules and itself(LKM Only)
    Uninstall {
        /// magiskboot path, if not specified, will search from $PATH
        #[arg(long, default_value = None)]
        magiskboot: Option<PathBuf>,
    },

    /// SELinux policy Patch tool
    Sepolicy {
        #[command(subcommand)]
        command: Sepolicy,
    },

    /// Manage App Profiles
    Profile {
        #[command(subcommand)]
        command: Profile,
    },

    /// Manage kernel features
    Feature {
        #[command(subcommand)]
        command: Feature,
    },

    /// Patch boot or init_boot images to apply KernelSU
    BootPatch(BootPatchArgs),

    /// Restore boot or init_boot images patched by KernelSU
    BootRestore(BootRestoreArgs),

    /// Show boot information
    BootInfo {
        #[command(subcommand)]
        command: BootInfo,
    },

    /// KPM module manager
    #[cfg(target_arch = "aarch64")]
    Kpm {
        #[command(subcommand)]
        command: kpm_cmd::Kpm,
    },

    /// Manage kernel umount paths
    Umount {
        #[command(subcommand)]
        command: Umount,
    },

    /// For developers
    Debug {
        #[command(subcommand)]
        command: Debug,
    },
    /// Kernel interface
    Kernel {
        #[command(subcommand)]
        command: Kernel,
    },
    /// Dump kernel sulog to file (/data/adb/ksu/log/sulog.log)
    SulogDump,
}

#[derive(clap::Subcommand, Debug)]
enum BootInfo {
    /// show current kmi version
    CurrentKmi,

    /// show supported kmi versions
    SupportedKmis,

    /// check if device is A/B capable
    IsAbDevice,

    /// show auto-selected boot partition name
    DefaultPartition,

    /// list available partitions for current or OTA toggled slot
    AvailablePartitions,

    /// show slot suffix for current or OTA toggled slot
    SlotSuffix {
        /// toggle to another slot
        #[arg(short = 'u', long, default_value = "false")]
        ota: bool,
    },
}

#[derive(clap::Subcommand, Debug)]
enum Debug {
    /// Set the manager app, kernel CONFIG_KSU_DEBUG should be enabled.
    SetManager {
        /// manager package name
        #[arg(default_value_t = String::from("com.sukisu.ultra"))]
        apk: String,
    },

    /// Get apk size and hash
    GetSign {
        /// apk path
        apk: String,
    },

    /// Root Shell
    Su {
        /// switch to gloabl mount namespace
        #[arg(short, long, default_value = "false")]
        global_mnt: bool,
    },

    /// Get kernel version
    Version,

    /// For testing
    Test,

    /// Extract an embedded binary to a specified path
    ExtractBinary {
        /// binary name (e.g. busybox, resetprop, bootctl)
        name: String,
        /// destination file path
        path: PathBuf,
    },

    /// Process mark management
    Mark {
        #[command(subcommand)]
        command: MarkCommand,
    },
}

#[derive(clap::Subcommand, Debug)]
enum MarkCommand {
    /// Get mark status for a process (or all)
    Get {
        /// target pid (0 for total count)
        #[arg(default_value = "0")]
        pid: i32,
    },

    /// Mark a process
    Mark {
        /// target pid (0 for all processes)
        #[arg(default_value = "0")]
        pid: i32,
    },

    /// Unmark a process
    Unmark {
        /// target pid (0 for all processes)
        #[arg(default_value = "0")]
        pid: i32,
    },

    /// Refresh mark for all running processes
    Refresh,
}

#[derive(clap::Subcommand, Debug)]
enum Sepolicy {
    /// Patch sepolicy
    Patch {
        /// sepolicy statements
        sepolicy: String,
    },

    /// Apply sepolicy from file
    Apply {
        /// sepolicy file path
        file: String,
    },

    /// Check if sepolicy statement is supported/valid
    Check {
        /// sepolicy statements
        sepolicy: String,
    },
}

#[derive(clap::Subcommand, Debug)]
enum Module {
    /// Install module <ZIP>
    Install {
        /// module zip file path
        zip: String,
    },

    /// Undo module uninstall mark <id>
    UndoUninstall {
        /// module id
        id: String,
    },

    /// Uninstall module <id>
    Uninstall {
        /// module id
        id: String,
    },

    /// enable module <id>
    Enable {
        /// module id
        id: String,
    },

    /// disable module <id>
    Disable {
        // module id
        id: String,
    },

    /// run action for module <id>
    Action {
        // module id
        id: String,
    },

    /// module lua runner
    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    Lua {
        // module id
        id: String,
        // lua function
        function: String,
    },

    /// list all modules
    List,

    /// manage module configuration
    Config {
        #[command(subcommand)]
        command: ModuleConfigCmd,
    },
}

#[derive(clap::Subcommand, Debug)]
enum ModuleConfigCmd {
    /// Get a config value
    Get {
        /// config key
        key: String,
    },

    /// Set a config value
    Set {
        /// config key
        key: String,
        /// config value (omit to read from stdin)
        value: Option<String>,
        /// read value from stdin (default if value not provided)
        #[arg(long)]
        stdin: bool,
        /// use temporary config (cleared on reboot)
        #[arg(short, long)]
        temp: bool,
    },

    /// List all config entries
    List,

    /// Delete a config entry
    Delete {
        /// config key
        key: String,
        /// delete from temporary config
        #[arg(short, long)]
        temp: bool,
    },

    /// Clear all config entries
    Clear {
        /// clear temporary config
        #[arg(short, long)]
        temp: bool,
    },
}

#[derive(clap::Subcommand, Debug)]
enum Profile {
    /// get root profile's selinux policy of <package-name>
    GetSepolicy {
        /// package name
        package: String,
    },

    /// set root profile's selinux policy of <package-name> to <profile>
    SetSepolicy {
        /// package name
        package: String,
        /// policy statements
        policy: String,
    },

    /// get template of <id>
    GetTemplate {
        /// template id
        id: String,
    },

    /// set template of <id> to <template string>
    SetTemplate {
        /// template id
        id: String,
        /// template string
        template: String,
    },

    /// delete template of <id>
    DeleteTemplate {
        /// template id
        id: String,
    },

    /// list all templates
    ListTemplates,
}

#[derive(clap::Subcommand, Debug)]
enum Feature {
    /// Get feature value and support status
    Get {
        /// Feature ID or name (su_compat, kernel_umount)
        id: String,
        /// Read from config file
        #[arg(long, default_value_t = false)]
        config: bool,
    },

    /// Set feature value
    Set {
        /// Feature ID or name
        id: String,
        /// Feature value (0=disable, 1=enable)
        value: u64,
    },

    /// List all available features
    List,

    /// Check feature status (supported/unsupported/managed)
    Check {
        /// Feature ID or name (su_compat, kernel_umount)
        id: String,
    },

    /// Load configuration from file and apply to kernel
    Load,

    /// Save current kernel feature states to file
    Save,
}

#[derive(clap::Subcommand, Debug)]
enum Kernel {
    /// Nuke ext4 sysfs
    NukeExt4Sysfs {
        /// mount point
        mnt: String,
    },
    /// Manage umount list
    Umount {
        #[command(subcommand)]
        command: UmountOp,
    },
    /// Notify that module is mounted
    NotifyModuleMounted,
}

#[derive(clap::Subcommand, Debug)]
enum Umount {
    /// Add mount point to umount list
    Add {
        /// mount point path
        mnt: String,
        /// umount flags (default: 0, MNT_DETACH: 2)
        #[arg(short, long, default_value = "0")]
        flags: u32,
    },
    /// Remove mount point from umount list
    Remove {
        /// mount point path
        mnt: String,
    },
    /// List all mount points in umount list
    List,
    /// Save current umount list to file
    Save,
    /// Apply saved umount list from file to kernel
    Apply,
    /// Clear custom umount paths (wipe kernel list)
    ClearCustom,
}

#[derive(clap::Subcommand, Debug)]
enum UmountOp {
    /// Add mount point to umount list
    Add {
        /// mount point path
        mnt: String,
        /// umount flags (default: 0, MNT_DETACH: 2)
        #[arg(short, long, default_value = "0")]
        flags: u32,
    },
    /// Delete mount point from umount list
    Del {
        /// mount point path
        mnt: String,
    },
    /// Wipe all entries from umount list
    Wipe,
}

#[cfg(target_arch = "aarch64")]
mod kpm_cmd {
    use clap::Subcommand;
    use std::path::PathBuf;

    #[derive(Subcommand, Debug)]
    pub enum Kpm {
        /// Load a KPM module: load <path> [args]
        Load { path: PathBuf, args: Option<String> },
        /// Unload a KPM module: unload <name>
        Unload { name: String },
        /// Get number of loaded modules
        Num,
        /// List loaded KPM modules
        List,
        /// Get info of a KPM module: info <name>
        Info { name: String },
        /// Send control command to a KPM module: control <name> <args>
        Control { name: String, args: String },
        /// Print KPM Loader version
        Version,
    }
}

#[cfg(target_arch = "aarch64")]
#[derive(clap::Subcommand, Debug)]
enum Susfs {
    /// Get SUSFS Status
    Status,
    /// Get SUSFS Version
    Version,
    /// Get SUSFS enable Features
    Features,
    /// Show current configuration
    Config,
    /// Reset configuration to default
    Reset,

    // === 日志控制 ===
    /// Enable or disable log
    SetLog {
        /// 1 to enable, 0 to disable
        enabled: bool,
    },

    // === AVC日志欺骗 ===
    /// Enable or disable AVC log spoofing
    SetAvcLogSpoofing {
        /// 1 to enable, 0 to disable
        enabled: bool,
    },

    // === SUS挂载隐藏 ===
    /// Set SUS mount hide for non-su processes
    SetHideSusMounts {
        /// 1 to hide for all, 0 to hide only for non-KSU
        hide_all: bool,
    },

    // === uname/build_time ===
    /// Set uname and build time
    SetUname {
        /// uname value
        uname: String,
        /// build time value
        build_time: String,
    },

    // === SUS路径管理 ===
    /// Add a SUS path
    AddSusPath {
        /// path to add
        path: String,
    },
    /// Remove a SUS path
    RemoveSusPath {
        /// path to remove
        path: String,
    },
    /// List all SUS paths
    ListSusPaths,

    // === SUS循环路径管理 ===
    /// Add a SUS loop path
    AddSusLoopPath {
        /// path to add
        path: String,
    },
    /// Remove a SUS loop path
    RemoveSusLoopPath {
        /// path to remove
        path: String,
    },
    /// List all SUS loop paths
    ListSusLoopPaths,

    // === SUS Map管理 ===
    /// Add a SUS map
    AddSusMap {
        /// map to add (format: source->target)
        map: String,
    },
    /// Remove a SUS map
    RemoveSusMap {
        /// map to remove
        map: String,
    },
    /// List all SUS maps
    ListSusMaps,

    // === Kstat管理 ===
    /// Add a Kstat path
    AddKstatPath {
        /// path to add
        path: String,
    },
    /// Remove a Kstat path
    RemoveKstatPath {
        /// path to remove
        path: String,
    },
    /// List all Kstat paths
    ListKstatPaths,

    // === Kstat静态配置 ===
    /// Add a Kstat static config
    AddKstatStatic {
        /// config string (path|ino|dev|nlink|size|atime|atimeNsec|mtime|mtimeNsec|ctime|ctimeNsec|blocks|blksize)
        config: String,
    },
    /// Remove a Kstat static config
    RemoveKstatStatic {
        /// config to remove
        config: String,
    },
    /// List all Kstat static configs
    ListKstatStatic,

    // === Kstat更新 ===
    /// Update Kstat for a path
    UpdateKstat {
        /// path to update
        path: String,
    },
    /// Update Kstat full clone for a path
    UpdateKstatFullClone {
        /// path to update
        path: String,
    },

    // === 隐藏BL ===
    /// Enable or disable hide boot loader
    SetHideBl {
        /// 1 to enable, 0 to disable
        enabled: bool,
    },

    // === 清理残留 ===
    /// Enable or disable cleanup residue
    SetCleanupResidue {
        /// 1 to enable, 0 to disable
        enabled: bool,
    },

    // === 执行时机 ===
    /// Set execute in post-fs-data
    SetExecuteInPostFsData {
        /// 1 for post-fs-data, 0 for service
        enabled: bool,
    },

    // === Magisk模块 ===
    /// Create/update Magisk module
    CreateModule,
    /// Remove Magisk module
    RemoveModule,

    // === 自启动 ===
    /// Enable or disable auto start
    SetAutoStart {
        /// 1 to enable, 0 to disable
        enabled: bool,
    },

    // === 备份/恢复 ===
    /// Create a backup
    Backup {
        /// backup file path (optional)
        path: Option<String>,
    },
    /// Restore from backup
    Restore {
        /// backup file path
        path: String,
    },
    /// Validate a backup file
    ValidateBackup {
        /// backup file path
        path: String,
    },
    /// List all backups
    ListBackups,

    // === 槽位信息 ===
    /// Get slot info
    SlotInfo,

    // === 完全重置 ===
    /// Reset to default
    ResetAll,
}

pub fn run() -> Result<()> {
    android_logger::init_once(
        Config::default()
            .with_max_level(crate::debug_select!(LevelFilter::Trace, LevelFilter::Info))
            .with_tag("KernelSU"),
    );

    // the kernel executes su with argv[0] = "su" and replace it with us
    let arg0 = std::env::args().next().unwrap_or_default();
    if arg0 == "su" || arg0 == "/system/bin/su" {
        return crate::su::root_shell();
    }

    let cli = Args::parse();

    log::info!("command: {:?}", cli.command);

    let result = match cli.command {
        Commands::PostFsData => init_event::on_post_data_fs(),
        Commands::BootCompleted => {
            init_event::on_boot_completed();
            Ok(())
        }
        #[cfg(target_arch = "aarch64")]
        Commands::Susfs { command } => {
            match command {
                Susfs::Version => println!("{}", susfs::get_susfs_version()),

                Susfs::Status => println!("{}", susfs::get_susfs_status()),

                Susfs::Features => println!("{}", susfs::get_susfs_features()),

                // 配置管理
                Susfs::Config => susfs_features::show_config(),

                Susfs::Reset => {
                    susfs_features::reset_to_default()?;
                }

                // 日志控制
                Susfs::SetLog { enabled } => {
                    susfs_features::susfs_enable_log(enabled)?;
                    println!("Log enabled: {}", enabled);
                }

                // AVC日志欺骗
                Susfs::SetAvcLogSpoofing { enabled } => {
                    susfs_features::susfs_enable_avc_log_spoofing(enabled)?;
                    println!("AVC log spoofing enabled: {}", enabled);
                }

                // SUS挂载隐藏
                Susfs::SetHideSusMounts { hide_all } => {
                    susfs_features::susfs_hide_sus_mnts_for_non_su_procs(hide_all)?;
                    println!("Hide SUS mounts for all procs: {}", hide_all);
                }

                // uname/build_time
                Susfs::SetUname { uname, build_time } => {
                    susfs_features::susfs_set_uname(&uname, &build_time)?;
                    println!("Set uname: {}, build_time: {}", uname, build_time);
                }

                // SUS路径管理
                Susfs::AddSusPath { path } => {
                    susfs_features::susfs_add_sus_path(&path)?;
                    println!("Added SUS path: {}", path);
                }
                Susfs::RemoveSusPath { path } => {
                    susfs_features::susfs_remove_sus_path(&path)?;
                    println!("Removed SUS path: {}", path);
                }
                Susfs::ListSusPaths => {
                    let paths = susfs_features::get_sus_paths()?;
                    println!("SUS paths:");
                    for p in paths {
                        println!("  - {}", p);
                    }
                }

                // SUS循环路径管理
                Susfs::AddSusLoopPath { path } => {
                    susfs_features::susfs_add_sus_path_loop(&path)?;
                    println!("Added SUS loop path: {}", path);
                }
                Susfs::RemoveSusLoopPath { path } => {
                    susfs_features::susfs_remove_sus_path_loop(&path)?;
                    println!("Removed SUS loop path: {}", path);
                }
                Susfs::ListSusLoopPaths => {
                    let paths = susfs_features::get_sus_loop_paths()?;
                    println!("SUS loop paths:");
                    for p in paths {
                        println!("  - {}", p);
                    }
                }

                // SUS Map管理
                Susfs::AddSusMap { map } => {
                    susfs_features::susfs_add_sus_map(&map)?;
                    println!("Added SUS map: {}", map);
                }
                Susfs::RemoveSusMap { map } => {
                    susfs_features::susfs_remove_sus_map(&map)?;
                    println!("Removed SUS map: {}", map);
                }
                Susfs::ListSusMaps => {
                    let maps = susfs_features::get_sus_maps()?;
                    println!("SUS maps:");
                    for m in maps {
                        println!("  - {}", m);
                    }
                }

                // Kstat路径管理
                Susfs::AddKstatPath { path } => {
                    susfs_features::susfs_add_sus_kstat(&path)?;
                    println!("Added Kstat path: {}", path);
                }
                Susfs::RemoveKstatPath { path } => {
                    susfs_features::susfs_remove_sus_kstat(&path)?;
                    println!("Removed Kstat path: {}", path);
                }
                Susfs::ListKstatPaths => {
                    let paths = susfs_features::get_add_kstat_paths()?;
                    println!("Kstat paths:");
                    for p in paths {
                        println!("  - {}", p);
                    }
                }

                // Kstat静态配置
                Susfs::AddKstatStatic { config } => {
                    susfs_features::susfs_add_sus_kstat_statically(&config)?;
                    println!("Added Kstat static config");
                }
                Susfs::RemoveKstatStatic { config } => {
                    susfs_features::susfs_remove_sus_kstat_config(&config)?;
                    println!("Removed Kstat static config");
                }
                Susfs::ListKstatStatic => {
                    let configs = susfs_features::get_kstat_configs()?;
                    println!("Kstat static configs:");
                    for c in configs {
                        println!("  - {}", c);
                    }
                }

                // Kstat更新
                Susfs::UpdateKstat { path } => {
                    susfs_features::susfs_update_sus_kstat(&path)?;
                    println!("Updated Kstat for: {}", path);
                }
                Susfs::UpdateKstatFullClone { path } => {
                    susfs_features::susfs_update_sus_kstat_full_clone(&path)?;
                    println!("Updated Kstat full clone for: {}", path);
                }

                // 隐藏BL
                Susfs::SetHideBl { enabled } => {
                    susfs_features::set_enable_hide_bl(enabled)?;
                    println!("Hide BL enabled: {}", enabled);
                }

                // 清理残留
                Susfs::SetCleanupResidue { enabled } => {
                    susfs_features::set_enable_cleanup_residue(enabled)?;
                    println!("Cleanup residue enabled: {}", enabled);
                }

                // 执行时机
                Susfs::SetExecuteInPostFsData { enabled } => {
                    susfs_features::set_execute_in_post_fs_data(enabled)?;
                    println!("Execute in post-fs-data: {}", enabled);
                }

                // Magisk模块
                Susfs::CreateModule => {
                    susfs_features::create_magisk_module()?;
                    println!("Magisk module created");
                }
                Susfs::RemoveModule => {
                    susfs_features::remove_magisk_module()?;
                    println!("Magisk module removed");
                }

                // 自启动
                Susfs::SetAutoStart { enabled } => {
                    susfs_features::configure_auto_start(enabled)?;
                    println!("Auto start enabled: {}", enabled);
                }

                // 备份/恢复
                Susfs::Backup { path } => {
                    let backup_path = susfs_features::create_backup(path)?;
                    println!("Backup created: {}", backup_path);
                }
                Susfs::Restore { path } => {
                    susfs_features::restore_from_backup(&path)?;
                    println!("Restored from: {}", path);
                }
                Susfs::ValidateBackup { path } => {
                    let backup = susfs_features::validate_backup(&path)?;
                    println!("Backup valid:");
                    println!("  Version: {}", backup.version);
                    println!("  Timestamp: {}", backup.timestamp);
                    println!("  Device: {}", backup.device_info);
                }
                Susfs::ListBackups => {
                    let backups = susfs_features::list_backups()?;
                    println!("Backups:");
                    for b in backups {
                        println!("  - {}", b);
                    }
                }

                // 槽位信息
                Susfs::SlotInfo => {
                    let slots = susfs_features::get_slot_info()?;
                    let current = susfs_features::get_current_active_slot()?;
                    println!("Slot info:");
                    for slot in slots {
                        let marker = if slot.slot_name == current { " *" } else { "" };
                        println!("  - {}: uname={}, build_time={}{}", slot.slot_name, slot.uname, slot.build_time, marker);
                    }
                }

                // 完全重置
                Susfs::ResetAll => {
                    susfs_features::reset_to_default()?;
                    println!("Reset to default");
                }
            }
            Ok(())
        }
        Commands::Module { command } => {
            utils::switch_mnt_ns(1)?;
            match command {
                Module::Install { zip } => module::install_module(&zip),
                Module::UndoUninstall { id } => module::undo_uninstall_module(&id),
                Module::Uninstall { id } => module::uninstall_module(&id),
                Module::Enable { id } => module::enable_module(&id),
                Module::Disable { id } => module::disable_module(&id),
                Module::Action { id } => module::run_action(&id),
                #[cfg(all(target_os = "android", target_arch = "aarch64"))]
                Module::Lua { id, function } => {
                    module::run_lua(&id, &function, false, true).map_err(|e| anyhow::anyhow!("{e}"))
                }
                Module::List => module::list_modules(),
                Module::Config { command } => {
                    // Get module ID from environment variable
                    let module_id = std::env::var("KSU_MODULE").map_err(|_| {
                        anyhow::anyhow!("This command must be run in the context of a module")
                    })?;

                    match command {
                        ModuleConfigCmd::Get { key } => {
                            // Use merge_configs to respect priority (temp overrides persist)
                            let config = module_config::merge_configs(&module_id)?;
                            match config.get(&key) {
                                Some(value) => {
                                    println!("{value}");
                                    Ok(())
                                }
                                None => anyhow::bail!("Key '{key}' not found"),
                            }
                        }
                        ModuleConfigCmd::Set {
                            key,
                            value,
                            stdin,
                            temp,
                        } => {
                            // Validate key at CLI layer for better user experience
                            module_config::validate_config_key(&key)?;

                            // Read value from stdin or argument
                            let value_str = match value {
                                Some(v) if !stdin => v,
                                _ => {
                                    // Read from stdin
                                    use std::io::Read;
                                    let mut buffer = String::new();
                                    std::io::stdin()
                                        .read_to_string(&mut buffer)
                                        .context("Failed to read from stdin")?;
                                    buffer
                                }
                            };

                            // Validate value
                            module_config::validate_config_value(&value_str)?;

                            let config_type = if temp {
                                module_config::ConfigType::Temp
                            } else {
                                module_config::ConfigType::Persist
                            };
                            module_config::set_config_value(
                                &module_id,
                                &key,
                                &value_str,
                                config_type,
                            )
                        }
                        ModuleConfigCmd::List => {
                            let config = module_config::merge_configs(&module_id)?;
                            if config.is_empty() {
                                println!("No config entries found");
                            } else {
                                for (key, value) in config {
                                    println!("{key}={value}");
                                }
                            }
                            Ok(())
                        }
                        ModuleConfigCmd::Delete { key, temp } => {
                            let config_type = if temp {
                                module_config::ConfigType::Temp
                            } else {
                                module_config::ConfigType::Persist
                            };
                            module_config::delete_config_value(&module_id, &key, config_type)
                        }
                        ModuleConfigCmd::Clear { temp } => {
                            let config_type = if temp {
                                module_config::ConfigType::Temp
                            } else {
                                module_config::ConfigType::Persist
                            };
                            module_config::clear_config(&module_id, config_type)
                        }
                    }
                }
            }
        }
        Commands::Install { magiskboot } => utils::install(magiskboot),
        Commands::Uninstall { magiskboot } => utils::uninstall(magiskboot),
        Commands::Sepolicy { command } => match command {
            Sepolicy::Patch { sepolicy } => crate::sepolicy::live_patch(&sepolicy),
            Sepolicy::Apply { file } => crate::sepolicy::apply_file(file),
            Sepolicy::Check { sepolicy } => crate::sepolicy::check_rule(&sepolicy),
        },
        Commands::LateLoad {
            magica,
            post_magica,
        } => {
            if let Some(port) = magica {
                return crate::magica::run(port).map_err(|e| {
                    error!("Error running magica: {e}");
                    e
                });
            }
            let result = crate::late_load::run();
            if post_magica {
                info!("Restoring adb properties (post-magica cleanup)...");
                if let Err(e) = crate::magica::disable_adb_root() {
                    error!("disable adb root failed: {e}");
                }
            }
            result
        }
        Commands::Services => {
            init_event::on_services();
            Ok(())
        }
        Commands::Profile { command } => match command {
            Profile::GetSepolicy { package } => crate::profile::get_sepolicy(package),
            Profile::SetSepolicy { package, policy } => {
                crate::profile::set_sepolicy(package, policy)
            }
            Profile::GetTemplate { id } => crate::profile::get_template(id),
            Profile::SetTemplate { id, template } => crate::profile::set_template(id, template),
            Profile::DeleteTemplate { id } => crate::profile::delete_template(id),
            Profile::ListTemplates => crate::profile::list_templates(),
        },

        Commands::Feature { command } => match command {
            Feature::Get { id, config } => {
                if config {
                    crate::feature::get_feature_config(&id)
                } else {
                    crate::feature::get_feature(&id)
                }
            }
            Feature::Set { id, value } => crate::feature::set_feature(&id, value),
            Feature::List => {
                crate::feature::list_features();
                Ok(())
            }
            Feature::Check { id } => crate::feature::check_feature(&id),
            Feature::Load => crate::feature::load_config_and_apply(),
            Feature::Save => crate::feature::save_config(),
        },

        Commands::Debug { command } => match command {
            Debug::SetManager { apk } => debug::set_manager(&apk),
            Debug::GetSign { apk } => {
                let sign = apk_sign::get_apk_signature(&apk)?;
                println!("size: {:#x}, hash: {}", sign.0, sign.1);
                Ok(())
            }
            Debug::Version => {
                println!("Kernel Version: {}", ksucalls::get_version());
                Ok(())
            }
            Debug::Su { global_mnt } => crate::su::grant_root(global_mnt),
            Debug::Test => assets::ensure_binaries(false),
            Debug::ExtractBinary { name, path } => {
                let data = assets::get_asset_data(&name)?;
                utils::ensure_binary(&path, &data, false)
            }
            Debug::Mark { command } => match command {
                MarkCommand::Get { pid } => debug::mark_get(pid),
                MarkCommand::Mark { pid } => debug::mark_set(pid),
                MarkCommand::Unmark { pid } => debug::mark_unset(pid),
                MarkCommand::Refresh => debug::mark_refresh(),
            },
        },

        Commands::BootPatch(boot_patch) => crate::boot_patch::patch(boot_patch),

        Commands::BootInfo { command } => match command {
            BootInfo::CurrentKmi => {
                let kmi = crate::boot_patch::get_current_kmi()?;
                println!("{kmi}");
                // return here to avoid printing the error message
                return Ok(());
            }
            BootInfo::SupportedKmis => {
                let kmi = crate::assets::list_supported_kmi();
                for kmi in &kmi {
                    println!("{kmi}");
                }
                return Ok(());
            }
            BootInfo::IsAbDevice => {
                let val = crate::utils::getprop("ro.build.ab_update")
                    .unwrap_or_else(|| String::from("false"));
                let is_ab = val.trim().to_lowercase() == "true";
                println!("{}", if is_ab { "true" } else { "false" });
                return Ok(());
            }
            BootInfo::DefaultPartition => {
                let kmi = crate::boot_patch::get_current_kmi().unwrap_or_else(|_| String::new());
                let name = crate::boot_patch::choose_boot_partition(&kmi, false, &None);
                println!("{name}");
                return Ok(());
            }
            BootInfo::SlotSuffix { ota } => {
                let suffix = crate::boot_patch::get_slot_suffix(ota);
                println!("{suffix}");
                return Ok(());
            }
            BootInfo::AvailablePartitions => {
                let parts = crate::boot_patch::list_available_partitions();
                for p in &parts {
                    println!("{p}");
                }
                return Ok(());
            }
        },
        Commands::BootRestore(boot_restore) => crate::boot_patch::restore(boot_restore),
        Commands::Umount { command } => match command {
            Umount::Add { mnt, flags } => ksucalls::umount_list_add(&mnt, flags),
            Umount::Remove { mnt } => umount::remove_umount_entry_from_config(&mnt),
            Umount::List => {
                let list = ksucalls::umount_list_list()?;
                print!("{list}");
                Ok(())
            }
            Umount::Save => umount::save_umount_config(),
            Umount::Apply => umount::apply_umount_config(),
            Umount::ClearCustom => umount::clear_umount_config(),
        },
        Commands::Kernel { command } => match command {
            Kernel::NukeExt4Sysfs { mnt } => ksucalls::nuke_ext4_sysfs(&mnt),
            Kernel::Umount { command } => match command {
                UmountOp::Add { mnt, flags } => ksucalls::umount_list_add(&mnt, flags),
                UmountOp::Del { mnt } => ksucalls::umount_list_del(&mnt),
                UmountOp::Wipe => ksucalls::umount_list_wipe().map_err(Into::into),
            },
            Kernel::NotifyModuleMounted => {
                ksucalls::report_module_mounted();
                Ok(())
            }
        },
        Commands::SulogDump => {
            ksucalls::dump_sulog_to_file()?;
            println!("sulog saved to /data/adb/ksu/log/sulog.log");
            Ok(())
        }
        #[cfg(target_arch = "aarch64")]
        Commands::Kpm { command } => {
            use crate::cli::kpm_cmd::Kpm;
            match command {
                Kpm::Load { path, args } => {
                    crate::kpm::load_module(path.to_str().unwrap(), args.as_deref())
                }
                Kpm::Unload { name } => crate::kpm::unload_module(name),
                Kpm::Num => crate::kpm::num().map(|_| ()),
                Kpm::List => crate::kpm::list(),
                Kpm::Info { name } => crate::kpm::info(name),
                Kpm::Control { name, args } => {
                    let ret = crate::kpm::control(name, args)?;
                    println!("{ret}");
                    Ok(())
                }
                Kpm::Version => crate::kpm::version(),
            }
        }
    };

    if let Err(e) = &result {
        log::error!("Error: {e:?}");
    }
    result
}
