mod apk_sign;
mod assets;
mod boot_patch;
mod cli;
mod debug;
mod defs;
mod init_event;
mod kpm;
mod ksucalls;
#[cfg(target_os = "android")]
mod magic_mount;
mod module;
mod profile;
mod restorecon;
mod sepolicy;
mod su;
mod utils;
mod uid_scanner;

fn main() -> anyhow::Result<()> {
    cli::run()
}
