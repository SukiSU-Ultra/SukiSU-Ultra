#![deny(clippy::all, clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(
    clippy::module_name_repetitions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::cast_possible_wrap
)]

mod apk_sign;
mod assets;
mod boot_patch;
mod cli;
mod debug;
mod defs;
mod feature;
mod init_event;
#[cfg(target_arch = "aarch64")]
mod kpm;
mod ksucalls;
mod metamodule;
mod module;
mod module_config;
mod profile;
mod restorecon;
mod sepolicy;
mod su;
mod susfs;
#[cfg(target_os = "android")]
mod uid_scanner;
mod umount_manager;
mod utils;

fn main() -> anyhow::Result<()> {
    cli::run()
}
