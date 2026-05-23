use crate::ksu_uapi;
use anyhow::{Context, Result, ensure};
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(clap::Args, Debug, Clone, Default)]
pub struct UtsSpoofConfig {
    /// Kernel release string to spoof
    #[arg(long)]
    pub release: Option<String>,

    /// Kernel version string to spoof
    #[arg(long)]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct UtsSpoofParams {
    pub release: Option<String>,
    pub version: Option<String>,
}

impl From<&UtsSpoofConfig> for UtsSpoofParams {
    fn from(config: &UtsSpoofConfig) -> Self {
        Self {
            release: config.release.clone(),
            version: config.version.clone(),
        }
    }
}

fn do_cpio_cmd(magiskboot: &Path, workdir: &Path, cpio_path: &Path, cmd: &str) -> Result<()> {
    let status = Command::new(magiskboot)
        .current_dir(workdir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .arg("cpio")
        .arg(cpio_path)
        .arg(cmd)
        .status()?;
    ensure!(status.success(), "magiskboot cpio {cmd} failed");
    Ok(())
}

pub fn apply_spoof_to_ramdisk(
    magiskboot: &Path,
    workdir: &Path,
    ramdisk: &Path,
    release: Option<&str>,
    version: Option<&str>,
) -> Result<()> {
    if let Some(release) = release.map(str::trim).filter(|v| !v.is_empty()) {
        println!("- Adding spoof release config");
        let config_file = workdir.join("ksu_spoof_release");
        std::fs::write(&config_file, release).with_context(|| "write ksu_spoof_release")?;
        do_cpio_cmd(
            magiskboot,
            workdir,
            ramdisk,
            "add 0644 ksu_spoof_release ksu_spoof_release",
        )?;
    }

    if let Some(version) = version.map(str::trim).filter(|v| !v.is_empty()) {
        println!("- Adding spoof version config");
        let config_file = workdir.join("ksu_spoof_version");
        std::fs::write(&config_file, version).with_context(|| "write ksu_spoof_version")?;
        do_cpio_cmd(
            magiskboot,
            workdir,
            ramdisk,
            "add 0644 ksu_spoof_version ksu_spoof_version",
        )?;
    }

    Ok(())
}

pub fn set_spoof_version(release: &str, version: &str) -> anyhow::Result<()> {
    let mut cmd = ksu_uapi::ksu_set_spoof_version_cmd {
        release: [0; 65],
        version: [0; 65],
    };

    let r_bytes = release.as_bytes();
    let r_len = std::cmp::min(r_bytes.len(), 64);
    cmd.release[..r_len].copy_from_slice(&r_bytes[..r_len]);

    let v_bytes = version.as_bytes();
    let v_len = std::cmp::min(v_bytes.len(), 64);
    cmd.version[..v_len].copy_from_slice(&v_bytes[..v_len]);

    crate::ksucalls::ksuctl(ksu_uapi::KSU_IOCTL_SET_SPOOF_VERSION, &raw mut cmd)?;
    Ok(())
}
