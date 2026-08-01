#![allow(clippy::ref_option, clippy::needless_pass_by_value)]

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{BufReader, Cursor, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use android_bootimg::cpio::{Cpio, CpioEntry};
use android_bootimg::parser::{BootImage, BootImageVersion, RamdiskImage};
use android_bootimg::patcher::BootImagePatchOption;
use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use memmap2::{Mmap, MmapOptions};
use regex_lite::Regex;

use crate::assets;

#[cfg(target_os = "android")]
mod android {
    use super::Result;
    pub(super) use crate::defs::{BACKUP_FILENAME, KSU_BACKUP_DIR, KSU_BACKUP_FILE_PREFIX};
    use crate::defs::{DEFAULT_PACKAGE_NAME, KSU_TEMP_BACKUP_DIR_NAME};
    use android_bootimg::cpio::{Cpio, CpioEntry};
    use anyhow::{Context, anyhow, bail, ensure};
    use regex_lite::Regex;
    use rustix::process::getuid;
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use crate::utils;

    pub(super) fn ensure_gki_kernel() -> Result<()> {
        let version = get_kernel_version()?;
        let is_gki = version.0 == 5 && version.1 >= 10 || version.2 > 5;
        ensure!(is_gki, "only support GKI kernel");
        Ok(())
    }

    pub fn get_kernel_version() -> Result<(i32, i32, i32)> {
        let uname = rustix::system::uname();
        let version = uname.release().to_string_lossy();
        let re = Regex::new(r"(\d+)\.(\d+)\.(\d+)")?;
        if let Some(captures) = re.captures(&version) {
            let major = captures
                .get(1)
                .and_then(|m| m.as_str().parse::<i32>().ok())
                .ok_or_else(|| anyhow!("Major version parse error"))?;
            let minor = captures
                .get(2)
                .and_then(|m| m.as_str().parse::<i32>().ok())
                .ok_or_else(|| anyhow!("Minor version parse error"))?;
            let patch = captures
                .get(3)
                .and_then(|m| m.as_str().parse::<i32>().ok())
                .ok_or_else(|| anyhow!("Patch version parse error"))?;
            Ok((major, minor, patch))
        } else {
            Err(anyhow!("Invalid kernel version string"))
        }
    }

    fn parse_kmi(version: &str) -> Result<String> {
        let re = Regex::new(r"(.* )?(\d+\.\d+)(\S+)?(android\d+)(.*)")?;
        let cap = re
            .captures(version)
            .ok_or_else(|| anyhow::anyhow!("Failed to get KMI from boot/modules"))?;
        let android_version = cap.get(4).map_or("", |m| m.as_str());
        let kernel_version = cap.get(2).map_or("", |m| m.as_str());
        Ok(format!("{android_version}-{kernel_version}"))
    }

    fn parse_kmi_from_uname() -> Result<String> {
        let uname = rustix::system::uname();
        let version = uname.release().to_string_lossy();
        parse_kmi(&version)
    }

    fn parse_kmi_from_modules() -> Result<String> {
        use std::io::BufRead;
        // find a *.ko in /vendor/lib/modules
        let modfile = std::fs::read_dir("/vendor/lib/modules")?
            .filter_map(Result::ok)
            .find(|entry| entry.path().extension().is_some_and(|ext| ext == "ko"))
            .map(|entry| entry.path())
            .ok_or_else(|| anyhow!("No kernel module found"))?;
        let output = Command::new("modinfo").arg(modfile).output()?;
        for line in output.stdout.lines().map_while(Result::ok) {
            if line.starts_with("vermagic") {
                return parse_kmi(&line);
            }
        }
        bail!("Parse KMI from modules failed")
    }

    pub fn get_current_kmi() -> Result<String> {
        parse_kmi_from_uname().or_else(|_| parse_kmi_from_modules())
    }

    fn calculate_sha1(file_path: impl AsRef<Path>) -> Result<String> {
        use sha1::Digest;
        use std::io::Read;
        let mut file = std::fs::File::open(file_path.as_ref())?;
        let mut hasher = sha1::Sha1::new();
        let mut buffer = [0; 1024];

        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        let result = hasher.finalize();
        Ok(base16ct::lower::encode_string(&result))
    }

    fn find_backup_location(sha1: &String) -> Result<(File, String)> {
        let filename = format!("{KSU_BACKUP_FILE_PREFIX}{sha1}");
        let target = format!("{KSU_BACKUP_DIR}{filename}");
        if let Ok(target_file) = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&target)
        {
            return Ok((target_file, target));
        }

        // We have no permission to access /data/adb
        // Save it to /data/user_de/$USER/$PKG/boot_backup
        let user_id = getuid().as_raw() / 100_000;

        let backup_dir =
            format!("/data/user_de/{user_id}/{DEFAULT_PACKAGE_NAME}/{KSU_TEMP_BACKUP_DIR_NAME}");
        std::fs::remove_dir_all(&backup_dir).ok();
        std::fs::create_dir(&backup_dir)?;
        let backup_file = format!("{backup_dir}/{filename}");
        if let Ok(file) = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&backup_file)
        {
            return Ok((file, backup_file));
        }

        bail!("Both /data/adb/ksu and {backup_dir} are not accessible!")
    }

    pub(super) fn do_backup(cpio: &mut Cpio, image: &Path) -> Result<()> {
        let sha1 = calculate_sha1(image)?;
        let (mut target_file, target) = find_backup_location(&sha1)?;
        println!("- Backup stock boot image");
        let mut source = OpenOptions::new()
            .create(false)
            .truncate(false)
            .read(true)
            .write(false)
            .open(image)?;

        // Use io::copy instead of fs::copy to allow copy block device
        std::io::copy(&mut source, &mut target_file)
            .with_context(|| format!("failed to backup to {target}"))?;

        let backup_file = CpioEntry::regular(0o755, Box::new(sha1));
        cpio.add(BACKUP_FILENAME, backup_file)?;
        println!("- Stock image has been backup to");
        println!("- {target}");
        Ok(())
    }

    pub(super) fn clean_backup(sha1: &str) -> Result<()> {
        println!("- Clean up backup");
        let backup_name = format!("{KSU_BACKUP_FILE_PREFIX}{sha1}");
        let dir = std::fs::read_dir(KSU_BACKUP_DIR)?;
        for entry in dir.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Some(name) = path.file_name() {
                let name = name.to_string_lossy().to_string();
                if name != backup_name
                    && name.starts_with(KSU_BACKUP_FILE_PREFIX)
                    && std::fs::remove_file(path).is_ok()
                {
                    println!("- removed {name}");
                }
            }
        }
        Ok(())
    }

    pub(super) fn backup_vendor_boot(image: &Path) -> Result<PathBuf> {
        const PREFIX: &str = "sakisu_vendor_boot_backup_";
        let sha1 = calculate_sha1(image)?;
        let target = PathBuf::from(KSU_BACKUP_DIR).join(format!("{PREFIX}{sha1}.img"));
        if target.is_file() {
            if calculate_sha1(&target)? == sha1 {
                println!("- Existing vendor_boot backup: {}", target.display());
                return Ok(target);
            }
            println!(
                "- Existing vendor_boot backup is incomplete; replacing it atomically: {}",
                target.display()
            );
        }

        utils::ensure_dir_exists(Path::new(KSU_BACKUP_DIR))?;
        println!("- Backing up vendor_boot before rmvr");
        let temporary = target.with_extension(format!("img.tmp.{}", std::process::id()));
        if temporary.exists() {
            std::fs::remove_file(&temporary)
                .with_context(|| format!("remove stale backup {}", temporary.display()))?;
        }
        let backup_result = (|| -> Result<()> {
            let mut target_file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            let mut source = OpenOptions::new().read(true).open(image)?;
            let copied = std::io::copy(&mut source, &mut target_file)
                .with_context(|| format!("backup vendor_boot to {}", temporary.display()))?;
            target_file.sync_all()?;
            ensure!(
                target_file.metadata()?.len() == copied,
                "vendor_boot backup length changed while writing"
            );
            drop(target_file);
            ensure!(
                calculate_sha1(&temporary)? == sha1,
                "vendor_boot backup verification failed"
            );
            std::fs::rename(&temporary, &target).with_context(|| {
                format!("atomically install vendor_boot backup {}", target.display())
            })?;
            File::open(KSU_BACKUP_DIR)?.sync_all()?;
            Ok(())
        })();
        if backup_result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        backup_result?;
        println!("- Vendor_boot backup: {}", target.display());
        Ok(target)
    }

    pub(super) fn flash_partition(partition: &str, data: &[u8]) -> Result<()> {
        let mut blk = std::fs::OpenOptions::new()
            .write(true)
            .truncate(false)
            .create(false)
            .open(partition)
            .with_context(|| format!("open {partition}"))?;
        unsafe {
            const BLKROSET: i32 = libc::_IO(0x12, 93);
            let mut val: libc::c_int = 0;
            if libc::ioctl(blk.as_raw_fd(), BLKROSET, &raw mut val) != 0 {
                bail!("Failed to set rw for {partition}: {}", *libc::__errno());
            }
        }
        blk.write_all(data).context("flash boot failed")?;
        blk.sync_all().context("sync boot failed")?;
        Ok(())
    }

    pub fn choose_boot_partition(
        kmi: &str,
        is_replace_kernel: bool,
        partition: &Option<String>,
    ) -> String {
        let slot_suffix = get_slot_suffix(false);
        let skip_init_boot = kmi.starts_with("android12-");
        let init_boot_exist =
            Path::new(&format!("/dev/block/by-name/init_boot{slot_suffix}")).exists();

        // if specific partition is specified, use it
        if let Some(part) = partition {
            return match part.as_str() {
                "boot" | "init_boot" | "vendor_boot" => part.clone(),
                _ => "boot".to_string(),
            };
        }

        // if init_boot exists and not skipping it, use it
        if !is_replace_kernel && init_boot_exist && !skip_init_boot {
            return "init_boot".to_string();
        }

        "boot".to_string()
    }

    pub fn get_slot_suffix(ota: bool) -> String {
        let mut slot_suffix = utils::getprop("ro.boot.slot_suffix").unwrap_or_default();
        if !slot_suffix.is_empty() && ota {
            if slot_suffix == "_a" {
                slot_suffix = "_b".to_string();
            } else {
                slot_suffix = "_a".to_string();
            }
        }
        slot_suffix
    }

    pub fn list_available_partitions() -> Vec<String> {
        let slot_suffix = get_slot_suffix(false);
        let candidates = vec!["boot", "init_boot", "vendor_boot"];
        candidates
            .into_iter()
            .filter(|name| Path::new(&format!("/dev/block/by-name/{name}{slot_suffix}")).exists())
            .map(ToString::to_string)
            .collect()
    }

    pub(super) fn auto_boot_partition_path(
        kmi: &str,
        ota: bool,
        is_replace_kernel: bool,
        partition: &Option<String>,
    ) -> PathBuf {
        let slot_suffix = get_slot_suffix(ota);
        let name = choose_boot_partition(kmi, is_replace_kernel, partition);
        PathBuf::from(format!("/dev/block/by-name/{name}{slot_suffix}"))
    }

    pub(super) fn post_ota() -> Result<()> {
        use crate::assets::BOOTCTL_PATH;
        use crate::defs::ADB_DIR;
        let status = Command::new(BOOTCTL_PATH).arg("hal-info").status()?;
        if !status.success() {
            return Ok(());
        }

        let current_slot = Command::new(BOOTCTL_PATH)
            .arg("get-current-slot")
            .output()?
            .stdout;
        let current_slot = String::from_utf8(current_slot)?;
        let current_slot = current_slot.trim();
        let target_slot = i32::from(current_slot == "0");

        Command::new(BOOTCTL_PATH)
            .arg(format!("set-active-boot-slot {target_slot}"))
            .status()?;

        let post_fs_data = Path::new(ADB_DIR).join("post-fs-data.d");
        utils::ensure_dir_exists(&post_fs_data)?;
        let post_ota_sh = post_fs_data.join("post_ota.sh");

        let sh_content = format!(
            r"
{BOOTCTL_PATH} mark-boot-successful
rm -f {BOOTCTL_PATH}
rm -f /data/adb/post-fs-data.d/post_ota.sh
"
        );

        std::fs::write(&post_ota_sh, sh_content)?;
        std::fs::set_permissions(post_ota_sh, std::fs::Permissions::from_mode(0o755))?;

        Ok(())
    }
}

#[cfg(target_os = "android")]
pub use android::*;

fn map_file(file: &Path) -> Result<Mmap> {
    let mut f = File::open(file).with_context(|| format!("open {}", file.display()))?;
    let len = f
        .seek(SeekFrom::End(0))
        .with_context(|| format!("seek end of {}", file.display()))? as usize;
    let mmap = unsafe { MmapOptions::new().len(len).map(&f)? };
    Ok(mmap)
}

pub fn parse_kmi(buffer: &[u8]) -> Result<String> {
    let re = Regex::new(r"(\d+\.\d+)(?:\S+)?(android\d+)").context("Failed to compile regex")?;
    buffer
        .windows(4)
        .enumerate()
        .filter(|(_, x)| {
            x[1] == b'.'
                && x[2].is_ascii_digit()
                && match x[0] {
                    b'5' => x[3].is_ascii_digit(),
                    b'6'..=b'9' => true,
                    _ => false,
                }
        })
        .find_map(|(i, _)| {
            let a = &buffer[i..buffer.len().min(i + 100)];
            if let Some(e) = a.iter().position(|c| *c == 0)
                && let Ok(s) = std::str::from_utf8(&a[..e])
                && let Some(caps) = re.captures(s)
                && let (Some(kernel_version), Some(android_version)) = (caps.get(1), caps.get(2))
            {
                Some(format!(
                    "{}-{}",
                    android_version.as_str(),
                    kernel_version.as_str()
                ))
            } else {
                None
            }
        })
        .ok_or_else(|| {
            println!("- Failed to get KMI version");
            anyhow!("Try to choose LKM manually")
        })
}

fn parse_kmi_from_kernel(kernel: &Path) -> Result<String> {
    let data = std::fs::read(kernel).context("Failed to read kernel file")?;
    parse_kmi(&data)
}

fn parse_kmi_from_boot(image: &Path) -> Result<String> {
    let data = map_file(image)?;
    let boot = BootImage::parse(&data)?;
    if let Some(kernel) = boot.get_blocks().get_kernel() {
        let mut output = Vec::<u8>::new();
        kernel.dump(&mut output, false)?;
        parse_kmi(&output)
    } else {
        bail!("no kernel found in boot image")
    }
}

/// For vendor boot, prefer the `init_boot` ramdisk entry over the one with empty name,
/// matching the original magiskboot lookup order (init_boot.cpio before ramdisk.cpio).
fn extract_ramdisk(ramdisk_image: &RamdiskImage) -> Result<(Cpio, Option<usize>)> {
    if ramdisk_image.is_vendor_ramdisk() {
        let (pos, target) = ramdisk_image
            .iter_vendor_ramdisk()
            .enumerate()
            .find(|e| e.1.get_name_raw() == b"init_boot")
            .or_else(|| {
                ramdisk_image
                    .iter_vendor_ramdisk()
                    .enumerate()
                    .find(|e| e.1.get_name_raw() == b"")
            })
            .ok_or_else(|| anyhow!("No suitable vendor ramdisk entry found"))?;
        let mut buf = Vec::<u8>::new();
        target.dump(&mut buf, false)?;
        Ok((Cpio::load_from_data(&buf)?, Some(pos)))
    } else {
        let mut buf = Vec::<u8>::new();
        ramdisk_image.dump(&mut buf, false)?;
        Ok((Cpio::load_from_data(&buf)?, None))
    }
}

fn enforce_bootimage_version(boot: &BootImage<'_>) -> Result<()> {
    if let BootImageVersion::Android(ver) = boot.get_header().get_version()
        && ver < 3
    {
        bail!("bootimage version {ver} is not supported!")
    }
    Ok(())
}

const DEFAULT_VENDOR_RMVR_MODULES: [&str; 2] = ["vr", "vklp"];

#[derive(Debug, Default, Eq, PartialEq)]
struct VendorModuleCleanupReport {
    removed_modules: usize,
    updated_indexes: usize,
}

impl VendorModuleCleanupReport {
    fn changed(&self) -> bool {
        self.removed_modules > 0 || self.updated_indexes > 0
    }

    fn merge(&mut self, other: Self) {
        self.removed_modules += other.removed_modules;
        self.updated_indexes += other.updated_indexes;
    }
}

fn is_vendor_boot_version(version: BootImageVersion) -> bool {
    matches!(version, BootImageVersion::Vendor(_))
}

fn strip_module_compression_suffix(name: &str) -> &str {
    [".gz", ".xz", ".zst", ".lz4"]
        .into_iter()
        .find_map(|suffix| name.strip_suffix(suffix))
        .unwrap_or(name)
}

fn normalize_module_stem(value: &str, require_ko_suffix: bool) -> Option<String> {
    let value = value.trim().trim_matches(|c| matches!(c, ':' | ','));
    let basename = value.rsplit('/').next().unwrap_or(value);
    let basename = strip_module_compression_suffix(basename);
    let stem = if let Some(stem) = basename.strip_suffix(".ko") {
        stem
    } else if require_ko_suffix {
        return None;
    } else {
        basename
    };

    (!stem.is_empty()).then(|| stem.replace('-', "_").to_ascii_lowercase())
}

fn is_target_module_reference(value: &str, targets: &BTreeSet<String>) -> bool {
    normalize_module_stem(value, false).is_some_and(|stem| targets.contains(&stem))
}

fn normalized_cpio_path(path: &str) -> &str {
    let mut normalized = path.trim_start_matches('/');
    while let Some(stripped) = normalized.strip_prefix("./") {
        normalized = stripped;
    }
    normalized
}

fn is_target_module_path(path: &str, targets: &BTreeSet<String>) -> bool {
    let path = normalized_cpio_path(path);
    path.starts_with("lib/modules/")
        && normalize_module_stem(path, true).is_some_and(|stem| targets.contains(&stem))
}

fn rewrite_module_index_line(
    index_name: &str,
    line: &str,
    targets: &BTreeSet<String>,
) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Some(line.to_string());
    }

    let (content, comment) = line
        .split_once('#')
        .map_or((line, None), |(content, comment)| (content, Some(comment)));
    let tokens = content.split_whitespace().collect::<Vec<_>>();

    let attach_comment = |mut rebuilt: String| {
        if let Some(comment) = comment {
            if !rebuilt.is_empty() && !rebuilt.ends_with(' ') {
                rebuilt.push(' ');
            }
            rebuilt.push('#');
            rebuilt.push_str(comment);
        }
        rebuilt
    };

    match index_name {
        "modules.dep" => {
            let Some((module, dependencies)) = content.split_once(':') else {
                return Some(line.to_string());
            };
            if is_target_module_reference(module, targets) {
                return None;
            }

            let kept = dependencies
                .split_whitespace()
                .filter(|dependency| !is_target_module_reference(dependency, targets))
                .collect::<Vec<_>>();
            let rebuilt = if kept.is_empty() {
                format!("{}:", module.trim_end())
            } else {
                format!("{}: {}", module.trim_end(), kept.join(" "))
            };
            Some(attach_comment(rebuilt))
        }
        "modules.softdep" => {
            if tokens.len() >= 2 && is_target_module_reference(tokens[1], targets) {
                return None;
            }
            let rebuilt = tokens
                .into_iter()
                .filter(|token| {
                    matches!(*token, "softdep" | "pre:" | "post:")
                        || !is_target_module_reference(token, targets)
                })
                .collect::<Vec<_>>()
                .join(" ");
            Some(attach_comment(rebuilt))
        }
        "modules.alias" => {
            if tokens.first() == Some(&"alias")
                && tokens
                    .last()
                    .is_some_and(|module| is_target_module_reference(module, targets))
            {
                None
            } else {
                Some(line.to_string())
            }
        }
        "modules.options" | "modules.blocklist" => {
            if tokens.len() >= 2 && is_target_module_reference(tokens[1], targets) {
                None
            } else {
                Some(line.to_string())
            }
        }
        name if name == "modules.load"
            || name.starts_with("modules.load.")
            || name == "modules.order" =>
        {
            if tokens
                .first()
                .is_some_and(|module| is_target_module_reference(module, targets))
            {
                None
            } else {
                Some(line.to_string())
            }
        }
        _ => Some(line.to_string()),
    }
}

fn rewrite_module_index(
    index_path: &str,
    data: &[u8],
    targets: &BTreeSet<String>,
) -> Result<Option<Vec<u8>>> {
    let index_name = index_path.rsplit('/').next().unwrap_or(index_path);
    let text = std::str::from_utf8(data)
        .with_context(|| format!("{index_path} is not a UTF-8 module index"))?;
    let trailing_newline = text.ends_with('\n');
    let mut changed = false;
    let mut output = Vec::new();

    for line in text.lines() {
        match rewrite_module_index_line(index_name, line.trim_end_matches('\r'), targets) {
            Some(rebuilt) => {
                changed |= rebuilt != line;
                output.push(rebuilt);
            }
            None => changed = true,
        }
    }

    if !changed {
        return Ok(None);
    }

    let mut rebuilt = output.join("\n");
    if trailing_newline && !rebuilt.is_empty() {
        rebuilt.push('\n');
    }
    Ok(Some(rebuilt.into_bytes()))
}

fn is_supported_module_index(path: &str) -> bool {
    let path = normalized_cpio_path(path);
    if !path.starts_with("lib/modules/") {
        return false;
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    matches!(
        name,
        "modules.dep"
            | "modules.softdep"
            | "modules.alias"
            | "modules.options"
            | "modules.blocklist"
            | "modules.load"
            | "modules.order"
    ) || name.starts_with("modules.load.")
}

fn remove_vendor_modules(cpio: &mut Cpio) -> Result<VendorModuleCleanupReport> {
    let targets = DEFAULT_VENDOR_RMVR_MODULES
        .into_iter()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let paths = cpio.entries().keys().cloned().collect::<Vec<_>>();
    let mut report = VendorModuleCleanupReport::default();

    for path in paths
        .iter()
        .filter(|path| is_target_module_path(path, &targets))
    {
        ensure!(
            path.as_str() == normalized_cpio_path(path),
            "unsupported non-canonical CPIO path: {path}"
        );
        println!("- Removing vendor module {path}");
        cpio.rm(path, false);
        report.removed_modules += 1;
    }

    for index_path in paths.iter().filter(|path| is_supported_module_index(path)) {
        ensure!(
            index_path.as_str() == normalized_cpio_path(index_path),
            "unsupported non-canonical CPIO path: {index_path}"
        );
        let data = cpio
            .entry_by_name(index_path)
            .and_then(CpioEntry::data)
            .unwrap_or_default()
            .to_vec();
        let Some(rebuilt) = rewrite_module_index(index_path, &data, &targets)? else {
            continue;
        };

        println!("- Cleaning vendor module references in {index_path}");
        cpio.rm(index_path, false);
        cpio.add(index_path, CpioEntry::regular(0o644, Box::new(rebuilt)))?;
        report.updated_indexes += 1;
    }

    Ok(report)
}

fn remove_modules_from_vendor_boot(boot_image: &BootImage<'_>) -> Result<Option<Vec<u8>>> {
    ensure!(
        is_vendor_boot_version(boot_image.get_header().get_version()),
        "rmvr only accepts a vendor_boot image"
    );
    let ramdisk = boot_image
        .get_blocks()
        .get_ramdisk()
        .context("vendor_boot image has no ramdisk")?;
    let mut patcher = BootImagePatchOption::new(boot_image);
    let mut total = VendorModuleCleanupReport::default();

    if ramdisk.is_vendor_ramdisk() {
        for (index, fragment) in ramdisk.iter_vendor_ramdisk().enumerate() {
            let name = fragment.get_name().unwrap_or("<invalid-name>");
            let mut data = Vec::new();
            fragment
                .dump(&mut data, false)
                .with_context(|| format!("unpack vendor ramdisk fragment {index} ({name})"))?;
            let mut cpio = Cpio::load_from_data(&data)
                .with_context(|| format!("parse vendor ramdisk fragment {index} ({name})"))?;
            let report = remove_vendor_modules(&mut cpio)?;
            if report.changed() {
                let mut rebuilt = Vec::new();
                cpio.dump(&mut rebuilt)?;
                patcher.replace_vendor_ramdisk(index, Box::new(Cursor::new(rebuilt)), false);
            }
            total.merge(report);
        }
    } else {
        let mut data = Vec::new();
        ramdisk.dump(&mut data, false)?;
        let mut cpio = Cpio::load_from_data(&data).context("parse vendor_boot ramdisk")?;
        let report = remove_vendor_modules(&mut cpio)?;
        if report.changed() {
            let mut rebuilt = Vec::new();
            cpio.dump(&mut rebuilt)?;
            patcher.replace_ramdisk(Box::new(Cursor::new(rebuilt)), false);
        }
        total.merge(report);
    }

    if !total.changed() {
        println!("- No vr/vklp modules or index references found; image is unchanged");
        return Ok(None);
    }

    println!(
        "- Removed {} module file(s) and updated {} module index file(s)",
        total.removed_modules, total.updated_indexes
    );
    let mut output = Cursor::new(Vec::new());
    patcher.patch(&mut output)?;
    Ok(Some(output.into_inner()))
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn classify_boot_image(image: &PathBuf) -> Result<&'static str> {
    let image_data = map_file(image)?;
    let boot_image = BootImage::parse(&image_data)?;
    Ok(match boot_image.get_header().get_version() {
        BootImageVersion::Vendor(_) => "vendor_boot",
        BootImageVersion::Android(_) if boot_image.get_blocks().get_kernel().is_some() => "boot",
        BootImageVersion::Android(_) => "init_boot",
    })
}

#[derive(clap::Args, Debug)]
pub struct VendorBootRmvrArgs {
    /// vendor_boot image path; when omitted on Android, use the current slot vendor_boot
    #[arg(short, long)]
    pub boot: Option<PathBuf>,

    /// use the other slot when the image path is omitted
    #[cfg(target_os = "android")]
    #[arg(short = 'u', long, default_value = "false")]
    pub ota: bool,

    /// flash the cleaned image back to vendor_boot
    #[cfg(target_os = "android")]
    #[arg(short, long, default_value = "false")]
    pub flash: bool,

    /// output directory
    #[arg(short, long, default_value = None)]
    pub out: Option<PathBuf>,

    /// output file name
    #[arg(long, default_value = None)]
    pub out_name: Option<String>,

    /// accepted for Manager partition routing; only vendor_boot is valid
    #[cfg(target_os = "android")]
    #[arg(long, default_value = None)]
    pub partition: Option<String>,
}

pub fn patch_rmvr(args: VendorBootRmvrArgs) -> Result<()> {
    let inner = move || {
        let VendorBootRmvrArgs {
            boot: image,
            out,
            out_name,
            #[cfg(target_os = "android")]
            ota,
            #[cfg(target_os = "android")]
            flash,
            #[cfg(target_os = "android")]
            partition,
        } = args;

        println!(include_str!("./android/banner"));
        println!("- Mode: vendor_boot rmvr (vr.ko and vklp.ko)");

        #[cfg(target_os = "android")]
        let image_supplied = image.is_some();
        let boot_image_file = if let Some(image) = image {
            ensure!(image.exists(), "vendor_boot image not found");
            std::fs::canonicalize(image)?
        } else {
            #[cfg(target_os = "android")]
            {
                if let Some(partition) = partition {
                    ensure!(
                        partition == "vendor_boot",
                        "rmvr can only target the vendor_boot partition"
                    );
                }
                let slot_suffix = get_slot_suffix(ota);
                PathBuf::from(format!("/dev/block/by-name/vendor_boot{slot_suffix}"))
            }
            #[cfg(not(target_os = "android"))]
            {
                bail!("Please specify a vendor_boot image");
            }
        };

        #[cfg(target_os = "android")]
        println!("- Bootdevice: {}", boot_image_file.display());
        println!("- Parsing vendor_boot image");

        let boot_image_data = map_file(&boot_image_file)?;
        let boot_image = BootImage::parse(&boot_image_data)?;
        ensure!(
            is_vendor_boot_version(boot_image.get_header().get_version()),
            "rmvr rejected a non-vendor_boot image"
        );

        let patched = remove_modules_from_vendor_boot(&boot_image)?;
        let changed = patched.is_some();
        let new_boot_bytes = patched.unwrap_or_else(|| boot_image_data.to_vec());

        println!("- SAKISU_RMVR_CHANGED={}", u8::from(changed));

        drop(boot_image);
        drop(boot_image_data);

        #[cfg(target_os = "android")]
        if flash {
            if changed {
                let backup = backup_vendor_boot(&boot_image_file)?;
                println!("- Restore source if needed: {}", backup.display());
                println!("- Flashing cleaned vendor_boot image");
                flash_partition(&boot_image_file.display().to_string(), &new_boot_bytes)?;
            } else {
                println!("- Skipping flash because vendor_boot did not need cleanup");
            }
        }

        #[cfg(target_os = "android")]
        let should_write_output = image_supplied || !flash || out_name.is_some() || out.is_some();
        #[cfg(not(target_os = "android"))]
        let should_write_output = true;

        if should_write_output {
            let output_dir = out.unwrap_or(std::env::current_dir()?);
            let name = out_name.unwrap_or_else(|| {
                let now = chrono::Utc::now();
                format!("sukisu_rmvr_{}.img", now.format("%Y%m%d_%H%M%S"))
            });
            let output_image = output_dir.join(name);
            std::fs::write(&output_image, &new_boot_bytes)
                .context("write cleaned vendor_boot image")?;
            println!("- Output file is written to");
            println!("- {}", output_image.display().to_string().trim_matches('"'));
        }

        println!("- Done!");
        Ok(())
    };

    let result = inner();
    if let Err(ref error) = result {
        println!("- rmvr Error: {error}");
    }
    result
}

#[allow(clippy::struct_excessive_bools)]
#[derive(clap::Args, Debug)]
pub struct BootPatchArgs {
    /// boot image path, if not specified, will try to find the boot image automatically
    #[arg(short, long)]
    pub boot: Option<PathBuf>,

    /// kernel image path to replace
    #[arg(short, long)]
    pub kernel: Option<PathBuf>,

    /// LKM module path to replace, if not specified, will use the builtin one
    #[arg(short, long)]
    pub module: Option<PathBuf>,

    /// init to be replaced
    #[arg(short, long)]
    pub init: Option<PathBuf>,

    /// will use another slot when boot image is not specified
    #[cfg(target_os = "android")]
    #[arg(short = 'u', long, default_value = "false")]
    pub ota: bool,

    /// Flash it to boot partition after patch
    #[cfg(target_os = "android")]
    #[arg(short, long, default_value = "false")]
    pub flash: bool,

    /// Force backup source image as stock image
    #[cfg(target_os = "android")]
    #[arg(long, default_value = "false")]
    pub backup: bool,

    /// Output path. If not specified, will use current directory.
    /// If specified, the boot image will be written to the directory
    /// even if --flash is specified.
    #[cfg(target_os = "android")]
    #[arg(short, long, default_value = None)]
    pub out: Option<PathBuf>,

    /// Output path. If not specified, will use current directory.
    #[cfg(not(target_os = "android"))]
    #[arg(short, long, default_value = None)]
    pub out: Option<PathBuf>,

    /// KMI version, if specified, will use the specified KMI
    #[arg(long, default_value = None)]
    pub kmi: Option<String>,

    /// target partition override (init_boot | boot | vendor_boot)
    #[cfg(target_os = "android")]
    #[arg(long, default_value = None)]
    pub partition: Option<String>,

    /// File name of the output. If specified, the boot image will be
    /// written to the output directory even if --flash is specified.
    #[cfg(target_os = "android")]
    #[arg(long, default_value = None)]
    pub out_name: Option<String>,

    /// File name of the output.
    #[cfg(not(target_os = "android"))]
    #[arg(long, default_value = None)]
    pub out_name: Option<String>,

    /// Extra cmdline to append to boot image header
    #[arg(long, default_value = None)]
    pub cmdline: Option<String>,

    /// Always allow shell to get root permission
    #[arg(long, default_value = "false")]
    allow_shell: bool,

    /// Kernel release string passed to kernelsu.ko as spoof_release
    #[arg(long, default_value = None)]
    spoof_release: Option<String>,

    /// Kernel version string passed to kernelsu.ko as spoof_version
    #[arg(long, default_value = None)]
    spoof_version: Option<String>,

    /// Force enable adbd and disable adbd auth
    #[arg(long, default_value = "false")]
    enable_adbd: bool,

    /// Add more adb_debug prop
    #[arg(long, required = false)]
    adb_debug_prop: Option<String>,

    /// Do not (re-)install kernelsu, only modify configs (allow_shell, etc.)
    #[arg(long, default_value = "false")]
    no_install: bool,

    /// Do not load custom rc
    #[arg(long, default_value = "false")]
    no_custom_rc: bool,

    #[cfg(not(target_os = "android"))]
    #[arg(long, default_value = "aarch64")]
    arch: String,

    /// Patching ramdisk instead of boot image. This is used for AVD ramdisk
    #[arg(long, default_value = "false")]
    ramdisk: bool,
}

pub fn patch(args: BootPatchArgs) -> Result<()> {
    let inner = move || {
        let BootPatchArgs {
            boot: image,
            init,
            kernel,
            module: kmod,
            out,
            kmi,
            out_name,
            cmdline,
            allow_shell,
            spoof_release,
            spoof_version,
            enable_adbd,
            adb_debug_prop,
            no_install,
            #[cfg(target_os = "android")]
            ota,
            #[cfg(target_os = "android")]
            flash,
            #[cfg(target_os = "android")]
            backup,
            #[cfg(target_os = "android")]
            partition,
            no_custom_rc,
            #[cfg(not(target_os = "android"))]
            arch,
            ramdisk,
        } = args;

        println!(include_str!("banner"));

        #[cfg(target_os = "android")]
        let patch_file = image.is_some();

        #[cfg(target_os = "android")]
        if !patch_file {
            ensure_gki_kernel()?;
        }

        let is_replace_kernel = kernel.is_some();

        if ramdisk && is_replace_kernel {
            bail!("incompatiable option: --ramdisk and --kernel")
        }

        #[cfg(target_os = "android")]
        if ramdisk && flash {
            bail!("incompatiable option: --ramdisk and --flash")
        }

        if is_replace_kernel {
            ensure!(
                init.is_none() && kmod.is_none(),
                "init and module must not be specified."
            );
        }

        // None means --no-install: preserve the marker for the existing LKM.
        let bundled_lkm = (!no_install).then_some(kmod.is_none());

        let kmi = kmi.map_or_else(
            || -> Result<_> {
                if kmod.is_some() || (no_install && image.is_some()) {
                    return Ok(String::new());
                }
                #[cfg(target_os = "android")]
                if ota {
                    let slot_suffix = get_slot_suffix(true);
                    println!("- Trying to auto detect KMI version from boot");
                    return parse_kmi_from_boot(Path::new(&format!(
                        "/dev/block/by-name/boot{slot_suffix}"
                    )));
                }
                #[cfg(target_os = "android")]
                match get_current_kmi() {
                    Ok(value) => {
                        return Ok(value);
                    }
                    Err(e) => {
                        println!("- {e}");
                    }
                }
                Ok(if ramdisk {
                    bail!("please specify kmi manually")
                } else if let Some(image_path) = &image {
                    println!(
                        "- Trying to auto detect KMI version for {}",
                        image_path.display()
                    );
                    parse_kmi_from_boot(image_path)?
                } else if let Some(kernel_path) = &kernel {
                    println!(
                        "- Trying to auto detect KMI version for {}",
                        kernel_path.display()
                    );
                    parse_kmi_from_kernel(kernel_path)?
                } else {
                    String::new()
                })
            },
            Ok,
        )?;

        let boot_image_file = if let Some(image) = image {
            ensure!(image.exists(), "boot image not found");
            std::fs::canonicalize(image)?
        } else {
            #[cfg(target_os = "android")]
            {
                auto_boot_partition_path(&kmi, ota, is_replace_kernel, &partition)
            }
            #[cfg(not(target_os = "android"))]
            {
                bail!("Please specify a boot image");
            }
        };

        #[cfg(target_os = "android")]
        println!("- Bootdevice: {}", boot_image_file.display());

        // try extract bootctl/busybox
        #[cfg(target_os = "android")]
        let _ = assets::ensure_binaries(false);

        println!("- Preparing assets");
        println!("- Unpacking boot image");
        let boot_image_data = map_file(&boot_image_file)?;
        let boot_image = if ramdisk {
            BootImage::parse_raw_ramdisk(&boot_image_data)?
        } else {
            BootImage::parse(&boot_image_data)?
        };
        enforce_bootimage_version(&boot_image)?;
        ensure!(
            !is_vendor_boot_version(boot_image.get_header().get_version()),
            "vendor_boot must be handled by boot-patch-rmvr"
        );

        let mut patcher = BootImagePatchOption::new(&boot_image);

        if let Some(cmdline_value) = &cmdline {
            patcher.override_cmdline(cmdline_value.as_bytes());
            println!("- Set cmdline to: {cmdline_value}");
        }

        if let Some(kernel_path) = kernel {
            println!("- Adding Kernel");
            let kernel_data = map_file(&kernel_path)?;
            patcher.replace_kernel(Box::new(Cursor::new(kernel_data)), false);
        }

        let kernelsu_ko: Box<dyn AsRef<[u8]>> = if no_install {
            Box::new(Vec::<u8>::new())
        } else if let Some(kmod_path) = kmod {
            Box::new(map_file(&kmod_path)?)
        } else {
            #[cfg(target_os = "android")]
            {
                println!("- KMI: {kmi}");
                let name = format!("{kmi}_kernelsu.ko");
                assets::get_asset(&name).with_context(|| format!("Failed to load {name}"))?
            }
            #[cfg(not(target_os = "android"))]
            {
                println!("- KMI: {kmi}");
                println!("- Arch: {arch}");
                let name = format!("{arch}/{kmi}_kernelsu.ko");
                assets::get_asset(&name).with_context(|| format!("Failed to load {name}"))?
            }
        };

        let ksu_init: Box<dyn AsRef<[u8]>> = if no_install {
            Box::new(Vec::<u8>::new())
        } else if let Some(init_path) = init {
            Box::new(map_file(&init_path)?)
        } else {
            #[cfg(not(target_os = "android"))]
            {
                assets::get_asset(&format!("{arch}/ksuinit")).context("Failed to load ksuinit")?
            }
            #[cfg(target_os = "android")]
            {
                assets::get_asset("ksuinit").context("Failed to load ksuinit")?
            }
        };

        let (mut cpio, vendor_ramdisk_idx) =
            if let Some(ramdisk_image) = boot_image.get_blocks().get_ramdisk() {
                extract_ramdisk(ramdisk_image)?
            } else {
                println!("- No ramdisk, create by default");
                (Cpio::new(), None)
            };

        if !no_install {
            ensure!(
                !cpio.is_magisk_patched(),
                "Cannot work with Magisk patched image"
            );

            println!("- Adding KernelSU LKM");
            let is_kernelsu_patched = cpio.exists("kernelsu.ko");

            if !is_kernelsu_patched && cpio.exists("init") {
                cpio.mv("init", "init.real")?;
            }

            cpio.add("init", CpioEntry::regular(0o755, ksu_init))?;
            cpio.add("kernelsu.ko", CpioEntry::regular(0o755, kernelsu_ko))?;

            #[cfg(target_os = "android")]
            if (backup || (!is_kernelsu_patched && flash))
                && let Err(e) = do_backup(&mut cpio, &boot_image_file)
            {
                println!("- Backup stock image failed: {e:?}");
            }
        }

        let mut ksu_config: Vec<String> = cpio
            .entry_by_name("ksu_config")
            .and_then(CpioEntry::data)
            .and_then(|v| str::from_utf8(v).ok())
            .map(|v| {
                v.split(' ')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();

        let mut apply_config = |name: &str, value: &str, add: bool| {
            let has_value = ksu_config.iter().any(|v| v == value);

            if add {
                println!("- Adding {name} config");
                if !has_value {
                    ksu_config.push(value.to_owned());
                }
            } else if has_value {
                println!("- Removing {name} config");
                ksu_config.retain(|v| v != value);
            }
        };

        apply_config("no custom rc", "norc=1", no_custom_rc);
        apply_config("allow shell", "allow_shell=1", allow_shell);
        if let Some(bundled) = bundled_lkm {
            apply_config("bundled LKM", "bundled=1", bundled);
        }

        let mut apply_spoof_config = |key: &str, value: Option<&str>| {
            ksu_config.retain(|x| !x.starts_with(&format!("{key}=")));
            if let Some(v) = value {
                let v = v.trim();
                if v.is_empty() {
                    println!("- Removing {key} config");
                } else {
                    println!("- Adding {key} config");
                    let config_str = format!(
                        "{}=\"{}\"",
                        key,
                        v.replace('\\', "\\\\").replace('"', "\\\"")
                    );
                    ksu_config.push(config_str);
                }
            } else {
                println!("- Removing {key} config");
            }
        };

        apply_spoof_config("spoof_release", spoof_release.as_deref());
        apply_spoof_config("spoof_version", spoof_version.as_deref());

        if ksu_config.is_empty() {
            cpio.rm("ksu_config", false);
        } else {
            let data = ksu_config.join(" ").into_bytes();
            println!("- ksu_config content: {:?}", String::from_utf8_lossy(&data));
            cpio.add("ksu_config", CpioEntry::regular(0o644, Box::new(data)))?;
        }

        // remove legacy config files
        cpio.rm("allow_shell", false);
        cpio.rm("ksu_spoof_release", false);
        cpio.rm("ksu_spoof_version", false);

        if enable_adbd || adb_debug_prop.is_some() {
            println!("- Adding adb_debug props");
            cpio.add(
                "force_debuggable",
                CpioEntry::regular(0o644, Box::new(Vec::<u8>::new())),
            )?;

            let mut prop = Vec::<u8>::new();
            if enable_adbd {
                println!("- Adding props to enable adbd");
                prop.extend_from_slice(
                    b"ro.debuggable=1\nro.force.debuggable=1\nro.adb.secure=0\n",
                );
            }
            if let Some(extra) = adb_debug_prop {
                println!("- Adding custom props");
                prop.extend_from_slice(extra.as_bytes());
            }
            cpio.add("adb_debug.prop", CpioEntry::regular(0o644, Box::new(prop)))?;
        } else {
            if cpio.exists("force_debuggable") {
                println!("- Removing /force_debuggable");
                cpio.rm("force_debuggable", false);
            }
            if cpio.exists("adb_debug.prop") {
                println!("- Removing /adb_debug.prop");
                cpio.rm("adb_debug.prop", false);
            }
        }

        let mut new_cpio = Vec::<u8>::new();
        cpio.dump(&mut new_cpio)?;

        if let Some(idx) = vendor_ramdisk_idx {
            patcher.replace_vendor_ramdisk(idx, Box::new(Cursor::new(new_cpio)), false);
        } else {
            patcher.replace_ramdisk(Box::new(Cursor::new(new_cpio)), false);
        }

        println!("- Repacking boot image");
        let mut new_boot_buf = Cursor::new(Vec::<u8>::with_capacity(boot_image.get_size()));
        patcher.patch(&mut new_boot_buf)?;
        let new_boot_bytes = new_boot_buf.into_inner();

        // Free the source mmap so the boot partition is no longer mapped read-only,
        // otherwise some kernels reject the subsequent write.
        drop(boot_image);
        drop(boot_image_data);

        #[cfg(target_os = "android")]
        if flash {
            println!("- Flashing new boot image");
            let bootdevice = boot_image_file.display().to_string();
            flash_partition(&bootdevice, &new_boot_bytes)?;
            if ota {
                post_ota()?;
            }
        }

        #[cfg(target_os = "android")]
        let should_write_output = patch_file || !flash || out_name.is_some() || out.is_some();
        #[cfg(not(target_os = "android"))]
        let should_write_output = true;

        if should_write_output {
            let output_dir = out.unwrap_or(std::env::current_dir()?);
            let name = out_name.unwrap_or_else(|| {
                let now = chrono::Utc::now();
                format!("kernelsu_patched_{}.img", now.format("%Y%m%d_%H%M%S"))
            });
            let output_image = output_dir.join(name);
            std::fs::write(&output_image, &new_boot_bytes).context("write out new boot failed")?;
            println!("- Output file is written to");
            println!("- {}", output_image.display().to_string().trim_matches('"'));
        }

        println!("- Done!");
        Ok(())
    };

    let result = inner();
    if let Err(ref e) = result {
        println!("- Patch Error: {e}");
    }
    result
}

#[derive(clap::Args, Debug)]
pub struct BootRestoreArgs {
    /// boot image path, if not specified, will try to find the boot image automatically
    #[arg(short, long)]
    pub boot: Option<PathBuf>,

    /// Flash it to boot partition after restore
    #[cfg(target_os = "android")]
    #[arg(short, long, default_value = "false")]
    pub flash: bool,

    /// Output path. If not specified, will use current directory.
    /// If specified, the boot image will be written to the directory
    /// even if --flash is specified.
    #[cfg(target_os = "android")]
    #[arg(short, long, default_value = None)]
    pub out: Option<PathBuf>,

    /// Output path. If not specified, will use current directory.
    #[cfg(not(target_os = "android"))]
    #[arg(short, long, default_value = None)]
    pub out: Option<PathBuf>,

    /// File name of the output. If specified, the boot image will be
    /// written to the output directory even if --flash is specified.
    #[cfg(target_os = "android")]
    #[arg(long, default_value = None)]
    pub out_name: Option<String>,

    /// File name of the output.
    #[cfg(not(target_os = "android"))]
    #[arg(long, default_value = None)]
    pub out_name: Option<String>,
}

pub fn restore(args: BootRestoreArgs) -> Result<()> {
    let BootRestoreArgs {
        boot: image,
        out_name,
        out,
        #[cfg(target_os = "android")]
        flash,
    } = args;

    #[cfg(target_os = "android")]
    let kmi = get_current_kmi().unwrap_or_default();

    #[cfg(target_os = "android")]
    let image_supplied = image.is_some();

    let boot_image_file = if let Some(image) = image {
        ensure!(image.exists(), "boot image not found");
        std::fs::canonicalize(image)?
    } else {
        #[cfg(target_os = "android")]
        {
            auto_boot_partition_path(&kmi, false, false, &None)
        }
        #[cfg(not(target_os = "android"))]
        {
            bail!("Please specify a boot image");
        }
    };

    #[cfg(target_os = "android")]
    println!("- Bootdevice: {}", boot_image_file.display());

    println!("- Unpacking boot image");
    let bootimage_data = map_file(&boot_image_file)?;
    let boot_image = BootImage::parse(&bootimage_data)?;
    enforce_bootimage_version(&boot_image)?;

    let (mut cpio, vendor_ramdisk_idx) =
        if let Some(ramdisk_image) = boot_image.get_blocks().get_ramdisk() {
            extract_ramdisk(ramdisk_image)?
        } else {
            bail!("No compatible ramdisk found.")
        };

    ensure!(
        cpio.exists("kernelsu.ko"),
        "boot image is not patched by KernelSU"
    );

    #[cfg(target_os = "android")]
    let mut stock_boot: Option<PathBuf> = None;

    #[cfg(target_os = "android")]
    if let Some(backup_file) = cpio.entry_by_name(BACKUP_FILENAME) {
        let sha = String::from_utf8(backup_file.data().unwrap_or_default().to_vec())?;
        let sha = sha.trim();
        let backup_path =
            PathBuf::from(KSU_BACKUP_DIR).join(format!("{KSU_BACKUP_FILE_PREFIX}{sha}"));
        if backup_path.is_file() {
            println!("- Using backup file {}", backup_path.display());
            stock_boot = Some(backup_path);
        } else {
            println!("- Warning: no backup {} found!", backup_path.display());
        }
        if let Err(e) = clean_backup(sha) {
            println!("- Warning: Cleanup backup image failed: {e}");
        }
    } else {
        println!("- Backup info is absent!");
    }

    #[cfg(target_os = "android")]
    let mut stock_source: Option<PathBuf> = None;

    let new_boot_bytes: Vec<u8> = {
        #[cfg(target_os = "android")]
        {
            if let Some(stock_path) = stock_boot {
                let bytes = std::fs::read(&stock_path)
                    .with_context(|| format!("read stock boot {}", stock_path.display()))?;
                stock_source = Some(stock_path);
                bytes
            } else {
                rebuild_without_ksu(&boot_image, &mut cpio, vendor_ramdisk_idx)?
            }
        }
        #[cfg(not(target_os = "android"))]
        {
            rebuild_without_ksu(&boot_image, &mut cpio, vendor_ramdisk_idx)?
        }
    };

    drop(boot_image);
    drop(bootimage_data);

    #[cfg(target_os = "android")]
    if flash {
        if let Some(ref source) = stock_source {
            println!("- Flashing new boot image from {}", source.display());
        } else {
            println!("- Flashing new boot image");
        }
        let bootdevice = boot_image_file.display().to_string();
        flash_partition(&bootdevice, &new_boot_bytes)?;
    }

    #[cfg(target_os = "android")]
    let should_write_output = image_supplied || !flash || out_name.is_some() || out.is_some();
    #[cfg(not(target_os = "android"))]
    let should_write_output = true;

    if should_write_output {
        let output_dir = out.unwrap_or(std::env::current_dir()?);
        let name = out_name.unwrap_or_else(|| {
            let now = chrono::Utc::now();
            format!("kernelsu_restore_{}.img", now.format("%Y%m%d_%H%M%S"))
        });
        let output_image = output_dir.join(name);
        std::fs::write(&output_image, &new_boot_bytes).context("copy out new boot failed")?;
        println!("- Output file is written to");
        println!("- {}", output_image.display().to_string().trim_matches('"'));
    }

    println!("- Done!");
    Ok(())
}

fn rebuild_without_ksu(
    boot_image: &BootImage<'_>,
    cpio: &mut Cpio,
    vendor_ramdisk_idx: Option<usize>,
) -> Result<Vec<u8>> {
    println!("- Removing KernelSU from boot image");
    cpio.rm("kernelsu.ko", false);
    if cpio.exists("init.real") {
        cpio.mv("init.real", "init")?;
    }

    let mut new_cpio = Vec::<u8>::new();
    cpio.dump(&mut new_cpio)?;

    println!("- Repacking boot image");
    let mut patcher = BootImagePatchOption::new(boot_image);
    if let Some(idx) = vendor_ramdisk_idx {
        patcher.replace_vendor_ramdisk(idx, Box::new(Cursor::new(new_cpio)), false);
    } else {
        patcher.replace_ramdisk(Box::new(Cursor::new(new_cpio)), false);
    }

    let mut buf = Cursor::new(Vec::<u8>::with_capacity(boot_image.get_size()));
    patcher.patch(&mut buf)?;
    Ok(buf.into_inner())
}

pub fn read_ksu_config() -> Result<Vec<String>> {
    #[cfg(target_os = "android")]
    {
        let boot_image_file = auto_boot_partition_path("", false, false, &None);
        let bootimage_data = map_file(&boot_image_file)?;
        let boot_image = BootImage::parse(&bootimage_data)?;

        let (cpio, _) = if let Some(ramdisk_image) = boot_image.get_blocks().get_ramdisk() {
            extract_ramdisk(ramdisk_image)?
        } else {
            bail!("No compatible ramdisk found.")
        };

        let config = cpio
            .entry_by_name("ksu_config")
            .and_then(CpioEntry::data)
            .and_then(|v| str::from_utf8(v).ok())
            .map(|v| {
                v.split(' ')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(std::string::ToString::to_string)
                    .collect()
            })
            .unwrap_or_default();

        Ok(config)
    }

    #[cfg(not(target_os = "android"))]
    {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add_file(cpio: &mut Cpio, path: &str, data: &[u8]) {
        cpio.add(path, CpioEntry::regular(0o644, Box::new(data.to_vec())))
            .unwrap();
    }

    fn read_text<'a>(cpio: &'a Cpio, path: &str) -> &'a str {
        std::str::from_utf8(
            cpio.entry_by_name(path)
                .and_then(CpioEntry::data)
                .unwrap_or_default(),
        )
        .unwrap()
    }

    #[test]
    fn removes_vr_and_vklp_without_touching_similar_modules() {
        let mut cpio = Cpio::new();
        add_file(&mut cpio, "lib/modules/vr.ko", b"vr");
        add_file(&mut cpio, "lib/modules/6.6-gki/vendor/vklp.ko.zst", b"vklp");
        add_file(&mut cpio, "lib/modules/myvr.ko", b"keep");
        add_file(&mut cpio, "lib/modules/vklpx.ko", b"keep");
        add_file(
            &mut cpio,
            "lib/modules/modules.load",
            b"vr.ko\nmyvr.ko\nvklpx.ko\n",
        );
        add_file(
            &mut cpio,
            "lib/modules/modules.dep",
            b"lib/modules/vr.ko:\nlib/modules/foo.ko: lib/modules/vr.ko lib/modules/bar.ko\nlib/modules/myvr.ko:\n",
        );
        add_file(
            &mut cpio,
            "lib/modules/modules.softdep",
            b"softdep vr pre: helper\nsoftdep foo pre: vklp vklpx post: bar\n",
        );
        add_file(
            &mut cpio,
            "lib/modules/6.6-gki/modules.load.recovery",
            b"vendor/vklp.ko.zst\nmyvr.ko\n",
        );
        add_file(
            &mut cpio,
            "lib/modules/modules.alias",
            b"alias test vr\nalias test2 myvr\n",
        );
        add_file(
            &mut cpio,
            "lib/modules/modules.options",
            b"options vklp enabled=1\noptions vklpx enabled=1\n",
        );

        let report = remove_vendor_modules(&mut cpio).unwrap();

        assert_eq!(report.removed_modules, 2);
        assert_eq!(report.updated_indexes, 6);
        assert!(!cpio.exists("lib/modules/vr.ko"));
        assert!(!cpio.exists("lib/modules/6.6-gki/vendor/vklp.ko.zst"));
        assert!(cpio.exists("lib/modules/myvr.ko"));
        assert!(cpio.exists("lib/modules/vklpx.ko"));
        assert_eq!(
            read_text(&cpio, "lib/modules/modules.load"),
            "myvr.ko\nvklpx.ko\n"
        );
        assert_eq!(
            read_text(&cpio, "lib/modules/modules.dep"),
            "lib/modules/foo.ko: lib/modules/bar.ko\nlib/modules/myvr.ko:\n"
        );
        assert_eq!(
            read_text(&cpio, "lib/modules/modules.softdep"),
            "softdep foo pre: vklpx post: bar\n"
        );
        assert_eq!(
            read_text(&cpio, "lib/modules/6.6-gki/modules.load.recovery"),
            "myvr.ko\n"
        );
        assert_eq!(
            read_text(&cpio, "lib/modules/modules.alias"),
            "alias test2 myvr\n"
        );
        assert_eq!(
            read_text(&cpio, "lib/modules/modules.options"),
            "options vklpx enabled=1\n"
        );
    }

    #[test]
    fn cleanup_without_matches_is_byte_stable() {
        let mut cpio = Cpio::new();
        add_file(&mut cpio, "lib/modules/myvr.ko", b"keep");
        add_file(
            &mut cpio,
            "lib/modules/modules.load",
            b"# keep this comment\n\nmyvr.ko\n",
        );
        let mut before = Vec::new();
        cpio.dump(&mut before).unwrap();

        let report = remove_vendor_modules(&mut cpio).unwrap();
        let mut after = Vec::new();
        cpio.dump(&mut after).unwrap();

        assert_eq!(report, VendorModuleCleanupReport::default());
        assert_eq!(before, after);
    }

    #[test]
    fn vendor_boot_gate_uses_header_version_only() {
        assert!(is_vendor_boot_version(BootImageVersion::Vendor(3)));
        assert!(is_vendor_boot_version(BootImageVersion::Vendor(4)));
        assert!(!is_vendor_boot_version(BootImageVersion::Android(4)));
    }
}
