//! Best-effort userspace leases. These are NOT enforced on the kernel's grant path.
use anyhow::{Context, Result, bail};
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::{fs::OpenOptionsExt, process::CommandExt};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::{ksu_uapi as uapi, ksucalls};

const DIR: &str = "/data/adb/ksu/temporary-root";
const STATE: &str = "/data/adb/ksu/temporary-root/leases.conf";

#[derive(Debug, PartialEq, Eq)]
struct Lease {
    uid: i32,
    key: String,
    manager: u32,
    boot: String,
    deadline: Option<u64>,
}

fn boot_id() -> Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned())
}

fn boottime() -> Result<u64> {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut ts) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(ts.tv_sec as u64)
}

fn lock(name: &str, nonblocking: bool) -> Result<File> {
    fs::create_dir_all(DIR)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(format!("{DIR}/{name}"))?;
    let flags = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    if unsafe { libc::flock(file.as_raw_fd(), flags) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(file)
}

const HEADER: &str = "SUKISU_TEMPORARY_ROOT_V1";

fn encode(leases: &[Lease]) -> Result<String> {
    use std::fmt::Write;
    let mut text = format!("{HEADER}\n");
    for lease in leases {
        if lease.key.is_empty()
            || lease.key.len() >= 256
            || lease.key.chars().any(char::is_control)
            || lease.boot.is_empty()
            || !lease
                .boot
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'-')
        {
            bail!("invalid lease key or boot ID");
        }
        let deadline = lease
            .deadline
            .map_or_else(|| "boot".to_owned(), |end| end.to_string());
        writeln!(
            text,
            "{}\t{}\t{}\t{}\t{}",
            lease.uid, lease.manager, lease.boot, deadline, lease.key
        )?;
    }
    Ok(text)
}

fn decode(text: &str) -> Result<Vec<Lease>> {
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        bail!("unsupported temporary root state format");
    }
    let mut leases = Vec::new();
    let mut uids = std::collections::HashSet::new();
    for line in lines {
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 5 {
            bail!("invalid temporary root record");
        }
        let uid: i32 = fields[0].parse()?;
        let manager: u32 = fields[1].parse()?;
        if uid < 2000 || uid == manager as i32 || !uids.insert(uid) {
            bail!("invalid or duplicate temporary root UID");
        }
        leases.push(Lease {
            uid,
            manager,
            boot: fields[2].to_owned(),
            key: fields[4].to_owned(),
            deadline: if fields[3] == "boot" {
                None
            } else {
                Some(fields[3].parse()?)
            },
        });
    }
    // Apply the same field validation on both reads and writes.
    encode(&leases)?;
    Ok(leases)
}

fn load() -> Result<Vec<Lease>> {
    match fs::read(STATE) {
        Ok(bytes) => decode(std::str::from_utf8(&bytes)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

fn save(leases: &[Lease]) -> Result<()> {
    use std::io::Write;
    let path = format!("{STATE}.tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(encode(leases)?.as_bytes())?;
    file.sync_all()?;
    fs::rename(path, STATE)?;
    File::open(DIR)?.sync_all()?;
    Ok(())
}

// Run identity changes in a short-lived, single-threaded child. The setresuid
// kernel hook installs an additional driver fd; exiting closes that fd as well
// as any future identity-hook resources without accumulating them in watch().
fn as_manager(uid: u32, op: impl FnOnce() -> Result<()>) -> Result<()> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if pid == 0 {
        ksucalls::get_version();
        let result = if unsafe { libc::setresuid(uid, 0, 0) } == 0 {
            op()
        } else {
            Err(std::io::Error::last_os_error().into())
        };
        if let Err(e) = &result {
            log::error!("temporary root manager operation failed: {e:#}");
        }
        unsafe { libc::_exit(i32::from(result.is_err())) };
    }
    let mut status = 0;
    loop {
        if unsafe { libc::waitpid(pid, &raw mut status, 0) } >= 0 {
            break;
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e.into());
        }
    }
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        bail!("temporary root manager operation failed");
    }
    Ok(())
}

fn profile(uid: i32) -> Result<uapi::app_profile> {
    let mut cmd: uapi::ksu_get_app_profile_cmd = unsafe { std::mem::zeroed() };
    cmd.profile.curr_uid = uid;
    ksucalls::ksuctl(uapi::KSU_IOCTL_GET_APP_PROFILE, &raw mut cmd)?;
    Ok(cmd.profile)
}

#[allow(clippy::unnecessary_cast)] // c_char is signed on some supported architectures.
fn key_matches(profile: &uapi::app_profile, key: &str) -> bool {
    let bytes: Vec<u8> = profile
        .key
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    bytes == key.as_bytes()
}

pub fn set(uid: i32, key: String, manager: u32, seconds: u64) -> Result<()> {
    if unsafe { libc::getuid() } != 0 || uid < 2000 || uid == manager as i32 || seconds > 604_800 {
        bail!("invalid temporary root lease or caller");
    }
    // Validate permission and current package identity before persisting anything.
    as_manager(manager, || {
        let p = profile(uid)?;
        if !key_matches(&p, &key) {
            bail!("profile identity changed");
        }
        Ok(())
    })?;
    let guard = lock("state.lock", false)?;
    let mut leases = load()?;
    leases.retain(|lease| lease.uid != uid);
    leases.push(Lease {
        uid,
        key,
        manager,
        boot: boot_id()?,
        deadline: if seconds == 0 {
            None
        } else {
            Some(boottime()? + seconds)
        },
    });
    save(&leases)?;
    drop(guard);
    start()
}

pub fn clear(uid: i32) -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        bail!("root required");
    }
    let _guard = lock("state.lock", false)?;
    let mut leases = load()?;
    leases.retain(|lease| lease.uid != uid);
    save(&leases)
}

pub fn status(uid: i32) -> Result<()> {
    let _guard = lock("state.lock", false)?;
    if let Some(lease) = load()?.iter().find(|lease| lease.uid == uid) {
        println!(
            "{}",
            if lease.deadline.is_some() {
                "timed"
            } else {
                "boot"
            }
        );
    } else {
        println!("permanent");
    }
    Ok(())
}

fn expired(lease_boot: &str, boot: &str, deadline: Option<u64>, now: u64) -> bool {
    lease_boot != boot || deadline.is_some_and(|end| now >= end)
}

fn sweep() -> Result<()> {
    let _guard = lock("state.lock", false)?;
    let mut leases = load()?;
    let boot = boot_id()?;
    let now = boottime()?;
    let mut changed = false;
    leases.retain(|lease| {
        if !expired(&lease.boot, &boot, lease.deadline, now) {
            return true;
        }
        let result = as_manager(lease.manager, || {
            let mut p = profile(lease.uid)?;
            // Do not alter another package that has since reused this UID.
            if !key_matches(&p, &lease.key) || !p.allow_su {
                return Ok(());
            }
            p.allow_su = false;
            // Root/non-root configurations share a union: reset it, not reinterpret it.
            p.__bindgen_anon_1 = unsafe { std::mem::zeroed() };
            p.__bindgen_anon_1.nrp_config.use_default = true;
            let mut cmd = uapi::ksu_set_app_profile_cmd { profile: p };
            ksucalls::ksuctl(uapi::KSU_IOCTL_SET_APP_PROFILE, &raw mut cmd)?;
            Ok(())
        });
        match result {
            Ok(()) => {
                changed = true;
                false
            }
            Err(e) => {
                log::error!(
                    "temporary root revoke uid {} failed; retrying: {e:#}",
                    lease.uid
                );
                true
            }
        }
    });
    if changed {
        save(&leases)?;
    }
    Ok(())
}

pub fn start() -> Result<()> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["temporary-root", "watch"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn().context("start temporary root watcher")?;
    Ok(())
}

pub fn watch() -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        bail!("root required");
    }
    crate::utils::switch_cgroups();
    // A file lock, not a PID file, prevents duplicate workers and stale PID reuse.
    let _worker = match lock("watch.lock", true) {
        Ok(lock) => lock,
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock) =>
        {
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    loop {
        if let Err(e) = sweep() {
            log::error!("temporary root sweep failed: {e:#}");
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests {
    use super::{HEADER, Lease, decode, encode, expired};

    #[test]
    fn text_roundtrip() {
        let leases = vec![
            Lease {
                uid: 10001,
                manager: 10002,
                key: "com.example.tool".into(),
                boot: "abcd-1234".into(),
                deadline: Some(600),
            },
            Lease {
                uid: 110_001,
                manager: 10002,
                key: "com.example.other".into(),
                boot: "abcd-1234".into(),
                deadline: None,
            },
        ];
        assert_eq!(decode(&encode(&leases).unwrap()).unwrap(), leases);
        assert!(decode(&format!("{HEADER}\n")).unwrap().is_empty());
    }

    #[test]
    fn reject_corrupt_state() {
        assert!(decode("").is_err());
        assert!(decode("SUKISU_TEMPORARY_ROOT_V2\n").is_err());
        assert!(
            decode(&format!(
                "{HEADER}\n10001\t10002\tabcd\tinvalid\tcom.example"
            ))
            .is_err()
        );
        let record = "10001\t10002\tabcd\tboot\tcom.example\n";
        assert!(decode(&format!("{HEADER}\n{record}{record}")).is_err());
        assert!(decode(&format!("{HEADER}\n10001\t10002\tabcd\tboot\tbad\tkey")).is_err());
    }

    #[test]
    fn lease_boundaries() {
        assert!(!expired("a", "a", Some(600), 599));
        assert!(expired("a", "a", Some(600), 600));
        assert!(expired("a", "b", Some(600), 1));
        assert!(!expired("a", "a", None, u64::MAX));
        assert!(expired("a", "b", None, 0));
    }
}

// JSON mirrors the Manager's serializable Profile; rules are managed separately.
// These independent flags are part of the existing wire format, not a state machine.
#[allow(clippy::struct_excessive_bools)]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileInput {
    name: String,
    current_uid: i32,
    allow_su: bool,
    root_use_default: bool,
    root_template: Option<String>,
    uid: i32,
    gid: i32,
    groups: Vec<i32>,
    capabilities: Vec<u32>,
    context: String,
    namespace: i32,
    non_root_use_default: bool,
    umount_modules: bool,
    flags: i64,
}

#[allow(clippy::unnecessary_cast)]
fn copy_text(destination: &mut [libc::c_char], text: &str) -> Result<()> {
    if text.len() >= destination.len() || text.as_bytes().contains(&0) {
        bail!("invalid profile string");
    }
    for (dst, src) in destination.iter_mut().zip(text.bytes()) {
        *dst = src as libc::c_char;
    }
    Ok(())
}

fn to_profile(input: &ProfileInput) -> Result<uapi::app_profile> {
    let mut p: uapi::app_profile = unsafe { std::mem::zeroed() };
    p.version = uapi::KSU_APP_PROFILE_VER;
    p.curr_uid = input.current_uid;
    p.allow_su = input.allow_su;
    copy_text(&mut p.key, &input.name)?;
    if input.allow_su {
        let rp = unsafe { &mut p.__bindgen_anon_1.rp_config };
        rp.use_default = input.root_use_default;
        copy_text(
            &mut rp.template_name,
            input.root_template.as_deref().unwrap_or(""),
        )?;
        rp.profile.uid = input.uid;
        rp.profile.gid = input.gid;
        if input.groups.len() > rp.profile.groups.len()
            || input.capabilities.iter().any(|c| *c >= 64)
        {
            bail!("invalid groups or capabilities");
        }
        rp.profile.groups_count = input.groups.len() as u32;
        rp.profile.groups[..input.groups.len()].copy_from_slice(&input.groups);
        rp.profile.capabilities.effective = input
            .capabilities
            .iter()
            .fold(0, |bits, c| bits | (1u64 << c));
        copy_text(&mut rp.profile.selinux_domain, &input.context)?;
        rp.profile.namespaces = input.namespace;
        rp.profile.flags = input.flags as u64;
    } else {
        p.__bindgen_anon_1.nrp_config.use_default = input.non_root_use_default;
        p.__bindgen_anon_1.nrp_config.profile.umount_modules = input.umount_modules;
    }
    Ok(p)
}

/// Serialize every editor write with expiration. A lease is persisted before a
/// grant, and only removed after a successful permanent grant or revocation.
pub fn apply(manager: u32, mode: &str, expected_root: bool, json: &str) -> Result<()> {
    if unsafe { libc::getuid() } != 0 {
        bail!("root required");
    }
    let input: ProfileInput = serde_json::from_str(json)?;
    let p = to_profile(&input)?;
    if p.curr_uid < 0 || (p.allow_su && p.curr_uid < 2000 && p.curr_uid != 1000) {
        bail!("invalid profile UID");
    }
    let seconds = match mode {
        "keep" | "permanent" => None,
        value => {
            let seconds: u64 = value.parse()?;
            if p.curr_uid < 2000 || p.curr_uid == manager as i32 || seconds > 604_800 {
                bail!("invalid temporary root lease");
            }
            Some(seconds)
        }
    };
    let _guard = lock("state.lock", false)?;
    let mut leases = load()?;
    let boot = boot_id()?;
    let now = boottime()?;
    // Reject stale editors even if the watcher has not swept the deadline yet.
    if p.allow_su
        && expected_root
        && leases.iter().any(|lease| {
            lease.uid == p.curr_uid && expired(&lease.boot, &boot, lease.deadline, now)
        })
    {
        bail!("temporary root lease expired; reload before granting again");
    }
    // Validate the current state under the same lock as the eventual write.
    as_manager(manager, || {
        if p.allow_su && expected_root {
            let current = profile(p.curr_uid)?;
            if !current.allow_su || !key_matches(&current, &input.name) {
                bail!("profile changed; reload before granting again");
            }
        }
        Ok(())
    })?;
    if p.allow_su
        && let Some(seconds) = seconds
    {
        leases.retain(|lease| lease.uid != p.curr_uid);
        leases.push(Lease {
            uid: p.curr_uid,
            key: input.name,
            manager,
            boot,
            deadline: if seconds == 0 {
                None
            } else {
                Some(now + seconds)
            },
        });
        save(&leases)?;
        // Spawn before writing allow_su. Failure must never leave a grant
        // without a worker. The worker blocks on our state lock.
        start()?;
    }
    as_manager(manager, || {
        let mut cmd = uapi::ksu_set_app_profile_cmd { profile: p };
        ksucalls::ksuctl(uapi::KSU_IOCTL_SET_APP_PROFILE, &raw mut cmd)?;
        Ok(())
    })?;
    if !p.allow_su || mode == "permanent" {
        leases.retain(|lease| lease.uid != p.curr_uid);
        save(&leases)?;
    }
    Ok(())
}

#[cfg(test)]
mod apply_tests {
    use super::{ProfileInput, copy_text, to_profile};

    fn input() -> ProfileInput {
        serde_json::from_value(serde_json::json!({
            "name": "com.example.tool",
            "currentUid": 10001,
            "allowSu": true,
            "rootUseDefault": false,
            "rootTemplate": null,
            "uid": 0,
            "gid": 0,
            "groups": [0, 1000],
            "capabilities": [0, 63],
            "context": "u:r:ksu:s0",
            "namespace": 1,
            "nonRootUseDefault": false,
            "umountModules": true,
            "rules": "",
            "flags": 1
        }))
        .unwrap()
    }

    #[test]
    fn manager_profile_roundtrip() {
        let input = input();
        let p = to_profile(&input).unwrap();
        assert_eq!(p.curr_uid, 10001);
        assert!(p.allow_su);
        assert!(super::key_matches(&p, &input.name));
        let rp = unsafe { p.__bindgen_anon_1.rp_config };
        assert!(!rp.use_default);
        assert_eq!(rp.profile.groups_count, 2);
        assert_eq!(&rp.profile.groups[..2], &[0, 1000]);
        assert_eq!(rp.profile.capabilities.effective, 1 | (1u64 << 63));
        assert_eq!(rp.profile.flags, 1);
    }

    #[test]
    fn non_root_profile_uses_non_root_union() {
        let mut input = input();
        input.allow_su = false;
        let p = to_profile(&input).unwrap();
        let nrp = unsafe { p.__bindgen_anon_1.nrp_config };
        assert!(!p.allow_su);
        assert!(!nrp.use_default);
        assert!(nrp.profile.umount_modules);
    }

    #[test]
    fn reject_invalid_profile_fields() {
        let mut input = input();
        input.groups = vec![0; 33];
        assert!(to_profile(&input).is_err());
        input.groups.clear();
        input.capabilities = vec![64];
        assert!(to_profile(&input).is_err());
        let mut dst = [0; 4];
        assert!(copy_text(&mut dst, "abcd").is_err());
        assert!(copy_text(&mut dst, "a\0b").is_err());
        assert!(copy_text(&mut dst, "abc").is_ok());
        assert_eq!(dst[3], 0);
    }
}
