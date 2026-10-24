//! Best-effort userspace leases. These are NOT enforced on the kernel's grant path.
use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{fs::PermissionsExt, process::CommandExt};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::{ksu_uapi as uapi, ksucalls};

const DIR: &str = "/data/adb/ksu/temporary-root";
const STATE: &str = "leases.conf";
const KEY_FILE: &str = "state.key";
const MAGIC_1: u32 = 0x5355_4b49;
const MAGIC_2: u32 = 0x5452_4c53;
const FORMAT_VERSION: u32 = 2;
const NONCE_LEN: usize = 24;
const MAX_STATE_SIZE: u64 = 16 * 1024 * 1024;

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

// Walk from / using directory fds: O_NOFOLLOW on just the final path would
// still allow symlinked ancestors. All later operations are relative to this fd.
fn state_dir() -> Result<File> {
    if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 {
        bail!("root required");
    }
    let mut dir = File::open("/")?;
    for part in DIR.split('/').filter(|part| !part.is_empty()) {
        let name = CString::new(part)?;
        if part == "temporary-root" {
            let ret = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) };
            if ret != 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        dir = unsafe { File::from_raw_fd(fd) };
        let meta = dir.metadata()?;
        // Android/vendor filesystems may expose inherited ownership and modes.
        // Require directory type, but do not make metadata a feature gate.
        if !meta.is_dir() {
            bail!("temporary root path component is not a directory");
        }
    }
    // Try to keep state private, but do not fail lease/profile operations on
    // vendor filesystems that reject chmod or report inherited mode bits.
    if let Err(e) = dir.set_permissions(fs::Permissions::from_mode(0o700)) {
        log::warn!("set temporary root directory mode failed: {e}");
    }
    Ok(dir)
}

fn secure_open(dir: &File, name: &str, flags: i32) -> Result<File> {
    let name = CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // Keep the least restrictive useful check: an opened state object must be
    // a regular file. Do not reject vendor-specific owner, GID, mode, link count
    // or symlink layouts; access is still performed by the root ksud process.
    let file = unsafe { File::from_raw_fd(fd) };
    if !file.metadata()?.is_file() {
        bail!("temporary root state object is not a regular file");
    }
    Ok(file)
}

fn not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

fn random_bytes(bytes: &mut [u8]) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let count = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                bytes[offset..].as_mut_ptr(),
                bytes.len() - offset,
                0,
            )
        };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if count == 0 {
            bail!("random source returned no bytes");
        }
        offset += count as usize;
    }
    Ok(())
}

// Caller holds state.lock. Never regenerate a missing key for existing ciphertext.
fn state_key(dir: &File, create: bool) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    match secure_open(dir, KEY_FILE, libc::O_RDONLY) {
        Ok(mut file) => {
            if file.metadata()?.len() != key.len() as u64 {
                bail!("invalid temporary root key length");
            }
            file.read_exact(&mut key)?;
        }
        Err(e) if not_found(&e) && create => {
            random_bytes(&mut key)?;
            atomic_write(dir, KEY_FILE, &key)?;
        }
        Err(e) => return Err(e.context("read temporary root encryption key")),
    }
    Ok(key)
}

fn atomic_write(dir: &File, name: &str, bytes: &[u8]) -> Result<()> {
    // Reject an existing symlink or non-regular object, but allow vendor-specific
    // ownership, mode and hard-link metadata.
    match secure_open(dir, name, libc::O_RDONLY) {
        Ok(_) => {}
        Err(e) if not_found(&e) => {}
        Err(e) => return Err(e),
    }
    let mut random = [0u8; 16];
    random_bytes(&mut random)?;
    let temporary = format!(".{name}.{:032x}.tmp", u128::from_le_bytes(random));
    let mut file = secure_open(
        dir,
        &temporary,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )?;
    let source = CString::new(temporary)?;
    let destination = CString::new(name)?;
    let result = (|| -> Result<()> {
        if let Err(e) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
            log::warn!("set temporary root file mode failed: {e}");
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        if unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                source.as_ptr(),
                dir.as_raw_fd(),
                destination.as_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        dir.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(dir.as_raw_fd(), source.as_ptr(), 0);
        }
    }
    result
}

fn lock(name: &str, nonblocking: bool) -> Result<File> {
    let dir = state_dir()?;
    let file = secure_open(&dir, name, libc::O_CREAT | libc::O_RDWR)?;
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

fn envelope_header() -> Vec<u8> {
    [MAGIC_1, MAGIC_2, FORMAT_VERSION]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect()
}

fn seal(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8>> {
    let header = envelope_header();
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypt temporary root state failed"))?;
    let mut output = header;
    output.extend_from_slice(nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn unseal(bytes: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let header = envelope_header();
    let offset = header.len() + NONCE_LEN;
    if bytes.len() < offset + 16 || !bytes.starts_with(&header) {
        bail!("invalid encrypted temporary root state header");
    }
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(&bytes[header.len()..offset]),
            Payload {
                msg: &bytes[offset..],
                aad: &header,
            },
        )
        .map_err(|_| anyhow::anyhow!("temporary root state authentication failed"))
}

fn load() -> Result<Vec<Lease>> {
    let dir = state_dir()?;
    let mut file = match secure_open(&dir, STATE, libc::O_RDONLY) {
        Ok(file) => file,
        Err(e) if not_found(&e) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    if file.metadata()?.len() > MAX_STATE_SIZE {
        bail!("temporary root state too large");
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_STATE_SIZE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATE_SIZE {
        bail!("temporary root state too large");
    }
    // One-time migration only when no encryption key exists. Once provisioned,
    // never accept plaintext again (including after an authentication failure).
    if bytes.starts_with(HEADER.as_bytes()) {
        match secure_open(&dir, KEY_FILE, libc::O_RDONLY) {
            Err(e) if not_found(&e) => {}
            _ => bail!("refusing plaintext state after encryption was provisioned"),
        }
        let leases = decode(std::str::from_utf8(&bytes)?)?;
        save(&leases)?;
        return Ok(leases);
    }
    let plaintext = unseal(&bytes, &state_key(&dir, false)?)?;
    decode(std::str::from_utf8(&plaintext)?)
}

fn save(leases: &[Lease]) -> Result<()> {
    let plaintext = encode(leases)?;
    if plaintext.len() as u64 > MAX_STATE_SIZE - 64 {
        bail!("temporary root state too large");
    }
    let dir = state_dir()?;
    let key = state_key(&dir, true)?;
    let mut nonce = [0u8; NONCE_LEN];
    random_bytes(&mut nonce)?;
    atomic_write(&dir, STATE, &seal(plaintext.as_bytes(), &key, &nonce)?)
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
