//! Userspace command for the SusFS sus_path UID filter.
//!
//! The filter is an allow-list: when it is set, only the listed app UIDs can
//! see the paths registered through `add_sus_path`; every other process with
//! uid >= 10000 is hidden from them. An empty list is sent as `","`, which the
//! kernel parses into an empty bitmap and restores the default "hide from all
//! apps" behaviour.

use anyhow::Result;

use crate::susfs::abi::consts::{
    CMD_SUSFS_SET_SUS_PATH_UID_FILTER, ERR_CMD_NOT_SUPPORTED, SUSFS_APP_STR_BUF_SIZE,
};
use crate::susfs::abi::{SusfsSusPathUidFilter, send};

fn alloc_sus_path_uid_filter() -> Box<SusfsSusPathUidFilter> {
    let mut payload = Box::<SusfsSusPathUidFilter>::new_uninit();
    // SAFETY: the allocation is correctly aligned and zero is valid for every
    // field (a byte array and an i32). Initialize in place to avoid a 64 KiB
    // temporary on the stack, including in unoptimized builds.
    unsafe {
        std::ptr::write_bytes(
            payload.as_mut_ptr().cast::<u8>(),
            0,
            std::mem::size_of::<SusfsSusPathUidFilter>(),
        );
        payload.assume_init()
    }
}

/// Replace the sus_path UID filter with a comma-separated package list.
///
/// The kernel resolves package names to Android application UIDs from
/// `/data/system/packages.list`, validates their supported range and
/// atomically replaces the current allow-list.
pub fn set_sus_path_uid_filter(package_names: &str) -> Result<()> {
    let normalized = package_names
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>()
        .join(",");
    // The kernel rejects an empty buffer but tolerates empty comma-separated
    // entries. A comma therefore replaces the bitmap with an empty bitmap.
    let normalized = if normalized.is_empty() {
        ",".to_string()
    } else {
        normalized
    };
    for name in normalized.split(',').filter(|name| !name.is_empty()) {
        anyhow::ensure!(
            name.len() <= 255
                && name != "."
                && name != ".."
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_'),
            "invalid package name: {name}"
        );
    }

    let bytes = normalized.as_bytes();
    if bytes.len() >= SUSFS_APP_STR_BUF_SIZE {
        anyhow::bail!(
            "package list is too long ({} bytes, maximum {})",
            bytes.len(),
            SUSFS_APP_STR_BUF_SIZE - 1
        );
    }

    let mut payload = alloc_sus_path_uid_filter();
    payload.err = ERR_CMD_NOT_SUPPORTED;
    payload.app_strings[..bytes.len()].copy_from_slice(bytes);

    send(
        CMD_SUSFS_SET_SUS_PATH_UID_FILTER,
        payload.as_mut(),
        "set_sus_path_uid_filter",
    )?;
    anyhow::ensure!(
        payload.err != ERR_CMD_NOT_SUPPORTED,
        "sus_path UID filter is not supported by the running SuSFS kernel"
    );
    Ok(())
}
