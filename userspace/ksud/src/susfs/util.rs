//! Cross-command utilities.
//!
//! Helpers shared by more than one command in `cmd/`. Kept at the root of
//! `susfs/` because they don't depend on anything command-specific.

use std::fs::Metadata;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::susfs::abi::{SusfsKstat, SUSFS_MAX_PATHNAME};

/// Resolve `path` to an absolute, symlink-free path.
///
/// Equivalent to `realpath(3)` in the C source.
pub(crate) fn canonicalize(path: &str) -> Result<PathBuf> {
    std::path::Path::new(path)
        .canonicalize()
        .with_context(|| format!("failed to get realpath from path: '{path}'"))
}

/// Read the entire contents of `path` into a `Vec<u8>`.
pub(crate) fn read_file(path: &Path) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("error opening file: '{}'", path.display()))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .with_context(|| format!("reading error from file: '{}'", path.display()))?;
    Ok(buf)
}

/// Write `path` into a fixed-size C string buffer, returning `Err` if the
/// path doesn't fit.
///
/// Used by every command whose payload struct carries a `target_pathname` /
/// `redirected_pathname` field.
pub(crate) fn copy_path_into(buf: &mut [u8; SUSFS_MAX_PATHNAME], path: &str) -> Result<()> {
    let bytes = path.as_bytes();
    if bytes.len() >= buf.len() {
        anyhow::bail!("path too long ({} bytes, max {})", bytes.len(), buf.len() - 1);
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(())
}

/// Populate the `spoofed_*` fields of a `SusfsKstat` from a `stat(2)`
/// result. Mirrors `copy_from_stat_to_sus_kstat` in `sus_kstat.c`.
pub(crate) fn copy_metadata_into_kstat(kstat: &mut SusfsKstat, md: &Metadata) {
    kstat.target_ino = md.ino();
    kstat.spoofed_ino = md.ino();
    kstat.spoofed_dev = md.dev();
    kstat.spoofed_nlink = md.nlink() as u32;
    kstat.spoofed_size = md.size();
    kstat.spoofed_atime_tv_sec = md.atime();
    kstat.spoofed_atime_tv_nsec = md.atime_nsec() as u64;
    kstat.spoofed_mtime_tv_sec = md.mtime();
    kstat.spoofed_mtime_tv_nsec = md.mtime_nsec() as u64;
    kstat.spoofed_ctime_tv_sec = md.ctime();
    kstat.spoofed_ctime_tv_nsec = md.ctime_nsec() as u64;
    kstat.spoofed_blocks = md.blocks();
    kstat.spoofed_blksize = md.blksize() as i64;
}

/// Convert a `[u8; N]` buffer that may or may not be NUL-terminated into a
/// UTF-8 `String`, falling back to `"<invalid>"` when the bytes are not
/// valid UTF-8.
pub(crate) fn cstr_buf_to_string(buf: &[u8]) -> String {
    let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..nul].to_vec()).unwrap_or_else(|_| "<invalid>".to_string())
}
