// SPDX-License-Identifier: GPL-2.0
//
// sukisu-fs userspace controller
//
// Talks to the kernel via four ioctls on the KSU supercall fd:
//   - SUKISU_FS_MOUNT  : layer sukisu-fs on an existing directory
//   - SUKISU_FS_UMOUNT : remove the layer
//   - SUKISU_FS_RULE   : add / remove / clear visibility rules
//   - SUKISU_FS_LIST   : enumerate rules
//
// This file is the implementation; the CLI plumbing lives in cli.rs.

use anyhow::{Context, Result, anyhow, bail};

use crate::ksu_uapi;

const VIEW_HIDE: u32 = 0;
const VIEW_SHOW: u32 = 1;

pub fn mount(source: &str, target: &str) -> Result<()> {
    let mut cmd = ksu_sukisu_fs_mount_cmd {
        source: zeroed_path(),
        target: zeroed_path(),
    };
    copy_path(&mut cmd.source, source)?;
    copy_path(&mut cmd.target, target)?;

    crate::ksucalls::ksuctl(ksu_uapi::KSU_IOCTL_SUKISU_FS_MOUNT, &raw mut cmd)
        .map_err(|e| anyhow!("sukisu_fs mount failed: {e}"))?;
    Ok(())
}

pub fn umount(target: &str) -> Result<()> {
    let mut cmd = ksu_sukisu_fs_mount_cmd {
        source: zeroed_path(),
        target: zeroed_path(),
    };
    copy_path(&mut cmd.target, target)?;

    crate::ksucalls::ksuctl(ksu_uapi::KSU_IOCTL_SUKISU_FS_UMOUNT, &raw mut cmd)
        .map_err(|e| anyhow!("sukisu_fs umount failed: {e}"))?;
    Ok(())
}

pub fn rule_add(view: u32, uid_min: u32, uid_max: u32, path: &str) -> Result<()> {
    if view != VIEW_HIDE && view != VIEW_SHOW {
        bail!("invalid view: must be 0 (HIDE) or 1 (SHOW)");
    }
    if uid_min > uid_max {
        bail!("uid_min ({uid_min}) > uid_max ({uid_max})");
    }

    let mut cmd = ksu_sukisu_fs_rule_cmd {
        operation: 1, // SUKISU_FS_RULE_ADD
        view,
        uid_min,
        uid_max,
        path: zeroed_path(),
    };
    copy_path(&mut cmd.path, path)?;

    crate::ksucalls::ksuctl(ksu_uapi::KSU_IOCTL_SUKISU_FS_RULE, &raw mut cmd)
        .map_err(|e| anyhow!("sukisu_fs rule_add failed: {e}"))?;
    Ok(())
}

pub fn rule_remove(path: &str) -> Result<()> {
    let mut cmd = ksu_sukisu_fs_rule_cmd {
        operation: 2, // SUKISU_FS_RULE_REMOVE
        view: 0,
        uid_min: 0,
        uid_max: 0,
        path: zeroed_path(),
    };
    copy_path(&mut cmd.path, path)?;

    crate::ksucalls::ksuctl(ksu_uapi::KSU_IOCTL_SUKISU_FS_RULE, &raw mut cmd)
        .map_err(|e| anyhow!("sukisu_fs rule_remove failed: {e}"))?;
    Ok(())
}

pub fn rule_clear() -> Result<()> {
    let mut cmd = ksu_sukisu_fs_rule_cmd {
        operation: 4, // SUKISU_FS_RULE_CLEAR
        view: 0,
        uid_min: 0,
        uid_max: 0,
        path: zeroed_path(),
    };

    crate::ksucalls::ksuctl(ksu_uapi::KSU_IOCTL_SUKISU_FS_RULE, &raw mut cmd)
        .map_err(|e| anyhow!("sukisu_fs rule_clear failed: {e}"))?;
    Ok(())
}

pub fn rule_list() -> Result<Vec<(u32, u32, u32, String)>> {
    // Query the total first.
    let mut probe = ksu_sukisu_fs_rule_cmd {
        operation: 0,
        view: 0,
        uid_min: 0,
        uid_max: 0,
        path: zeroed_path(),
    };

    crate::ksucalls::ksuctl(ksu_uapi::KSU_IOCTL_SUKISU_FS_LIST, &raw mut probe)
        .context("sukisu_fs rule_list probe failed")?;
    let total = probe.uid_min as usize;

    let mut rules = Vec::with_capacity(total);
    for index in 0..total as u32 {
        let mut entry = ksu_sukisu_fs_rule_cmd {
            operation: 0,
            view: 0,
            uid_min: index,
            uid_max: 0,
            path: zeroed_path(),
        };
        crate::ksucalls::ksuctl(ksu_uapi::KSU_IOCTL_SUKISU_FS_LIST, &raw mut entry)
            .with_context(|| format!("sukisu_fs rule_list index={index}"))?;
        let path = read_path(&entry.path);
        rules.push((entry.view, entry.uid_min, entry.uid_max, path));
    }
    Ok(rules)
}

// --- helpers --------------------------------------------------------------

#[repr(C)]
#[derive(Copy, Clone)]
struct ksu_sukisu_fs_mount_cmd {
    source: [u8; 256],
    target: [u8; 256],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ksu_sukisu_fs_rule_cmd {
    operation: u32,
    view: u32,
    uid_min: u32,
    uid_max: u32,
    path: [u8; 256],
}

const fn zeroed_path() -> [u8; 256] {
    [0u8; 256]
}

fn copy_path(dst: &mut [u8; 256], src: &str) -> Result<()> {
    let bytes = src.as_bytes();
    if bytes.len() >= 256 {
        bail!("path too long: {} bytes (max 255)", bytes.len());
    }
    dst[..bytes.len()].copy_from_slice(bytes);
    dst[bytes.len()] = 0;
    Ok(())
}

fn read_path(src: &[u8; 256]) -> String {
    let end = src.iter().position(|&b| b == 0).unwrap_or(256);
    String::from_utf8_lossy(&src[..end]).into_owned()
}
