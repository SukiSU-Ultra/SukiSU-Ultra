//! SuSFS path / map / redirect operations.

use crate::susfs::abi::consts::{
    CMD_SUSFS_ADD_OPEN_REDIRECT, CMD_SUSFS_ADD_SUS_MAP, CMD_SUSFS_ADD_SUS_PATH,
    CMD_SUSFS_ADD_SUS_PATH_LOOP, ERR_CMD_NOT_SUPPORTED, SUSFS_MAX_PATHNAME,
};
use crate::susfs::abi::{send, SusfsMap, SusfsOpenRedirect, SusfsSusPath};
use crate::susfs::util::copy_path_into;

/// Mark `path` as a SuSFS hidden path.
pub fn add_sus_path(path: &str) -> anyhow::Result<()> {
    let mut cmd = SusfsSusPath {
        target_pathname: [0; SUSFS_MAX_PATHNAME],
        err: ERR_CMD_NOT_SUPPORTED,
    };
    copy_path_into(&mut cmd.target_pathname, path)?;
    send(CMD_SUSFS_ADD_SUS_PATH, &mut cmd, "add_sus_path")
}

/// Like [`add_sus_path`] but also follows the path across bind mounts.
pub fn add_sus_path_loop(path: &str) -> anyhow::Result<()> {
    let mut cmd = SusfsSusPath {
        target_pathname: [0; SUSFS_MAX_PATHNAME],
        err: ERR_CMD_NOT_SUPPORTED,
    };
    copy_path_into(&mut cmd.target_pathname, path)?;
    send(CMD_SUSFS_ADD_SUS_PATH_LOOP, &mut cmd, "add_sus_path_loop")
}

/// Add an `open()`-time redirect: `target` paths will be silently opened
/// as `redirected` for processes selected by `uid_scheme`.
pub fn add_open_redirect(
    target: &str,
    redirected: &str,
    uid_scheme: u32,
) -> anyhow::Result<()> {
    let mut cmd = SusfsOpenRedirect {
        target_pathname: [0; SUSFS_MAX_PATHNAME],
        redirected_pathname: [0; SUSFS_MAX_PATHNAME],
        uid_scheme,
        err: ERR_CMD_NOT_SUPPORTED,
    };
    copy_path_into(&mut cmd.target_pathname, target)?;
    copy_path_into(&mut cmd.redirected_pathname, redirected)?;
    send(CMD_SUSFS_ADD_OPEN_REDIRECT, &mut cmd, "add_open_redirect")
}

/// Add `path` to the SuSFS map of overlay / mount roots.
pub fn add_sus_map(path: &str) -> anyhow::Result<()> {
    let mut cmd = SusfsMap {
        target_pathname: [0; SUSFS_MAX_PATHNAME],
        err: ERR_CMD_NOT_SUPPORTED,
    };
    copy_path_into(&mut cmd.target_pathname, path)?;
    send(CMD_SUSFS_ADD_SUS_MAP, &mut cmd, "add_sus_map")
}
