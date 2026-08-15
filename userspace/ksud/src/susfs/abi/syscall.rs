//! Low-level syscall helper.
//!
//! Every SuSFS command is dispatched through the same `reboot(2)` syscall:
//!
//! ```text
//! syscall(SYS_reboot,
//!         KSU_INSTALL_MAGIC1,   // magic #1
//!         SUSFS_MAGIC,          // magic #2
//!         cmd_id,               // which command to run
//!         &mut payload)         // command-specific #[repr(C)] struct
//! ```
//!
//! After the syscall returns, the kernel writes an `err` code into the
//! payload struct; we surface that as an `anyhow::Error` so callers can
//! bubble it up the stack.

use libc::SYS_reboot;

use super::consts::{ERR_CMD_NOT_SUPPORTED, KSU_INSTALL_MAGIC1, SUSFS_MAGIC};
use super::types::{
    SusfsAvcLogSpoofing, SusfsCmdlineOrBootconfig, SusfsFeatures, SusfsHideSusMnts,
    SusfsKstat, SusfsLog, SusfsMap, SusfsOpenRedirect, SusfsSusPath, SusfsUname, SusfsVariant,
    SusfsVersion,
};

/// Dispatch a SuSFS command and return `Ok(())` when the kernel reports no
/// error.
///
/// The kernel always fills `payload.err` (sentinel
/// [`ERR_CMD_NOT_SUPPORTED`] when the feature is off, otherwise a `0`-on-
/// success / errno-style value), so this is the single chokepoint where
/// `cmd != ERR_CMD_NOT_SUPPORTED && cmd != 0` is converted into an
/// `anyhow::Error`.
pub(crate) fn send<T: HasErr>(cmd: u32, payload: &mut T, op_name: &str) -> anyhow::Result<()> {
    // Pass the payload as a raw `*mut c_void` so the `&mut T` reference
    // isn't moved into the syscall (the FFI signature expects a raw
    // pointer, and the kernel writes back into our buffer, but we still
    // own the `&mut T` on the Rust side).
    unsafe {
        libc::syscall(
            SYS_reboot,
            KSU_INSTALL_MAGIC1,
            SUSFS_MAGIC,
            cmd,
            payload as *mut T as *mut libc::c_void,
        )
    };

    let err = payload.err();
    if err == 0 || err == ERR_CMD_NOT_SUPPORTED {
        return Ok(());
    }
    anyhow::bail!("{op_name}: kernel returned err={err}")
}

/// Convenience wrapper: read the `err` field of a SuSFS payload struct.
///
/// Kept as a trait (instead of free-standing `field` access) so the
/// implementation lives next to the struct definitions and new payload
/// types automatically get the right implementation.
pub(crate) trait HasErr {
    fn err(&self) -> i32;
}

// `HasErr` is implemented by every concrete payload type via a blanket
// macro that reads the trailing `err` field.
macro_rules! impl_has_err {
    ($($t:ty),* $(,)?) => {
        $(impl HasErr for $t {
            #[inline]
            fn err(&self) -> i32 { self.err }
        })*
    };
}

impl_has_err!(
    SusfsVersion,
    SusfsFeatures,
    SusfsVariant,
    SusfsUname,
    SusfsLog,
    SusfsAvcLogSpoofing,
    SusfsHideSusMnts,
    SusfsOpenRedirect,
    SusfsKstat,
    SusfsMap,
    SusfsSusPath,
    SusfsCmdlineOrBootconfig,
);
