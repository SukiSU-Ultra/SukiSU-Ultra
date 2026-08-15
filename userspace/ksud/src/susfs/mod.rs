//! SuSFS userspace bindings.
//!
//! This module exposes a small, typed Rust API over the SuSFS kernel ABI,
//! which is reached through a single `reboot(2)` syscall with the magic
//! values `KSU_INSTALL_MAGIC1` and `SUSFS_MAGIC`.
//!
//! ## Layout
//!
//! ```text
//! susfs/
//! ├── mod.rs   ← you are here: public re-exports only
//! ├── util.rs  ← cross-command helpers (canonicalize / read_file / copy_*)
//! ├── abi/     ← SuSFS kernel ABI (consts + #[repr(C)] structs + syscall glue)
//! └── cmd/     ← one file per SuSFS command (status / spoof / paths / kstat)
//! ```
//!
//! All public functions are safe to call from `Android` targets; on
//! non-Android hosts the crate root guards the whole module under
//! `#[cfg(target_arch = "aarch64")]`, matching the kernel ABI.

pub mod abi;
pub mod cmd;
pub mod util;

pub use cmd::kstat::*;
pub use cmd::paths::*;
pub use cmd::spoof::*;
pub use cmd::status::*;
