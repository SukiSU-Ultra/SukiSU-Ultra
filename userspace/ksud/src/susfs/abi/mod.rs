//! SuSFS kernel ABI.
//!
//! Internal description of the SuSFS userspace ↔ kernel protocol:
//! magic numbers, command IDs, payload struct layouts, and the single
//! `SYS_reboot` syscall used to dispatch every command.
//!
//! None of these items are part of the public API; the crate-root
//! `susfs` module re-exports only the high-level command functions.

pub mod consts;
pub mod syscall;
pub mod types;

pub use consts::*;
pub use syscall::send;
pub use types::*;
