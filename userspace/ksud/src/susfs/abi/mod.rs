//! SuSFS kernel ABI.
//!
//! Internal description of the SuSFS userspace ↔ kernel protocol:
//! magic numbers, command IDs, payload struct layouts, and the single
//! `SYS_reboot` syscall used to dispatch every command.
//!
//! None of these items are part of the public API; the crate-root
//! `susfs` module re-exports only the high-level command functions.

pub(crate) mod consts;
pub(crate) mod syscall;
pub(crate) mod types;

pub(crate) use consts::*;
pub(crate) use syscall::send;
pub(crate) use types::*;
