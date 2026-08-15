//! High-level SuSFS commands.
//!
//! Each file in this module wraps one or more SuSFS kernel commands into
//! a typed Rust function. Public re-exports happen at `crate::susfs`.
//!
//! - [`status`] — read-only queries
//! - [`spoof`]  — kernel-level spoofing setters
//! - [`paths`]  — `sus_path` / `sus_map` / `open_redirect` operations
//! - [`kstat`]  — `sus_kstat` operations

pub(crate) mod kstat;
pub(crate) mod paths;
pub(crate) mod spoof;
pub(crate) mod status;
