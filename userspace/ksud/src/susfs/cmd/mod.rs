//! High-level SuSFS commands.
//!
//! Each file in this module wraps one or more SuSFS kernel commands into
//! a typed Rust function. Public re-exports happen at `crate::susfs`.
//!
//! - [`status`] — read-only queries
//! - [`spoof`]  — kernel-level spoofing setters
//! - [`paths`]  — `sus_path` / `sus_map` / `open_redirect` operations
//! - [`kstat`]  — `sus_kstat` operations

pub mod kstat;
pub mod paths;
pub mod spoof;
pub mod status;
