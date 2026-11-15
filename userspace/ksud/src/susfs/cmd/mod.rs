//! High-level SuSFS commands.
//!
//! Each file in this module wraps one or more SuSFS kernel commands into
//! a typed Rust function. Public re-exports happen at `crate::susfs`.
//!
//! - [`status`] — read-only queries
//! - [`spoof`]  — kernel-level spoofing setters
//! - [`paths`]  — `sus_path` / `sus_map` / `open_redirect` operations
//! - [`sus_path_uid_filter`] — restrict which apps can see sus paths
//! - [`kstat`]  — `sus_kstat` operations

pub mod kstat;
pub mod paths;
pub mod priority_uid_filter;
pub mod spoof;
pub mod status;
pub mod sus_path_uid_filter;
