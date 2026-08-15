//! Shell-script fragment builders.
//!
//! Each file in this module produces one or more shell snippets that are
//! then concatenated by the four [`generate`] entry-points into a final
//! per-stage script. Splitting them this way keeps every snippet small
//! and reviewable, and makes it trivial to toggle / reorder them later.
//!
//! - [`prelude`] — `LOG_DIR` setup + `get_current_time` shell function +
//!   the `ksud` binary existence check that every script shares
//! - [`prop`]    — `module.prop` content
//! - [`hide_bl`] — BL-hiding snippet (Shamiko-derived)
//! - [`cleanup`] — tool-residue cleanup list
//! - [`generate`]— the four full scripts assembled from the above

pub mod cleanup;
pub mod generate;
pub mod hide_bl;
pub mod prelude;
pub mod prop;
