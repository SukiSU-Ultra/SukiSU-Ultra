//! SuSFS Manager module installer.
//!
//! Generates a Magisk-style module (`/data/adb/modules/susfs_manager`)
//! that, once installed, runs four shell scripts at the appropriate
//! boot stages (`service.sh` / `post-fs-data.sh` / `post-mount.sh` /
//! `boot-completed.sh`) to configure SuSFS on next boot.
//!
//! ## Layout
//!
//! ```text
//! susfs_module/
//! ├── mod.rs      ← public re-exports (install_module / remove_module / is_module_installed)
//! ├── consts.rs   ← module path / log dir / default values / shell helpers
//! ├── install.rs  ← the only function that talks to `sh` via Command
//! └── scripts/    ← shell-script fragment builders
//!     ├── mod.rs
//!     ├── prelude.rs   ← log_setup / binary_check
//!     ├── prop.rs      ← module.prop
//!     ├── hide_bl.rs   ← BL-hiding snippets
//!     ├── cleanup.rs   ← tool-residue cleanup list
//!     └── generate.rs  ← the four full script generators
//! ```

mod consts;
mod install;
mod scripts;

pub use install::{install_module, is_module_installed, remove_module};