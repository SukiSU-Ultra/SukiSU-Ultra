//! Persistent SuSFS Manager configuration store.
//!
//! Stores key/value pairs in a binary file under
//! `/data/adb/ksu/susfs_config` (magic-header + length-prefixed record
//! format). Higher-level accessors live in [`store`]; the
//! "config → module installer" glue lives in [`module`].
//!
//! ## Layout
//!
//! ```text
//! susfs_config/
//! ├── mod.rs      ← public re-exports (cli.rs uses these directly)
//! ├── keys.rs     ← KEY_* constants / ALL_KEYS (internal only)
//! ├── binary.rs   ← magic / version / record format read/write
//! ├── store.rs    ← load / save / get / set / remove / clear /
//! │                reset_to_defaults / export_json
//! └── module.rs   ← ModuleConfig + load_module_config (for susfs_module)
//! ```

mod binary;
mod keys;
mod module;
mod store;

pub use module::{ModuleConfig, load_module_config};
pub use store::{clear, export_json, get, remove, reset_to_defaults, set};