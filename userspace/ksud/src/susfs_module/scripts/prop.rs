//! `module.prop` content.

/// Fixed module metadata for the SuSFS Manager module.
///
/// `updateJson=` is intentionally left blank — the module is generated
/// on-device, not distributed through Magisk's update channel.
pub fn module_prop() -> String {
    r"id=susfs_manager
name=SuSFS Manager
version=v4.0.0
versionCode=40000
author=ShirkNeko
description=SuSFS Manager Auto Configuration Module (自动生成请不要手动卸载或删除该模块! / Automatically generated Please do not manually uninstall or delete the module!)
updateJson=
"
    .to_string()
}
