//! BL-hiding snippet (Shamiko-derived).
//!
//! Two pieces: [`hide_bl_section`] emits the helper functions
//! (`check_reset_prop`, `check_missing_match_prop`, …), then
//! [`hide_bl_props`] is the body that calls them with the right
//! `resetprop` key/value pairs.

/// Helper-function definitions, prefixed once before any property tweaks.
pub fn hide_bl_section() -> String {
    r#"# 隐藏BL 来自 Shamiko 脚本
RESETPROP_BIN="/data/adb/ksu/bin/resetprop"

check_reset_prop() {
    local NAME=$1
    local EXPECTED=$2
    local VALUE=$("$RESETPROP_BIN" $NAME)
    [ -z $VALUE ] || [ $VALUE = $EXPECTED ] || "$RESETPROP_BIN" $NAME $EXPECTED
}

check_missing_prop() {
    local NAME=$1
    local EXPECTED=$2
    local VALUE=$("$RESETPROP_BIN" $NAME)
    [ -z $VALUE ] && "$RESETPROP_BIN" $NAME $EXPECTED
}

check_missing_match_prop() {
    local NAME=$1
    local EXPECTED=$2
    local VALUE=$("$RESETPROP_BIN" $NAME)
    [ -z $VALUE ] || [ $VALUE = $EXPECTED ] || "$RESETPROP_BIN" $NAME $EXPECTED
    [ -z $VALUE ] && "$RESETPROP_BIN" $NAME $EXPECTED
}

contains_reset_prop() {
    local NAME=$1
    local CONTAINS=$2
    local NEWVAL=$3
    case "$("$RESETPROP_BIN" $NAME)" in
        *"$CONTAINS"*) "$RESETPROP_BIN" $NAME $NEWVAL ;;
    esac
}
"#
    .to_string()
}

/// Concrete `resetprop` calls run 30 s after boot to override the BL
/// surface (`ro.boot.verifiedbootstate`, `ro.boot.vbmeta.*`, …).
pub fn hide_bl_props() -> String {
    r#"sleep 30
"$RESETPROP_BIN" -w sys.boot_completed 0
check_missing_prop "ro.boot.vbmeta.invalidate_on_error" "yes"
check_missing_match_prop "ro.boot.vbmeta.avb_version" "1.2"
check_missing_match_prop "ro.boot.vbmeta.hash_alg" "sha256"
check_missing_prop "ro.boot.vbmeta.size" "19968"
check_missing_match_prop "ro.boot.vbmeta.device_state" "locked"
check_missing_match_prop "ro.boot.verifiedbootstate" "green"
check_reset_prop "ro.boot.flash.locked" "1"
check_reset_prop "ro.boot.veritymode" "enforcing"
check_reset_prop "ro.boot.warranty_bit" "0"
check_reset_prop "ro.warranty_bit" "0"
check_reset_prop "ro.debuggable" "0"
check_reset_prop "ro.force.debuggable" "0"
check_reset_prop "ro.secure" "1"
check_reset_prop "ro.adb.secure" "1"
check_reset_prop "ro.build.type" "user"
check_reset_prop "ro.build.tags" "release-keys"
check_reset_prop "ro.vendor.boot.warranty_bit" "0"
check_reset_prop "ro.vendor.warranty_bit" "0"
check_missing_match_prop "vendor.boot.vbmeta.device_state" "locked"
check_missing_match_prop "vendor.boot.verifiedbootstate" "green"
check_reset_prop "sys.oem_unlock_allowed" "0"
check_reset_prop "ro.secureboot.lockstate" "locked"
check_missing_match_prop "ro.boot.realmebootstate" "green"
check_reset_prop "ro.boot.realme.lockstate" "1"
check_reset_prop "ro.crypto.state" "encrypted"
# Hide adb debugging traces
resetprop "sys.usb.adb.disabled" " "
# Hide recovery boot mode
contains_reset_prop "ro.bootmode" "recovery" "unknown"
contains_reset_prop "ro.boot.bootmode" "recovery" "unknown"
contains_reset_prop "vendor.boot.bootmode" "recovery" "unknown"
# Hide cloudphone detection
[ -n "$(resetprop ro.kernel.qemu)" ] && resetprop ro.kernel.qemu ""
"#
    .to_string()
}
