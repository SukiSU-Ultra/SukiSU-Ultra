package com.sukisu.ultra.ui.util

import androidx.annotation.StringRes
import com.sukisu.ultra.R

/**
 * Identifier of a kernel extension (KSU_IOCTL_EXTENSION / enum ksu_extension_id).
 * Mirrors `ExtensionId` in `userspace/ksud/src/extension_id.rs` and
 * `enum ksu_extension_id` in `uapi/extension.h`.
 */
enum class ExtensionId(val id: Int, val wireName: String, @StringRes val displayRes: Int) {
    Kpm(0, "kpm", R.string.extension_kpm_title),
    CpuSpoof(1, "cpu_spoof", R.string.extension_cpu_spoof_title),
    UmountPaths(2, "umount_paths", R.string.extension_umount_paths_title),
    DynamicManager(3, "dynamic_manager", R.string.extension_dynamic_manager_title),
    SuSFS(4, "susfs", R.string.extension_susfs_title),
    VersionSpoof(5, "version_spoof", R.string.extension_version_spoof_title);

    companion object {
        val ALL: List<ExtensionId> = listOf(Kpm, CpuSpoof, UmountPaths, DynamicManager, SuSFS, VersionSpoof)

        fun fromWireName(name: String): ExtensionId? =
            ALL.firstOrNull { it.wireName == name }
    }

    /**
     * Whether this extension exposes a runtime sticky bit at all.
     *
     * `true`  → kernel has a get/set handler; UI may show a toggle.
     * `false` → the subsystem is either compile-time-only (KPM), purely
     *           io-driven (CPU spoof, umount paths). 
     *           The status line in the overview shows "Supported" and
     *           the card has no on/off control; opening the sub-screen
     *           reveals whatever real controls exist.
     *
     * Mirrors `ExtensionId::has_sticky_bit` in
     * `userspace/ksud/src/extension_id.rs`. SuSFS is intentionally not
     * on the Rust side: it has no kernel extension handler, so adding
     * `KSU_EXTENSION_SUSFS` would require a UAPI bump and a kernel
     * patch that we cannot assume is present.
     */
    val hasStickyBit: Boolean
        get() = this == DynamicManager
}

/**
 * Runtime state of one extension, as reported by the kernel.
 *  - `supported`: the kernel has a registered handler; the card is
 *    shown as non-interactive if false.
 *  - `forced`: `force_extension=` boot param took the value; the
 *    card is read-only and labelled "Forced by boot config".
 *  - `managed`: a module owns the extension; the card is read-only
 *    and labelled "Managed by module".
 *  - `value`: the sticky bit. Only meaningful when
 *    [id.hasStickyBit] is true; for KPM / CPU spoof / umount paths
 *    the kernel always reports 0 and the UI ignores it.
 */
data class ExtensionState(
    val id: ExtensionId,
    val value: Long,
    val supported: Boolean,
    val forced: Boolean,
    val managed: Boolean,
) {
    val userToggleable: Boolean
        get() = id.hasStickyBit && supported && !forced && !managed
    val enabled: Boolean get() = userToggleable && value != 0L
}
