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
    DynamicManager(3, "dynamic_manager", R.string.extension_dynamic_manager_title);

    companion object {
        val ALL: List<ExtensionId> = listOf(Kpm, CpuSpoof, UmountPaths, DynamicManager)

        fun fromWireName(name: String): ExtensionId? =
            ALL.firstOrNull { it.wireName == name }
    }
}

/**
 * Runtime state of one extension, as reported by the kernel.
 *  - `supported`: the kernel has a registered handler; the toggle is
 *    shown as disabled if false.
 *  - `forced`: `force_extension=` boot param took the value; the
 *    toggle is disabled and labelled "Forced by boot config".
 *  - `value`: the sticky bit. Most extensions use bit 0 (1 = enabled).
 */
data class ExtensionState(
    val id: ExtensionId,
    val value: Long,
    val supported: Boolean,
    val forced: Boolean,
) {
    val userToggleable: Boolean get() = supported && !forced
    val enabled: Boolean get() = supported && value != 0L
}
