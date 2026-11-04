package com.sukisu.ultra.ui.util

import androidx.compose.runtime.Immutable

/**
 * Identifier of a kernel extension (KSU_IOCTL_EXTENSION / enum ksu_extension_id).
 * Mirrors `ExtensionId` in `userspace/ksud/src/extension_id.rs` and
 * `enum ksu_extension_id` in `uapi/extension.h`.
 *
 * This enum is only a compatibility table now:
 *  - the kernel reports its handler table through KSU_EXTENSION_ENUM, so an
 *    id this enum does not contain still reaches the UI;
 *  - [legacyHasStickyBit] is consulted only when the kernel predates
 *    extension ABI 1 and therefore cannot publish capability bits.
 *
 * UI metadata (localised title, summary, entry point) lives in
 * [com.sukisu.ultra.ui.screen.extensions.ExtensionCatalog], not here.
 */
enum class ExtensionId(val id: Int, val wireName: String) {
    Kpm(0, "kpm"),
    CpuSpoof(1, "cpu_spoof"),
    UmountPaths(2, "umount_paths"),
    DynamicManager(3, "dynamic_manager"),
    SuSFS(4, "susfs"),
    VersionSpoof(5, "version_spoof");

    companion object {
        val ALL: List<ExtensionId> = listOf(Kpm, CpuSpoof, UmountPaths, DynamicManager, SuSFS, VersionSpoof)

        fun fromWireName(name: String): ExtensionId? =
            ALL.firstOrNull { it.wireName == name }
    }

    /**
     * Static fallback for kernels that predate extension ABI 1.
     *
     * Those kernels publish no capability bits, so "does this extension have
     * a toggle" cannot be asked. This table is the last hand-maintained
     * mirror of the kernel's handler table and only ever runs against such a
     * kernel, which by definition has exactly this table — it can never
     * disagree with a kernel that answers the ABI probe.
     *
     * Prefer [ExtensionState.sticky], which carries the kernel's answer.
     *
     *   - KPM reports `CONFIG_KPM` via GET, but the bit is compile-time and
     *     there is no runtime setter.
     *   - CPU spoof, umount paths and version spoof are purely io-driven:
     *     their state lives in each ioctl payload, never in a sticky u64.
     */
    val legacyHasStickyBit: Boolean
        get() = this == DynamicManager
}


fun legacyExtensionHasStickyBit(wireName: String): Boolean =
    ExtensionId.fromWireName(wireName)?.legacyHasStickyBit == true

/**
 * Runtime state of one extension, as reported by the kernel.
 *  - `supported`: the kernel has a registered handler; the card is
 *    shown as non-interactive if false.
 *  - `forced`: `force_extension=` boot param took the value; the
 *    card is read-only and labelled "Forced by boot config".
 *  - `managed`: a module owns the extension; the card is read-only
 *    and labelled "Managed by module".
 *  - `value`: the sticky bit. Only meaningful when [sticky] is true; for
 *    KPM / CPU spoof / umount paths the kernel always reports 0.
 *  - `sticky` / `persistent` / `perUid` / `needsReboot`: capability bits
 *    from the kernel. `capsKnown` is false on kernels older than extension
 *    ABI 1, where ksud substitutes [legacyExtensionHasStickyBit].
 *
 * [wireName] and [id] come from the kernel, so an extension this build has
 * no [ExtensionId] for is still representable.
 */
@Immutable
data class ExtensionState(
    val id: Int,
    val wireName: String,
    val value: Long,
    val supported: Boolean,
    val forced: Boolean,
    val managed: Boolean,
    val capsKnown: Boolean = false,
    val sticky: Boolean = legacyExtensionHasStickyBit(wireName),
    val persistent: Boolean = legacyExtensionHasStickyBit(wireName),
    val perUid: Boolean = false,
    val needsReboot: Boolean = false,
) {
    val userToggleable: Boolean
        get() = sticky && supported && !forced && !managed
    val enabled: Boolean get() = userToggleable && value != 0L
}
