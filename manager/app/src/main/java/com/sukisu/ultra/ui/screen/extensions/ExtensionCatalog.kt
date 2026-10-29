package com.sukisu.ultra.ui.screen.extensions

import androidx.annotation.StringRes
import androidx.compose.runtime.Immutable
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.navigation3.Route

/**
 * What opening an extension card does.
 *
 * [Screen] is the entry point this build knows how to render; [Generic] is
 * the fallback for a handler that only exists in the kernel so far. A generic
 * sticky extension is toggled inline from its card, which is what makes a new
 * extension usable without touching this screen.
 */
sealed interface ExtensionEntry {
    data class Screen(val route: Route) : ExtensionEntry
    data object Generic : ExtensionEntry
}

/**
 * UI metadata for one extension.
 *
 * The kernel publishes the canonical facts (id, wire name, capabilities) and
 * [com.sukisu.ultra.ui.util.ExtensionState] carries them. This descriptor only
 * adds what the kernel should not own: localised copy and the manager's
 * navigation target. Adding an extension whose settings fit the generic
 * card needs no change here at all.
 */
@Immutable
data class ExtensionDescriptor(
    val wireName: String,
    @StringRes val titleRes: Int? = null,
    @StringRes val summaryRes: Int? = null,
    val entry: ExtensionEntry = ExtensionEntry.Generic,
)

/**
 * The single place that maps a kernel wire name to a localised card and an
 * entry point. Screens iterate the kernel's list and ask for a descriptor;
 * they never switch on an id.
 */
object ExtensionCatalog {

    private val known: List<ExtensionDescriptor> = listOf(
        ExtensionDescriptor(
            wireName = "kpm",
            titleRes = R.string.extension_kpm_title,
            summaryRes = R.string.extension_kpm_summary,
            entry = ExtensionEntry.Screen(Route.Kpm),
        ),
        ExtensionDescriptor(
            wireName = "cpu_spoof",
            titleRes = R.string.extension_cpu_spoof_title,
            summaryRes = R.string.extension_cpu_spoof_summary,
            entry = ExtensionEntry.Screen(Route.CpuSpoof),
        ),
        ExtensionDescriptor(
            wireName = "umount_paths",
            titleRes = R.string.extension_umount_paths_title,
            summaryRes = R.string.extension_umount_paths_summary,
            entry = ExtensionEntry.Screen(Route.UmountManager),
        ),
        ExtensionDescriptor(
            wireName = "dynamic_manager",
            titleRes = R.string.extension_dynamic_manager_title,
            summaryRes = R.string.extension_dynamic_manager_summary,
            entry = ExtensionEntry.Screen(Route.DynamicManagers),
        ),
        ExtensionDescriptor(
            wireName = "susfs",
            titleRes = R.string.extension_susfs_title,
            summaryRes = R.string.extension_susfs_summary,
            entry = ExtensionEntry.Screen(Route.SuSFS),
        ),
        ExtensionDescriptor(
            wireName = "version_spoof",
            titleRes = R.string.extension_version_spoof_title,
            summaryRes = R.string.extension_version_spoof_summary,
            entry = ExtensionEntry.Screen(Route.VersionSpoof),
        ),
    )

    private val byWireName: Map<String, ExtensionDescriptor> = known.associateBy { it.wireName }

    /**
     * Descriptor for a kernel-reported extension. Unknown names fall back to
     * the kernel's own canonical name, no summary, and the generic card.
     * [id] is only used when the name is empty so the card never renders
     * blank.
     */
    fun descriptorFor(wireName: String, id: Int): ExtensionDescriptor =
        byWireName[wireName] ?: ExtensionDescriptor(
            wireName = wireName.ifBlank { "#$id" },
            entry = ExtensionEntry.Generic,
        )
}
