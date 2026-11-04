package com.sukisu.ultra.data.repository

import com.sukisu.ultra.ui.util.ExtensionId
import com.sukisu.ultra.ui.util.ExtensionOverviewEntry
import com.sukisu.ultra.ui.util.ExtensionState
import com.sukisu.ultra.ui.util.getExtensionOverview
import com.sukisu.ultra.ui.util.setExtensionValue

/**
 * User-facing contract for the extension subsystem.
 *
 * The overview list is built from `ksud extension list`, which on ABI 2+
 * enumerates the kernel's own handler table. That is why [probeAll] returns
 * a list rather than a map keyed by [ExtensionId]: an extension added to the
 * kernel after this manager was built still shows up.
 *
 * [setEnabled] drives the generic card shown for sticky extensions with no
 * dedicated page. Known extensions with their own sub-screen keep using
 * their existing ksud subcommands (e.g. `manager set-enabled`); this method
 * is not a replacement for those.
 */
interface ExtensionRepository {
    /**
     * Probe every extension at once. Known extensions the kernel did not
     * register are included with `supported = false` so a build-time
     * feature switch stays visible instead of disappearing.
     */
    suspend fun probeAll(): List<ExtensionState>

    
    suspend fun setEnabled(extensionId: Int, enabled: Boolean): Result<Unit>
}

class ExtensionRepositoryImpl : ExtensionRepository {

    override suspend fun probeAll(): List<ExtensionState> {
        val overview = getExtensionOverview()
        val out = LinkedHashMap<String, ExtensionState>(overview.size + ExtensionId.ALL.size)

        for ((name, entry) in overview) {
            out[name] = entry.toState()
        }

        // Keep the historical "not supported" rows for compiled-in
        // extensions the running kernel did not register.
        for (known in ExtensionId.ALL) {
            if (out.containsKey(known.wireName)) continue
            out[known.wireName] = ExtensionState(
                id = known.id,
                wireName = known.wireName,
                value = 0L,
                supported = false,
                forced = false,
                managed = false,
                capsKnown = false,
            )
        }

        return out.values.sortedBy { it.id }
    }

    override suspend fun setEnabled(extensionId: Int, enabled: Boolean): Result<Unit> =
        setExtensionValue(extensionId, if (enabled) 1L else 0L)
}

private fun ExtensionOverviewEntry.toState(): ExtensionState = ExtensionState(
    id = id,
    wireName = name,
    value = value,
    supported = supported,
    forced = forced,
    managed = managed,
    // ksud already applied the legacy fallback when the kernel reports ABI 0,
    // so a missing entry (older ksud, or an id it never asked about) is the
    // only case left to fill in from the static table.
    capsKnown = apiVersion > 0,
    sticky = sticky,
    persistent = persistent,
    perUid = perUid,
    needsReboot = needsReboot,
)
