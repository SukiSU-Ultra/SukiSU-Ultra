package com.sukisu.ultra.data.repository

import com.sukisu.ultra.ui.util.ExtensionId
import com.sukisu.ultra.ui.util.ExtensionState
import com.sukisu.ultra.ui.util.getExtensionStatus
import com.sukisu.ultra.ui.util.getExtensionValue
import com.sukisu.ultra.ui.util.getKpmVersion

/**
 * User-facing contract for the extension subsystem. All calls go
 * through the ksud binary via the `extension` subcommand.
 *
 * The overview screen is read-only: every extension that exposes a
 * runtime sticky bit (DynamicManager) is toggled from inside its own
 * sub-screen via dedicated ksud subcommands (e.g. `manager
 * set-enabled`), so this repository deliberately does not expose a
 * `setEnabled` operation.
 */
interface ExtensionRepository {
    suspend fun probe(id: ExtensionId): ExtensionState
}

class ExtensionRepositoryImpl : ExtensionRepository {

    override suspend fun probe(id: ExtensionId): ExtensionState {
        val status = getExtensionStatus(id.wireName)
        // "supported" / "unsupported" / "forced" / "managed" — see
        // userspace/ksud/src/extension.rs::check_extension.
        val statusBasedSupported = status == "supported" || status == "forced"
        val forced = status == "forced"
        val managed = status == "managed"

        // KPM requires the kernel sub-system to actually respond to "kpm version".
        // If that call fails/empty, the extension is effectively unsupported.
        val kpmWorking = id == ExtensionId.Kpm &&
            getKpmVersion().isNotEmpty()

        val supported = statusBasedSupported && (id != ExtensionId.Kpm || kpmWorking)
        val value = if (supported) getExtensionValue(id.wireName) ?: 0L else 0L

        return ExtensionState(
            id = id,
            value = value,
            supported = supported,
            forced = forced,
            managed = managed,
        )
    }
}
