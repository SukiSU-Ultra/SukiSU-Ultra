package com.sukisu.ultra.data.repository

import com.sukisu.ultra.ui.util.ExtensionId
import com.sukisu.ultra.ui.util.ExtensionState
import com.sukisu.ultra.ui.util.getExtensionStatus
import com.sukisu.ultra.ui.util.getExtensionValue
import com.sukisu.ultra.ui.util.setExtensionEnabled

/**
 * User-facing contract for the extension subsystem. All calls go
 * through the ksud binary via the `extension` subcommand.
 */
interface ExtensionRepository {
    suspend fun probe(id: ExtensionId): ExtensionState
    suspend fun setEnabled(id: ExtensionId, enabled: Boolean): Boolean
}

class ExtensionRepositoryImpl : ExtensionRepository {

    override suspend fun probe(id: ExtensionId): ExtensionState {
        val status = getExtensionStatus(id.wireName)
        // "supported" / "unsupported" / "forced" / "managed" — see
        // userspace/ksud/src/extension.rs::check_extension.
        val supported = status == "supported" || status == "forced"
        val forced = status == "forced"
        val value = if (supported) getExtensionValue(id.wireName) ?: 0L else 0L
        return ExtensionState(
            id = id,
            value = value,
            supported = supported,
            forced = forced,
        )
    }

    override suspend fun setEnabled(id: ExtensionId, enabled: Boolean): Boolean =
        setExtensionEnabled(id.wireName, enabled)
}
