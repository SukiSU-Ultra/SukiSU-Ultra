package com.sukisu.ultra.data.repository

import android.content.Context
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File

/**
 * Local record of the theme-store disclaimer/data-transfer agreement.
 *
 * It lives in [Context.noBackupFilesDir] on purpose: the agreement is device- and
 * installation-scoped, so uninstalling the manager (or restoring a backup on another device)
 * always requires accepting it again. [ThemeStoreConsent.showR18] is additionally mirrored to
 * signed-in accounts; after login an explicit web choice may replace the local value, but it can
 * never replace the agreement itself.
 */
@Serializable
data class ThemeStoreConsent(
    val version: Int,
    val acceptedAt: Long,
    val showR18: Boolean = false,
)

class ThemeStoreConsentStore(context: Context) {
    companion object {
        const val CURRENT_VERSION = 1
        private const val FILE_NAME = "theme_store_consent.json"
    }

    private val file = File(context.noBackupFilesDir, FILE_NAME)
    private val json = Json { ignoreUnknownKeys = true }

    fun read(): ThemeStoreConsent? {
        if (!file.isFile) return null
        val record = runCatching {
            json.decodeFromString(ThemeStoreConsent.serializer(), file.readText())
        }.getOrNull() ?: return null
        return record.takeIf { it.version == CURRENT_VERSION }
    }

    fun isAccepted(): Boolean = read() != null

    fun accept(showR18: Boolean = false): ThemeStoreConsent {
        val record = ThemeStoreConsent(
            version = CURRENT_VERSION,
            acceptedAt = System.currentTimeMillis(),
            showR18 = showR18,
        )
        write(record)
        return record
    }

    fun updateShowR18(showR18: Boolean): ThemeStoreConsent? {
        val record = read() ?: return null
        val updated = record.copy(showR18 = showR18)
        write(updated)
        return updated
    }

    fun revoke() {
        runCatching { file.delete() }
    }

    private fun write(record: ThemeStoreConsent) {
        runCatching {
            file.parentFile?.mkdirs()
            file.writeText(json.encodeToString(ThemeStoreConsent.serializer(), record))
        }
    }
}
