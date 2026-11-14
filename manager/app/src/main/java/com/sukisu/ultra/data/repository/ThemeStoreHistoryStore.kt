package com.sukisu.ultra.data.repository

/**
 * A viewed/downloaded theme as stored by the web account (`/account/api/history`),
 * resolved against the source it belongs to. The manager keeps no local history:
 * signed-in accounts share one history across the web and every manager install.
 */
enum class ThemeStoreHistoryKind(val key: String, val apiKind: String) {
    VIEWED("viewed", "view"),
    DOWNLOADED("downloaded", "download"),
}

data class ThemeStoreHistoryEntry(
    val key: String,
    val themeId: String,
    val name: String,
    val author: String,
    val sourceId: String,
    val baseUrl: String,
    val previewPath: String,
    val createdAt: Long,
    val r18: Boolean = false,
    val adaptive: Boolean = false,
)
