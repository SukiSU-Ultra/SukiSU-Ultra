package com.sukisu.ultra.ui.screen.appcontext

import androidx.annotation.StringRes

/**
 * UI state for App Context screen
 */
data class AppContextUiState(
    val contexts: List<AppContextEntry> = emptyList(),
    val isLoading: Boolean = false,
    @StringRes val error: Int? = null,
)

/**
 * Single app context entry
 */
data class AppContextEntry(
    val uid: Long,
    val foreground: Boolean,
    val profileId: Long,
    val tags: Long,
    val lastUpdateNs: String,
    val packageName: String? = null, // Optional: resolve from UID
)
