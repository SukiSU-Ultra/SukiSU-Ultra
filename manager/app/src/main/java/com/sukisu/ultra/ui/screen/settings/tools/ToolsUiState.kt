package com.sukisu.ultra.ui.screen.settings.tools

import androidx.compose.runtime.Immutable

@Immutable
data class ToolsUiState(
    val selinuxEnforcing: Boolean = true,
    val selinuxLoading: Boolean = true,
)

@Immutable
data class ToolsActions(
    val onBack: () -> Unit,
    val onSelinuxToggle: (Boolean) -> Unit = {},
    val onBackupAllowlist: () -> Unit = {},
    val onRestoreAllowlist: () -> Unit = {},
    val onNavigateToUmountManager: () -> Unit = {},
)
