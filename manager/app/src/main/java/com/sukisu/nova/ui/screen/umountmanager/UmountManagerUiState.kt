package com.sukisu.nova.ui.screen.umountmanager

import androidx.compose.runtime.Immutable

@Immutable
data class UmountManagerUiState(
    val pathList: List<UmountPathEntry> = emptyList(),
    val isLoading: Boolean = false,
    val showAddDialog: Boolean = false,
)

@Immutable
data class UmountManagerActions(
    val onRefresh: () -> Unit = {},
    val onAddClick: () -> Unit = {},
    val onAddPath: (String, Int) -> Unit = { _, _ -> },
    val onDismissAddDialog: () -> Unit = {},
    val onDeletePath: (UmountPathEntry) -> Unit = {},
    val onClearCustomPaths: () -> Unit = {},
    val onApplyConfig: () -> Unit = {},
    val onBack: () -> Unit = {},
)
