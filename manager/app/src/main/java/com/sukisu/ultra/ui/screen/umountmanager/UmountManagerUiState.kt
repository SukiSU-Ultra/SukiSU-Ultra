package com.sukisu.ultra.ui.screen.umountmanager

import androidx.compose.runtime.Immutable

@Immutable
data class UmountManagerUiState(
    val pathList: List<UmountPathEntry> = emptyList(),
    val exclusionList: List<UmountExclusionEntry> = emptyList(),
    val isLoading: Boolean = false,
    val showAddPathDialog: Boolean = false,
    val showAddExclusionDialog: Boolean = false,
    val showExclusionList: Boolean = false,
)

@Immutable
data class UmountManagerActions(
    val onRefresh: () -> Unit = {},
    val onAddPathClick: () -> Unit = {},
    val onAddPath: (String, Int) -> Unit = { _, _ -> },
    val onDismissAddPathDialog: () -> Unit = {},
    val onDeletePath: (UmountPathEntry) -> Unit = {},
    val onClearCustomPaths: () -> Unit = {},
    val onApplyConfig: () -> Unit = {},
    val onBack: () -> Unit = {},
    // Exclusion actions
    val onShowExclusionList: () -> Unit = {},
    val onAddExclusionClick: () -> Unit = {},
    val onAddExclusion: (String) -> Unit = { _ -> },
    val onDismissAddExclusionDialog: () -> Unit = {},
    val onDeleteExclusion: (UmountExclusionEntry) -> Unit = {},
    val onClearAllExclusions: () -> Unit = {},
    val onBackToPathList: () -> Unit = {},
)
