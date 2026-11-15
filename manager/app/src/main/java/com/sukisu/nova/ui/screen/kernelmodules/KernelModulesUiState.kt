package com.sukisu.nova.ui.screen.kernelmodules

import androidx.compose.runtime.Immutable

@Immutable
data class KernelModulesUiState(
    val snapshot: KernelModulesSnapshot? = null,
    val isLoading: Boolean = true,
    val failed: Boolean = false,
    val expanded: Set<String> = emptySet(),
)

@Immutable
data class KernelModulesActions(
    val onBack: () -> Unit = {},
    val onRefresh: () -> Unit = {},
    val onToggleExpanded: (String) -> Unit = {},
    val onCopy: (String) -> Unit = {},
)
