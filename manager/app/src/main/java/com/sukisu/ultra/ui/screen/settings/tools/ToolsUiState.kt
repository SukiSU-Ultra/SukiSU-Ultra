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
)

@Immutable
data class SpoofCpuParams(
    val cpuIndices: List<Int>,
    val midrHex: String,
    val bogomips: Int,
    val hwcapHex: String,
    val hwcap2Hex: String
)
