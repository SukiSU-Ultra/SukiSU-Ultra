package com.sukisu.ultra.ui.screen.settings.tools

import androidx.compose.runtime.Immutable

@Immutable
data class ToolsUiState(
    val selinuxEnforcing: Boolean = true,
    val selinuxLoading: Boolean = true,
    val spoofCpuDialogVisible: Boolean = false,
    val currentCpuInfo: CpuInfo? = null,
    val spoofCpuLoading: Boolean = false,
)

@Immutable
data class ToolsActions(
    val onBack: () -> Unit,
    val onSelinuxToggle: (Boolean) -> Unit = {},
    val onBackupAllowlist: () -> Unit = {},
    val onRestoreAllowlist: () -> Unit = {},
    val onNavigateToUmountManager: () -> Unit = {},
    val onOpenSpoofCpuDialog: () -> Unit = {},
    val onDismissSpoofCpuDialog: () -> Unit = {},
    val onApplySpoofCpu: (SpoofCpuParams) -> Unit = {},
)

@Immutable
data class SpoofCpuParams(
    val cpuIndices: List<Int>,
    val midrHex: String,
    val bogomips: Int,
    val hwcapHex: String,
    val hwcap2Hex: String
)
