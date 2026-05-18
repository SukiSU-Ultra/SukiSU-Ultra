package com.sukisu.ultra.ui.screen.install

import androidx.compose.runtime.Immutable
import com.sukisu.ultra.ui.kernelFlash.AnyKernel3State
import com.sukisu.ultra.ui.kernelFlash.KpmPatchOption
import com.sukisu.ultra.ui.util.LkmSelection

@Immutable
internal data class InstallUiState(
    val installMethod: InstallMethod?,
    val lkmSelection: LkmSelection,
    val partitionSelectionIndex: Int,
    val displayPartitions: List<String>,
    val currentKmi: String,
    val slotSuffix: String,
    val installMethodOptions: List<InstallMethod>,
    val canSelectPartition: Boolean,
    val advancedOptionsShown: Boolean,
    val allowShell: Boolean,
    val enableAdb: Boolean,
    val spoofRelease: String,
    val spoofVersion: String,
    // AnyKernel3 相关状态
    val anyKernel3State: AnyKernel3State?,
    val kpmPatchOption: KpmPatchOption,
    val showSlotSelectionDialog: Boolean,
    val showKpmPatchDialog: Boolean,
)

@Immutable
internal data class InstallScreenActions(
    val onBack: () -> Unit,
    val onSelectMethod: (InstallMethod) -> Unit,
    val onSelectBootImage: (InstallMethod) -> Unit,
    val onUploadLkm: () -> Unit,
    val onClearLkm: () -> Unit,
    val onSelectPartition: (Int) -> Unit,
    val onNext: () -> Unit,
    val onAdvancedOptionsClicked: () -> Unit,
    val onSelectAllowShell: (Boolean) -> Unit,
    val onSelectEnableAdb: (Boolean) -> Unit,
    val onSpoofReleaseChange: (String) -> Unit,
    val onSpoofVersionChange: (String) -> Unit,
    val onHorizonKernelSelected: (InstallMethod.HorizonKernel) -> Unit = {},
    val onReopenSlotDialog: (InstallMethod.HorizonKernel) -> Unit = {},
    val onReopenKpmDialog: (InstallMethod.HorizonKernel) -> Unit = {},
)
