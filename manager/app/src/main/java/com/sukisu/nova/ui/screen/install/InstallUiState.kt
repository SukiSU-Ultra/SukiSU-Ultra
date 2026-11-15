package com.sukisu.nova.ui.screen.install

import androidx.compose.runtime.Immutable
import com.sukisu.nova.ui.kernelFlash.KpmPatchOption
import com.sukisu.nova.ui.util.LkmSelection

@Immutable
internal data class InstallUiState(
    val installMethod: InstallMethod?,
    val lkmSelection: LkmSelection,
    val partitionSelectionIndex: Int,
    val displayPartitions: List<String>,
    val remotePartitionSelectionIndex: Int,
    val remoteDisplayPartitions: List<String>,
    val currentKmi: String,
    val slotSuffix: String,
    val installMethodOptions: List<InstallMethod>,
    val canSelectPartition: Boolean,
    val advancedOptionsShown: Boolean,
    val allowShell: Boolean,
    val enableAdb: Boolean,
    val forceBackup: Boolean,
    val canForceBackup: Boolean,
    val kpmPatchOption: KpmPatchOption,
    val kpmBootExpanded: Boolean,
    val kpmBootUri: android.net.Uri?,
    val canPatchKpm: Boolean,
    val blockModulesEnabled: Boolean,
    val blockModules: String,
    val blockModulesValid: Boolean,
    val spoofEnabled: Boolean = false,
    val spoofRelease: String,
    val spoofVersion: String,
) {
    val kpmEnabled: Boolean get() = kpmPatchOption.enabled
    val canInstall: Boolean
        get() = if (installMethod == null) canPatchKpm && kpmEnabled else blockModulesValid
    val canSelectKpmBoot: Boolean
        get() = kpmEnabled && installMethod !is InstallMethod.HorizonKernel
}

@Immutable
internal data class InstallScreenActions(
    val onBack: () -> Unit,
    val onDownloadFile: () -> Unit,
    val onSelectMethod: (InstallMethod) -> Unit,
    val onSelectBootImage: (InstallMethod) -> Unit,
    val onUploadLkm: () -> Unit,
    val onClearLkm: () -> Unit,
    val onSelectPartition: (Int) -> Unit,
    val onNext: () -> Unit,
    val onAdvancedOptionsClicked: () -> Unit,
    val onPatchKpmFile: () -> Unit,
    val onKpmOptionChange: (KpmPatchOption) -> Unit,
    val onToggleKpmBoot: () -> Unit,
    val onClearKpmBoot: () -> Unit,
    val onSelectAllowShell: (Boolean) -> Unit,
    val onSelectEnableAdb: (Boolean) -> Unit,
    val onSelectForceBackup: (Boolean) -> Unit,
    val onHorizonKernelSelected: (InstallMethod.HorizonKernel) -> Unit = {},
    val onReopenSlotDialog: (InstallMethod.HorizonKernel) -> Unit = {},
    val onSelectBlockModules: (Boolean) -> Unit,
    val onBlockModulesChange: (String) -> Unit,
    val onSpoofEnabledChange: (Boolean) -> Unit,
    val onSpoofReleaseChange: (String) -> Unit,
    val onSpoofVersionChange: (String) -> Unit,
)
