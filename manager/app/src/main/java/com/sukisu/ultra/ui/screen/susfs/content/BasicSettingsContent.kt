package com.sukisu.ultra.ui.screen.susfs.content

import android.content.Context
import androidx.compose.runtime.Composable
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.screen.susfs.content.miuix.BasicSettingsContentMiuix
import com.sukisu.ultra.ui.screen.susfs.content.material.BasicSettingsContentMaterial

@Composable
fun BasicSettingsContent(
    unameValue: String,
    onUnameValueChange: (String) -> Unit,
    buildTimeValue: String,
    onBuildTimeValueChange: (String) -> Unit,
    executeInPostFsData: Boolean,
    onExecuteInPostFsDataChange: (Boolean) -> Unit,
    autoStartEnabled: Boolean,
    canEnableAutoStart: Boolean,
    isLoading: Boolean,
    onAutoStartToggle: (Boolean) -> Unit,
    onShowSlotInfo: () -> Unit,
    context: Context,
    enableHideBl: Boolean,
    onEnableHideBlChange: (Boolean) -> Unit,
    enableCleanupResidue: Boolean,
    onEnableCleanupResidueChange: (Boolean) -> Unit,
    enableAvcLogSpoofing: Boolean,
    onEnableAvcLogSpoofingChange: (Boolean) -> Unit,
    hideSusMountsForAllProcs: Boolean,
    onHideSusMountsForAllProcsChange: (Boolean) -> Unit,
    cmdlineOrBootconfigPath: String = "",
    onCmdlineOrBootconfigApply: (String) -> Unit = {},
    onReset: (() -> Unit)? = null,
    onApply: (() -> Unit)? = null,
    onConfigReload: () -> Unit
) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> BasicSettingsContentMiuix(
            unameValue = unameValue,
            onUnameValueChange = onUnameValueChange,
            buildTimeValue = buildTimeValue,
            onBuildTimeValueChange = onBuildTimeValueChange,
            executeInPostFsData = executeInPostFsData,
            onExecuteInPostFsDataChange = onExecuteInPostFsDataChange,
            autoStartEnabled = autoStartEnabled,
            canEnableAutoStart = canEnableAutoStart,
            isLoading = isLoading,
            onAutoStartToggle = onAutoStartToggle,
            onShowSlotInfo = onShowSlotInfo,
            context = context,
            enableHideBl = enableHideBl,
            onEnableHideBlChange = onEnableHideBlChange,
            enableCleanupResidue = enableCleanupResidue,
            onEnableCleanupResidueChange = onEnableCleanupResidueChange,
            enableAvcLogSpoofing = enableAvcLogSpoofing,
            onEnableAvcLogSpoofingChange = onEnableAvcLogSpoofingChange,
            hideSusMountsForAllProcs = hideSusMountsForAllProcs,
            onHideSusMountsForAllProcsChange = onHideSusMountsForAllProcsChange,
            cmdlineOrBootconfigPath = cmdlineOrBootconfigPath,
            onCmdlineOrBootconfigApply = onCmdlineOrBootconfigApply,
            onReset = onReset,
            onApply = onApply,
            onConfigReload = onConfigReload
        )
        UiMode.Material -> BasicSettingsContentMaterial(
            unameValue = unameValue,
            onUnameValueChange = onUnameValueChange,
            buildTimeValue = buildTimeValue,
            onBuildTimeValueChange = onBuildTimeValueChange,
            executeInPostFsData = executeInPostFsData,
            onExecuteInPostFsDataChange = onExecuteInPostFsDataChange,
            autoStartEnabled = autoStartEnabled,
            canEnableAutoStart = canEnableAutoStart,
            isLoading = isLoading,
            onAutoStartToggle = onAutoStartToggle,
            onShowSlotInfo = onShowSlotInfo,
            context = context,
            enableHideBl = enableHideBl,
            onEnableHideBlChange = onEnableHideBlChange,
            enableCleanupResidue = enableCleanupResidue,
            onEnableCleanupResidueChange = onEnableCleanupResidueChange,
            enableAvcLogSpoofing = enableAvcLogSpoofing,
            onEnableAvcLogSpoofingChange = onEnableAvcLogSpoofingChange,
            hideSusMountsForAllProcs = hideSusMountsForAllProcs,
            onHideSusMountsForAllProcsChange = onHideSusMountsForAllProcsChange,
            cmdlineOrBootconfigPath = cmdlineOrBootconfigPath,
            onCmdlineOrBootconfigApply = onCmdlineOrBootconfigApply,
            onReset = onReset,
            onApply = onApply,
            onConfigReload = onConfigReload
        )
    }
}
