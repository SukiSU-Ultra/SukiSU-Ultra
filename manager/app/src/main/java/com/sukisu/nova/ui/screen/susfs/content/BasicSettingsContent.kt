package com.sukisu.nova.ui.screen.susfs.content

import androidx.compose.runtime.Composable
import com.sukisu.nova.ui.LocalUiMode
import com.sukisu.nova.ui.UiMode
import com.sukisu.nova.ui.screen.susfs.content.miuix.BasicSettingsContentMiuix
import com.sukisu.nova.ui.screen.susfs.content.material.BasicSettingsContentMaterial

@Composable
fun BasicSettingsContent(
    unameValue: String,
    onUnameValueChange: (String) -> Unit,
    buildTimeValue: String,
    onBuildTimeValueChange: (String) -> Unit,
    executeInPostFsData: Boolean,
    onExecuteInPostFsDataChange: (Boolean) -> Unit,
    isLoading: Boolean,
    onShowSlotInfo: () -> Unit,
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
            isLoading = isLoading,
            onShowSlotInfo = onShowSlotInfo,
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
            isLoading = isLoading,
            onShowSlotInfo = onShowSlotInfo,
            cmdlineOrBootconfigPath = cmdlineOrBootconfigPath,
            onCmdlineOrBootconfigApply = onCmdlineOrBootconfigApply,
            onReset = onReset,
            onApply = onApply,
            onConfigReload = onConfigReload
        )
    }
}
