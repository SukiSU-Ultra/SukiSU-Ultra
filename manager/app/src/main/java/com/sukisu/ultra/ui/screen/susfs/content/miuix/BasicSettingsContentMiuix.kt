package com.sukisu.ultra.ui.screen.susfs.content.miuix

import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.susfs.component.miuix.BackupRestoreComponentMiuix
import com.sukisu.ultra.ui.screen.susfs.component.miuix.DescriptionCardMiuix
import com.sukisu.ultra.ui.screen.susfs.component.miuix.ResetButtonMiuix
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSManager
import com.sukisu.ultra.ui.util.isAbDevice
import top.yukonga.miuix.kmp.basic.*
import top.yukonga.miuix.kmp.preference.OverlayDropdownPreference
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme

@Composable
fun BasicSettingsContentMiuix(
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
    onReset: (() -> Unit)? = null,
    onApply: (() -> Unit)? = null,
    onConfigReload: () -> Unit
) {
    val isAbDevice = produceState(initialValue = false) {
        value = isAbDevice()
    }.value

    // 执行位置选择
    val locationItems = listOf(
        stringResource(R.string.susfs_execution_location_service),
        stringResource(R.string.susfs_execution_location_post_fs_data)
    )

    // 说明卡片
    DescriptionCardMiuix(
        title = stringResource(R.string.susfs_config_description),
        description = stringResource(R.string.susfs_config_description_text)
    )

    // Uname输入框
    TextField(
        value = unameValue,
        onValueChange = onUnameValueChange,
        label = stringResource(R.string.susfs_uname_label),
        useLabelAsPlaceholder = true,
        modifier = Modifier
            .padding(top = 12.dp)
            .fillMaxWidth(),
        enabled = !isLoading
    )

    // 构建时间伪装输入框
    TextField(
        value = buildTimeValue,
        onValueChange = onBuildTimeValueChange,
        label = stringResource(R.string.susfs_build_time_label),
        useLabelAsPlaceholder = true,
        modifier = Modifier
            .padding(top = 12.dp)
            .fillMaxWidth(),
        enabled = !isLoading
    )

    Card(
        modifier = Modifier
            .padding(top = 12.dp)
            .fillMaxWidth(),
    ) {
        OverlayDropdownPreference(
            title = stringResource(R.string.susfs_execution_location_label),
            summary = if (executeInPostFsData) {
                stringResource(R.string.susfs_execution_location_post_fs_data)
            } else {
                stringResource(R.string.susfs_execution_location_service)
            },
            items = locationItems,
            selectedIndex = if (executeInPostFsData) 1 else 0,
            onSelectedIndexChange = { index ->
                onExecuteInPostFsDataChange(index == 1)
            },
            enabled = !isLoading,
            startAction = {
                Icon(
                    Icons.Default.LocationOn,
                    contentDescription = null,
                    tint = colorScheme.primary,
                    modifier = Modifier.padding(end = 16.dp)
                )
            }
        )
    }

    // 当前值显示
    Card(
        modifier = Modifier
            .padding(top = 12.dp)
            .fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Text(
                text = stringResource(R.string.susfs_current_value, SuSFSManager.getUnameValue(context)),
                style = MiuixTheme.textStyles.body2.copy(fontSize = 13.sp),
                color = colorScheme.onSurfaceVariantSummary
            )
            Text(
                text = stringResource(R.string.susfs_current_build_time, SuSFSManager.getBuildTimeValue(context)),
                style = MiuixTheme.textStyles.body2.copy(fontSize = 13.sp),
                color = colorScheme.onSurfaceVariantSummary
            )
            Text(
                text = stringResource(R.string.susfs_current_execution_location, if (SuSFSManager.getExecuteInPostFsData(context)) "Post-FS-Data" else "Service"),
                style = MiuixTheme.textStyles.body2.copy(fontSize = 13.sp),
                color = colorScheme.onSurfaceVariantSummary
            )
        }
    }

    // 应用按钮
    if (onApply != null) {
        Card(
            modifier = Modifier
                .padding(top = 12.dp)
                .fillMaxWidth(),
        ) {
            Button(
                onClick = { onApply() },
                enabled = !isLoading && (unameValue.isNotBlank() || buildTimeValue.isNotBlank()),
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp),
                cornerRadius = 8.dp
            ) {
                Text(
                    text = stringResource(R.string.susfs_apply)
                )
            }
        }
    }

    Card(
        modifier = Modifier
            .padding(top = 12.dp)
            .fillMaxWidth(),
    ) {
        // 开机自启动开关
        SwitchPreference(
            title = stringResource(R.string.susfs_autostart_title),
            summary = if (canEnableAutoStart) {
                stringResource(R.string.susfs_autostart_description)
            } else {
                stringResource(R.string.susfs_autostart_requirement)
            },
            startAction = {
                Icon(
                    Icons.Default.AutoMode,
                    modifier = Modifier.padding(end = 16.dp),
                    contentDescription = stringResource(R.string.susfs_autostart_title),
                    tint = if (canEnableAutoStart) colorScheme.onBackground else colorScheme.onSurfaceVariantSummary
                )
            },
            checked = autoStartEnabled,
            onCheckedChange = onAutoStartToggle,
            enabled = !isLoading && canEnableAutoStart
        )

        // 隐藏BL脚本开关
        SwitchPreference(
            title = stringResource(R.string.hide_bl_script),
            summary = stringResource(R.string.hide_bl_script_description),
            startAction = {
                Icon(
                    Icons.Default.Security,
                    modifier = Modifier.padding(end = 16.dp),
                    contentDescription = stringResource(R.string.hide_bl_script),
                    tint = colorScheme.onBackground
                )
            },
            checked = enableHideBl,
            onCheckedChange = onEnableHideBlChange,
            enabled = !isLoading
        )

        // 清理残留脚本开关
        SwitchPreference(
            title = stringResource(R.string.cleanup_residue),
            summary = stringResource(R.string.cleanup_residue_description),
            startAction = {
                Icon(
                    Icons.Default.CleaningServices,
                    modifier = Modifier.padding(end = 16.dp),
                    contentDescription = stringResource(R.string.cleanup_residue),
                    tint = colorScheme.onBackground
                )
            },
            checked = enableCleanupResidue,
            onCheckedChange = onEnableCleanupResidueChange,
            enabled = !isLoading
        )

        // AVC日志欺骗开关
        SwitchPreference(
            title = stringResource(R.string.avc_log_spoofing),
            summary = stringResource(R.string.avc_log_spoofing_description),
            startAction = {
                Icon(
                    Icons.Default.VisibilityOff,
                    modifier = Modifier.padding(end = 16.dp),
                    contentDescription = stringResource(R.string.avc_log_spoofing),
                    tint = colorScheme.onBackground
                )
            },
            checked = enableAvcLogSpoofing,
            onCheckedChange = onEnableAvcLogSpoofingChange,
            enabled = !isLoading
        )

        // 对所有进程隐藏SuS挂载开关
        SwitchPreference(
            title = stringResource(R.string.susfs_hide_mounts_for_all_procs_label),
            summary = if (hideSusMountsForAllProcs) {
                stringResource(R.string.susfs_hide_mounts_for_all_procs_enabled_description)
            } else {
                stringResource(R.string.susfs_hide_mounts_for_all_procs_disabled_description)
            },
            startAction = {
                Icon(
                    if (hideSusMountsForAllProcs) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                    modifier = Modifier.padding(end = 16.dp),
                    contentDescription = stringResource(R.string.susfs_hide_mounts_for_all_procs_label),
                    tint = colorScheme.onBackground
                )
            },
            checked = hideSusMountsForAllProcs,
            onCheckedChange = onHideSusMountsForAllProcsChange,
            enabled = !isLoading
        )
    }

    // 槽位信息按钮
    if (isAbDevice) {
        Card(
            modifier = Modifier
                .padding(top = 12.dp)
                .fillMaxWidth(),
        ) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Default.Info,
                        contentDescription = null,
                        tint = colorScheme.primary,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = stringResource(R.string.susfs_slot_info_title),
                        style = MiuixTheme.textStyles.title3,
                        fontWeight = FontWeight.Medium,
                        color = colorScheme.onBackground
                    )
                }
                Text(
                    text = stringResource(R.string.susfs_slot_info_description),
                    style = MiuixTheme.textStyles.body2.copy(fontSize = 13.sp),
                    color = colorScheme.onSurfaceVariantSummary,
                    lineHeight = 16.sp
                )
                Button(
                    onClick = onShowSlotInfo,
                    enabled = !isLoading,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .padding(vertical = 8.dp),
                    cornerRadius = 8.dp
                ) {
                    Text(
                        text = stringResource(R.string.susfs_slot_info_title)
                    )
                }
            }
        }
    }

    BackupRestoreComponentMiuix(
        isLoading = isLoading,
        onLoadingChange = { },
        onConfigReload = onConfigReload
    )

    // 重置按钮
    if (onReset != null) {
        ResetButtonMiuix(
            title = stringResource(R.string.susfs_reset_confirm_title),
            onClick = onReset
        )
    }
}
