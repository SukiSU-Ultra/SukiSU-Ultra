package com.sukisu.ultra.ui.screen.susfs.content.material

import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.susfs.component.material.BackupRestoreComponentMaterial
import com.sukisu.ultra.ui.screen.susfs.component.material.DescriptionCardMaterial
import com.sukisu.ultra.ui.screen.susfs.component.material.ResetButtonMaterial
import com.sukisu.ultra.ui.util.isAbDevice

@Composable
fun BasicSettingsContentMaterial(
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
    val isAbDevice = produceState(initialValue = false) { value = isAbDevice() }.value

    // 说明卡片
    DescriptionCardMaterial(
        title = stringResource(R.string.susfs_config_description),
        description = stringResource(R.string.susfs_config_description_text)
    )

    // 执行位置选择
    Card(
        modifier = Modifier.padding(top = 12.dp).fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f))
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.PlayArrow,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.susfs_execution_location_label),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.primary
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                FilterChip(
                    selected = !executeInPostFsData,
                    onClick = { onExecuteInPostFsDataChange(false) },
                    label = { Text(stringResource(R.string.susfs_execution_location_service)) },
                    enabled = !isLoading,
                    modifier = Modifier.weight(1f)
                )
                FilterChip(
                    selected = executeInPostFsData,
                    onClick = { onExecuteInPostFsDataChange(true) },
                    label = { Text(stringResource(R.string.susfs_execution_location_post_fs_data)) },
                    enabled = !isLoading,
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }

    // Uname输入框
    OutlinedTextField(
        value = unameValue,
        onValueChange = onUnameValueChange,
        label = { Text(stringResource(R.string.susfs_uname_label)) },
        modifier = Modifier.padding(top = 12.dp).fillMaxWidth(),
        enabled = !isLoading,
        singleLine = true
    )

    // 构建时间输入框
    OutlinedTextField(
        value = buildTimeValue,
        onValueChange = onBuildTimeValueChange,
        label = { Text(stringResource(R.string.susfs_build_time_label)) },
        modifier = Modifier.padding(top = 12.dp).fillMaxWidth(),
        enabled = !isLoading,
        singleLine = true
    )

    // 当前值显示
    Card(modifier = Modifier.padding(top = 12.dp).fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(text = stringResource(R.string.susfs_current_value, unameValue), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(text = stringResource(R.string.susfs_current_build_time, buildTimeValue), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(text = stringResource(R.string.susfs_current_execution_location, if (executeInPostFsData) "Post-FS-Data" else "Service"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }

    // 应用按钮
    if (onApply != null) {
        Button(
            onClick = { onApply() },
            enabled = !isLoading && (unameValue.isNotBlank() || buildTimeValue.isNotBlank()),
            modifier = Modifier.padding(top = 12.dp).fillMaxWidth()
        ) {
            Text(stringResource(R.string.susfs_apply))
        }
    }

    // 开关设置卡片
    Card(modifier = Modifier.padding(top = 12.dp).fillMaxWidth()) {
        Column {
            ListItem(
                headlineContent = { Text(stringResource(R.string.susfs_autostart_title)) },
                supportingContent = { Text(if (canEnableAutoStart) stringResource(R.string.susfs_autostart_description) else stringResource(R.string.susfs_autostart_requirement)) },
                leadingContent = { Icon(Icons.Default.AutoMode, contentDescription = null) },
                trailingContent = { Switch(checked = autoStartEnabled, onCheckedChange = onAutoStartToggle, enabled = !isLoading && canEnableAutoStart) }
            )
            HorizontalDivider()
            ListItem(
                headlineContent = { Text(stringResource(R.string.hide_bl_script)) },
                supportingContent = { Text(stringResource(R.string.hide_bl_script_description)) },
                leadingContent = { Icon(Icons.Default.Security, contentDescription = null) },
                trailingContent = { Switch(checked = enableHideBl, onCheckedChange = onEnableHideBlChange, enabled = !isLoading) }
            )
            HorizontalDivider()
            ListItem(
                headlineContent = { Text(stringResource(R.string.cleanup_residue)) },
                supportingContent = { Text(stringResource(R.string.cleanup_residue_description)) },
                leadingContent = { Icon(Icons.Default.CleaningServices, contentDescription = null) },
                trailingContent = { Switch(checked = enableCleanupResidue, onCheckedChange = onEnableCleanupResidueChange, enabled = !isLoading) }
            )
            HorizontalDivider()
            ListItem(
                headlineContent = { Text(stringResource(R.string.avc_log_spoofing)) },
                supportingContent = { Text(stringResource(R.string.avc_log_spoofing_description)) },
                leadingContent = { Icon(Icons.Default.VisibilityOff, contentDescription = null) },
                trailingContent = { Switch(checked = enableAvcLogSpoofing, onCheckedChange = onEnableAvcLogSpoofingChange, enabled = !isLoading) }
            )
            HorizontalDivider()
            ListItem(
                headlineContent = { Text(stringResource(R.string.susfs_hide_mounts_for_all_procs_label)) },
                supportingContent = { Text(if (hideSusMountsForAllProcs) stringResource(R.string.susfs_hide_mounts_for_all_procs_enabled_description) else stringResource(R.string.susfs_hide_mounts_for_all_procs_disabled_description)) },
                leadingContent = { Icon(if (hideSusMountsForAllProcs) Icons.Default.VisibilityOff else Icons.Default.Visibility, contentDescription = null) },
                trailingContent = { Switch(checked = hideSusMountsForAllProcs, onCheckedChange = onHideSusMountsForAllProcsChange, enabled = !isLoading) }
            )
        }
    }

    // 槽位信息按钮
    if (isAbDevice) {
        Card(modifier = Modifier.padding(top = 12.dp).fillMaxWidth()) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Info, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Spacer(Modifier.width(10.dp))
                    Text(text = stringResource(R.string.susfs_slot_info_title), style = MaterialTheme.typography.titleMedium)
                }
                Text(text = stringResource(R.string.susfs_slot_info_description), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Button(onClick = onShowSlotInfo, enabled = !isLoading, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.susfs_slot_info_title))
                }
            }
        }
    }

    // 备份还原
    BackupRestoreComponentMaterial(
        isLoading = isLoading,
        onLoadingChange = { },
        onConfigReload = onConfigReload
    )

    // 重置按钮
    if (onReset != null) {
        ResetButtonMaterial(
            title = stringResource(R.string.susfs_reset_confirm_title),
            onClick = onReset
        )
    }
}
