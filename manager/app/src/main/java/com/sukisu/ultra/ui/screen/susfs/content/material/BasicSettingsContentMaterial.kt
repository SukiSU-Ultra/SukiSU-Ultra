package com.sukisu.ultra.ui.screen.susfs.content.material

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
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
import com.sukisu.ultra.ui.theme.backgroundAwareColor
import com.sukisu.ultra.ui.util.isAbDevice

@Composable
fun BasicSettingsContentMaterial(
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
    val isAbDevice = produceState(initialValue = false) { value = isAbDevice() }.value

    // SAF file picker for `/proc/cmdline` (non-GKI) or `/proc/bootconfig`
    // (GKI) replacement. Empty MIME array lets the user choose any plain
    // text file.
    val cmdlineFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri -> uri?.let { onCmdlineOrBootconfigApply(it.toString()) } }


    // 说明卡片
    DescriptionCardMaterial(
        title = stringResource(R.string.susfs_config_description),
        description = stringResource(R.string.susfs_config_description_text)
    )

    // 执行位置选择
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceBright)
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
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
                    modifier = Modifier.weight(1f),
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = backgroundAwareColor(MaterialTheme.colorScheme.secondaryContainer),
                    ),
                )
                FilterChip(
                    selected = executeInPostFsData,
                    onClick = { onExecuteInPostFsDataChange(true) },
                    label = { Text(stringResource(R.string.susfs_execution_location_post_fs_data)) },
                    enabled = !isLoading,
                    modifier = Modifier.weight(1f),
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = backgroundAwareColor(MaterialTheme.colorScheme.secondaryContainer),
                    ),
                )
            }
        }
    }

    // Uname输入框
    OutlinedTextField(
        value = unameValue,
        onValueChange = onUnameValueChange,
        label = { Text(stringResource(R.string.susfs_uname_label)) },
        modifier = Modifier.fillMaxWidth(),
        enabled = !isLoading,
        singleLine = true,
        colors = OutlinedTextFieldDefaults.colors(
            unfocusedLabelColor = MaterialTheme.colorScheme.onSurface,
            focusedLabelColor = MaterialTheme.colorScheme.primary,
        ),
    )

    // 构建时间输入框
    OutlinedTextField(
        value = buildTimeValue,
        onValueChange = onBuildTimeValueChange,
        label = { Text(stringResource(R.string.susfs_build_time_label)) },
        modifier = Modifier.fillMaxWidth(),
        enabled = !isLoading,
        singleLine = true,
        colors = OutlinedTextFieldDefaults.colors(
            unfocusedLabelColor = MaterialTheme.colorScheme.onSurface,
            focusedLabelColor = MaterialTheme.colorScheme.primary,
        ),
    )

    // 当前值显示
    if (onApply != null) {
        Button(
            onClick = { onApply() },
            enabled = !isLoading && (unameValue.isNotBlank() || buildTimeValue.isNotBlank()),
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(stringResource(R.string.susfs_apply))
        }
    }


    if (isAbDevice) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(text = stringResource(R.string.susfs_slot_info_title), style = MaterialTheme.typography.titleMedium)
                }
                Text(text = stringResource(R.string.susfs_slot_info_description), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Button(onClick = onShowSlotInfo, enabled = !isLoading, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.susfs_slot_info_title))
                }
            }
        }
    }

    // Cmdline / Bootconfig 卡片
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = stringResource(R.string.susfs_cmdline_or_bootconfig_title),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.primary
                )
            }
            Text(
                text = stringResource(R.string.susfs_cmdline_or_bootconfig_description),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceBright
                )
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState())
                        .padding(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(
                            R.string.susfs_cmdline_or_bootconfig_current,
                            cmdlineOrBootconfigPath.ifBlank {
                                stringResource(R.string.susfs_cmdline_or_bootconfig_none)
                            }
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            Button(
                onClick = {
                    cmdlineFileLauncher.launch(arrayOf("text/plain", "application/octet-stream", "*/*"))
                },
                enabled = !isLoading,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.FolderOpen, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.susfs_cmdline_or_bootconfig_pick_file))
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
            onClick = onReset,
            enabled = !isLoading
        )
    }
}
