package com.sukisu.ultra.ui.screen.susfs.content.miuix

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.screen.susfs.component.miuix.BackupRestoreComponentMiuix
import com.sukisu.ultra.ui.screen.susfs.component.miuix.DescriptionCardMiuix
import com.sukisu.ultra.ui.screen.susfs.component.miuix.ResetButtonMiuix
import com.sukisu.ultra.ui.util.isAbDevice
import top.yukonga.miuix.kmp.basic.*
import top.yukonga.miuix.kmp.preference.OverlayDropdownPreference
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
    isLoading: Boolean,
    onShowSlotInfo: () -> Unit,
    cmdlineOrBootconfigPath: String = "",
    onCmdlineOrBootconfigApply: (String) -> Unit = {},
    onReset: (() -> Unit)? = null,
    onApply: (() -> Unit)? = null,
    onConfigReload: () -> Unit
) {
    val isAbDevice = produceState(initialValue = false) {
        value = isAbDevice()
    }.value

    // SAF file picker for `/proc/cmdline` (non-GKI) or `/proc/bootconfig`
    // (GKI) replacement. Empty MIME array lets the user choose any plain
    // text file.
    val cmdlineFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri -> uri?.let { onCmdlineOrBootconfigApply(it.toString()) } }

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

            .fillMaxWidth(),
        enabled = !isLoading
    )

    AppCard(
        modifier = Modifier

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
            enabled = !isLoading
        )
    }

    // 当前值显示
    if (onApply != null) {
        TextButton(
            text = stringResource(R.string.susfs_apply),
            onClick = onApply,
            enabled = !isLoading && (unameValue.isNotBlank() || buildTimeValue.isNotBlank()),
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.textButtonColorsPrimary(),
        )
    }

    if (isAbDevice) {
        AppCard(
            modifier = Modifier

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

    // Cmdline / Bootconfig 卡片
    AppCard(
        modifier = Modifier

            .fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = stringResource(R.string.susfs_cmdline_or_bootconfig_title),
                    style = MiuixTheme.textStyles.title3,
                    fontWeight = FontWeight.Medium,
                    color = colorScheme.primary
                )
            }
            Text(
                text = stringResource(R.string.susfs_cmdline_or_bootconfig_description),
                fontSize = 13.sp,
                color = colorScheme.onSurfaceVariantSummary,
                lineHeight = 16.sp
            )
            AppCard(
                colors = CardDefaults.defaultColors(
                    color = colorScheme.surfaceVariant.copy(alpha = 0.3f)
                )
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
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
                        fontSize = 13.sp,
                        color = colorScheme.onSurfaceVariantSummary
                    )
                }
            }
            Button(
                onClick = {
                    cmdlineFileLauncher.launch(arrayOf("text/plain", "application/octet-stream", "*/*"))
                },
                enabled = !isLoading,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .padding(vertical = 4.dp),
                cornerRadius = 8.dp
            ) {
                Text(stringResource(R.string.susfs_cmdline_or_bootconfig_pick_file))
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
            onClick = onReset,
            enabled = !isLoading
        )
    }
}
