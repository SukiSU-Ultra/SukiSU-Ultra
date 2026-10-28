package com.sukisu.ultra.ui.screen.susfs.content

import androidx.compose.runtime.Composable
import androidx.compose.foundation.layout.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedSwitchItem
import com.sukisu.ultra.ui.component.miuix.AppCard
import top.yukonga.miuix.kmp.preference.SwitchPreference

@Composable
fun FeatureTogglesContent(
    enableLog: Boolean,
    onEnableLogChange: (Boolean) -> Unit,
    autoStartEnabled: Boolean,
    canEnableAutoStart: Boolean,
    isLoading: Boolean,
    onAutoStartToggle: (Boolean) -> Unit,
    enableHideBl: Boolean,
    onEnableHideBlChange: (Boolean) -> Unit,
    enableCleanupResidue: Boolean,
    onEnableCleanupResidueChange: (Boolean) -> Unit,
    enableAvcLogSpoofing: Boolean,
    onEnableAvcLogSpoofingChange: (Boolean) -> Unit,
    hideSusMountsForAllProcs: Boolean,
    onHideSusMountsForAllProcsChange: (Boolean) -> Unit,
) {
    com.sukisu.ultra.ui.component.ConfigStatusNote(stringResource(R.string.config_status_explanation))
    when (LocalUiMode.current) {
        UiMode.Material -> {
            SegmentedColumn(
                content = listOf(
                    {
                        SegmentedSwitchItem(
                            title = stringResource(R.string.susfs_enable_log_label),
                            summary = stringResource(R.string.susfs_log_config_description),
                            checked = enableLog,
                            enabled = !isLoading,
                            onCheckedChange = onEnableLogChange,
                        )
                    },
                    {
                        SegmentedSwitchItem(
                            title = stringResource(R.string.susfs_autostart_title),
                            summary = stringResource(if (canEnableAutoStart) R.string.susfs_autostart_description else R.string.susfs_autostart_requirement),
                            checked = autoStartEnabled,
                            enabled = !isLoading && (canEnableAutoStart || autoStartEnabled),
                            onCheckedChange = onAutoStartToggle,
                        )
                    },
                    {
                        SegmentedSwitchItem(
                            title = stringResource(R.string.hide_bl_script),
                            summary = stringResource(R.string.hide_bl_script_description),
                            checked = enableHideBl,
                            enabled = !isLoading,
                            onCheckedChange = onEnableHideBlChange,
                        )
                    },
                    {
                        SegmentedSwitchItem(
                            title = stringResource(R.string.cleanup_residue),
                            summary = stringResource(R.string.cleanup_residue_description),
                            checked = enableCleanupResidue,
                            enabled = !isLoading,
                            onCheckedChange = onEnableCleanupResidueChange,
                        )
                    },
                    {
                        SegmentedSwitchItem(
                            title = stringResource(R.string.avc_log_spoofing),
                            summary = stringResource(R.string.avc_log_spoofing_description),
                            checked = enableAvcLogSpoofing,
                            enabled = !isLoading,
                            onCheckedChange = onEnableAvcLogSpoofingChange,
                        )
                    },
                    {
                        SegmentedSwitchItem(
                            title = stringResource(R.string.susfs_hide_mounts_for_all_procs_label),
                            summary = stringResource(if (hideSusMountsForAllProcs) R.string.susfs_hide_mounts_for_all_procs_enabled_description else R.string.susfs_hide_mounts_for_all_procs_disabled_description),
                            checked = hideSusMountsForAllProcs,
                            enabled = !isLoading,
                            onCheckedChange = onHideSusMountsForAllProcsChange,
                        )
                    },
                ),
            )

        }
        UiMode.Miuix -> {
            AppCard(modifier = Modifier.fillMaxWidth()) {
                SwitchPreference(
                    title = stringResource(R.string.susfs_enable_log_label),
                    summary = stringResource(R.string.susfs_log_config_description),
                    checked = enableLog,
                    enabled = !isLoading,
                    onCheckedChange = onEnableLogChange,
                )
                // 开机自启动开关
                SwitchPreference(
                    title = stringResource(R.string.susfs_autostart_title),
                    summary = if (canEnableAutoStart) {
                        stringResource(R.string.susfs_autostart_description)
                    } else {
                        stringResource(R.string.susfs_autostart_requirement)
                    },
                    checked = autoStartEnabled,
                    onCheckedChange = onAutoStartToggle,
                    enabled = !isLoading && (canEnableAutoStart || autoStartEnabled)
                )

                // 隐藏BL脚本开关
                SwitchPreference(
                    title = stringResource(R.string.hide_bl_script),
                    summary = stringResource(R.string.hide_bl_script_description),
                    checked = enableHideBl,
                    onCheckedChange = onEnableHideBlChange,
                    enabled = !isLoading
                )

                // 清理残留脚本开关
                SwitchPreference(
                    title = stringResource(R.string.cleanup_residue),
                    summary = stringResource(R.string.cleanup_residue_description),
                    checked = enableCleanupResidue,
                    onCheckedChange = onEnableCleanupResidueChange,
                    enabled = !isLoading
                )

                // AVC日志欺骗开关
                SwitchPreference(
                    title = stringResource(R.string.avc_log_spoofing),
                    summary = stringResource(R.string.avc_log_spoofing_description),
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
                    checked = hideSusMountsForAllProcs,
                    onCheckedChange = onHideSusMountsForAllProcsChange,
                    enabled = !isLoading
                )
            }

        }
    }
}
