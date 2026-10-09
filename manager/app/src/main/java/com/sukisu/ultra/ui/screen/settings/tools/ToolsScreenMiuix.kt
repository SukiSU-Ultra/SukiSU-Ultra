package com.sukisu.ultra.ui.screen.settings.tools

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Backup
import androidx.compose.material.icons.rounded.FolderDelete
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Restore
import androidx.compose.material.icons.rounded.Security
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.KsuIsValid
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.getSELinuxStatusRaw
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.preference.CheckboxPreference
import top.yukonga.miuix.kmp.preference.OverlayDropdownPreference
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.textStyles
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
fun ToolsMiuix(
    state: ToolsUiState,
    actions: ToolsActions
) {
    val scrollBehavior = MiuixScrollBehavior()
    val enableBlur = LocalEnableBlur.current
    val backdrop = rememberBlurBackdrop(enableBlur)
    val blurActive = backdrop != null
    val barColor = if (blurActive) Color.Transparent else colorScheme.surface

    Scaffold(
        topBar = {
            BlurredBar(backdrop) {
                TopAppBar(
                    color = barColor,
                    title = stringResource(R.string.tools),
                    scrollBehavior = scrollBehavior,
                    navigationIcon = {
                        IconButton(onClick = actions.onBack) {
                            val layoutDirection = LocalLayoutDirection.current
                            Icon(
                                modifier = Modifier.graphicsLayer {
                                    if (layoutDirection == LayoutDirection.Rtl) scaleX = -1f
                                },
                                imageVector = MiuixIcons.Back,
                                contentDescription = null
                            )
                        }
                    }
                )
            }
        },
        popupHost = { },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxHeight()
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .padding(horizontal = 12.dp),
            contentPadding = innerPadding,
            overscrollEffect = null,
        ) {
            item {
                KsuIsValid {
                    SelinuxToggleSectionMiuix(
                        selinuxEnforcing = state.selinuxEnforcing,
                        selinuxLoading = state.selinuxLoading,
                        onSelinuxToggle = actions.onSelinuxToggle
                    )

                    Card(
                        modifier = Modifier
                            .padding(top = 12.dp)
                            .fillMaxWidth(),
                    ) {
                        val umountManager = stringResource(id = R.string.umount_path_manager)
                        ArrowPreference(
                            title = umountManager,
                            startAction = {
                                Icon(
                                    Icons.Rounded.FolderDelete,
                                    modifier = Modifier.padding(end = 6.dp),
                                    contentDescription = umountManager,
                                    tint = colorScheme.onBackground
                                )
                            },
                            onClick = actions.onNavigateToUmountManager
                        )
                    }

                    Card(
                        modifier = Modifier
                            .padding(top = 12.dp)
                            .fillMaxWidth(),
                    ) {
                        val spoofCpuTitle = stringResource(id = R.string.tools_spoof_cpu_title)
                        ArrowPreference(
                            title = spoofCpuTitle,
                            summary = stringResource(R.string.tools_spoof_cpu_summary),
                            startAction = {
                                Icon(
                                    Icons.Rounded.Memory,
                                    modifier = Modifier.padding(end = 6.dp),
                                    contentDescription = spoofCpuTitle,
                                    tint = colorScheme.onBackground
                                )
                            },
                            onClick = actions.onOpenSpoofCpuDialog
                        )
                    }

                    AllowlistBackupSectionMiuix(
                        onBackup = actions.onBackupAllowlist,
                        onRestore = actions.onRestoreAllowlist
                    )
                }
            }
        }
    }
}

@Composable
private fun SelinuxToggleSectionMiuix(
    selinuxEnforcing: Boolean,
    selinuxLoading: Boolean,
    onSelinuxToggle: (Boolean) -> Unit
) {
    Card(
        modifier = Modifier
            .padding(top = 12.dp)
            .fillMaxWidth(),
    ) {
        val statusLabel = getSELinuxStatusRaw()
        SwitchPreference(
            title = stringResource(R.string.tools_selinux_toggle),
            summary = stringResource(R.string.tools_selinux_summary, statusLabel),
            startAction = {
                Icon(
                    imageVector = Icons.Rounded.Security,
                    modifier = Modifier.padding(end = 6.dp),
                    contentDescription = stringResource(id = R.string.tools_selinux_toggle),
                    tint = colorScheme.onBackground
                )
            },
            checked = selinuxEnforcing,
            enabled = !selinuxLoading,
            onCheckedChange = onSelinuxToggle
        )
    }
}

@Composable
private fun AllowlistBackupSectionMiuix(
    onBackup: () -> Unit,
    onRestore: () -> Unit
) {
    Card(
        modifier = Modifier
            .padding(vertical = 12.dp)
            .fillMaxWidth(),
    ) {
        ArrowPreference(
            title = stringResource(R.string.allowlist_backup_title),
            summary = stringResource(R.string.allowlist_backup_summary_picker),
            startAction = {
                Icon(
                    imageVector = Icons.Rounded.Backup,
                    modifier = Modifier.padding(end = 6.dp),
                    contentDescription = stringResource(R.string.allowlist_backup_title),
                    tint = colorScheme.onBackground
                )
            },
            onClick = onBackup
        )

        ArrowPreference(
            title = stringResource(R.string.allowlist_restore_title),
            summary = stringResource(R.string.allowlist_restore_summary_picker),
            startAction = {
                Icon(
                    imageVector = Icons.Rounded.Restore,
                    modifier = Modifier.padding(end = 6.dp),
                    contentDescription = stringResource(R.string.allowlist_restore_title),
                    tint = colorScheme.onBackground
                )
            },
            onClick = onRestore
        )
    }
}

@Composable
fun SpoofCpuDialogMiuix(
    currentCpuInfo: CpuInfo?,
    onDismiss: () -> Unit,
    onApply: (SpoofCpuParams) -> Unit
) {
    var selectedPreset by remember { mutableStateOf("custom") }
    var midrValue by remember { mutableStateOf(currentCpuInfo?.midrHex ?: "0x0") }
    var bogomipsValue by remember { mutableStateOf(currentCpuInfo?.bogomips?.toString() ?: "0") }
    var hwcapValue by remember { mutableStateOf(currentCpuInfo?.hwcap ?: "0x0") }
    var hwcap2Value by remember { mutableStateOf(currentCpuInfo?.hwcap2 ?: "0x0") }
    val coreCount = currentCpuInfo?.coreCount ?: 8
    var selectedCores by remember { mutableStateOf((0 until coreCount).toList()) }
    val showDialogState = remember { mutableStateOf(true) }

    val presetList = listOf(
        "custom" to stringResource(R.string.spoof_cpu_midr_custom),
        "0x413fd050" to "Cortex-A55",
        "0x413fd0b1" to "Cortex-A76",
        "0x413fd0d2" to "Cortex-A78",
        "0x413fd0d4" to "Cortex-A710",
        "0x413fd0d5" to "Cortex-A715",
        "0x413fd0c1" to "Cortex-X1",
        "0x413fd0e3" to "Cortex-X3",
        "0x413fd0c0" to "Neoverse N1",
        "0x511f804d" to "Kryo 4xx Gold",
        "0x511f805c" to "Kryo 5xx Gold",
        "0x513f8050" to "Kryo 6xx Gold+",
        "0x553f1000" to "Exynos M5"
    )

    if (showDialogState.value) {
        OverlayDialog(
            show = showDialogState.value,
            title = stringResource(R.string.spoof_cpu_dialog_title),
            onDismissRequest = {
                showDialogState.value = false
                onDismiss()
            },
            content = {
                Column(
                    modifier = Modifier
                        .verticalScroll(rememberScrollState())
                        .padding(horizontal = 24.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    // 警告提示
                    Text(
                        text = stringResource(R.string.spoof_cpu_warning),
                        color = colorScheme.error,
                        style = textStyles.body2
                    )

                    // 预设 SoC 选择
                    OverlayDropdownPreference(
                        title = stringResource(R.string.spoof_cpu_midr_preset_label),
                        summary = presetList.find { it.first == selectedPreset }?.second ?: "",
                        items = presetList.map { it.second },
                        selectedIndex = presetList.indexOfFirst { it.first == selectedPreset }.coerceAtLeast(0),
                        onSelectedIndexChange = { index ->
                            val (value, _) = presetList[index]
                            selectedPreset = value
                            if (value != "custom") {
                                midrValue = value
                            }
                        }
                    )

                    // MIDR 输入
                    TextField(
                        value = midrValue,
                        onValueChange = { 
                            midrValue = it
                            selectedPreset = "custom"
                        },
                        label = stringResource(R.string.spoof_cpu_field_midr),
                        useLabelAsPlaceholder = true,
                        modifier = Modifier.fillMaxWidth()
                    )

                    // BogoMIPS 输入
                    TextField(
                        value = bogomipsValue,
                        onValueChange = { bogomipsValue = it },
                        label = stringResource(R.string.spoof_cpu_field_bogomips),
                        useLabelAsPlaceholder = true,
                        modifier = Modifier.fillMaxWidth()
                    )

                    // HWCAP 输入
                    TextField(
                        value = hwcapValue,
                        onValueChange = { hwcapValue = it },
                        label = stringResource(R.string.spoof_cpu_field_hwcap),
                        useLabelAsPlaceholder = true,
                        modifier = Modifier.fillMaxWidth()
                    )

                    // HWCAP2 输入
                    TextField(
                        value = hwcap2Value,
                        onValueChange = { hwcap2Value = it },
                        label = stringResource(R.string.spoof_cpu_field_hwcap2),
                        useLabelAsPlaceholder = true,
                        modifier = Modifier.fillMaxWidth()
                    )

                    // CPU 核心选择标题
                    Text(
                        text = stringResource(R.string.spoof_cpu_field_cores),
                        style = textStyles.body1,
                        modifier = Modifier.padding(top = 8.dp)
                    )

                    // 全选复选框
                    CheckboxPreference(
                        title = stringResource(R.string.spoof_cpu_cores_all),
                        checked = selectedCores.size == coreCount,
                        onCheckedChange = {
                            selectedCores = if (selectedCores.size == coreCount) {
                                emptyList()
                            } else {
                                (0 until coreCount).toList()
                            }
                        }
                    )

                    // 各个核心的复选框
                    repeat(coreCount) { index ->
                        CheckboxPreference(
                            title = stringResource(R.string.spoof_cpu_cores_format, index),
                            checked = selectedCores.contains(index),
                            onCheckedChange = {
                                selectedCores = if (selectedCores.contains(index)) {
                                    selectedCores - index
                                } else {
                                    selectedCores + index
                                }
                            }
                        )
                    }

                    // 按钮
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Button(
                            onClick = {
                                showDialogState.value = false
                                onDismiss()
                            },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .padding(vertical = 8.dp),
                            cornerRadius = 8.dp
                        ) {
                            Text(text = stringResource(R.string.spoof_cpu_cancel))
                        }
                        Button(
                            onClick = {
                                val params = SpoofCpuParams(
                                    cpuIndices = selectedCores,
                                    midrHex = midrValue,
                                    bogomips = bogomipsValue.toIntOrNull() ?: 0,
                                    hwcapHex = hwcapValue,
                                    hwcap2Hex = hwcap2Value
                                )
                                showDialogState.value = false
                                onApply(params)
                            },
                            enabled = selectedCores.isNotEmpty(),
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .padding(vertical = 8.dp),
                            cornerRadius = 8.dp
                        ) {
                            Text(text = stringResource(R.string.spoof_cpu_apply))
                        }
                    }
                }
            }
        )
    }
}
