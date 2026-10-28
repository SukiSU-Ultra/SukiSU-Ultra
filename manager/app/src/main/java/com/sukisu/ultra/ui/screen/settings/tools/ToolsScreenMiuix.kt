package com.sukisu.ultra.ui.screen.settings.tools

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Restore
import androidx.compose.material.icons.rounded.Security
import androidx.compose.ui.Alignment
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
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.KsuIsValid
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.component.miuix.AppScaffold
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.getSELinuxStatusRaw
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.preference.ArrowPreference
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
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val barColor = if (blurActive || hasCustomBackground) Color.Transparent else colorScheme.surface

    AppScaffold(
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
                .then(if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier)
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

                    KernelModulesSectionMiuix(
                        onOpen = actions.onOpenKernelModules
                    )

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
    AppCard(
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
private fun KernelModulesSectionMiuix(
    onOpen: () -> Unit,
) {
    AppCard(
        modifier = Modifier
            .padding(top = 12.dp)
            .fillMaxWidth(),
    ) {
        ArrowPreference(
            title = stringResource(R.string.kernel_modules_title),
            summary = stringResource(R.string.tools_kernel_modules_summary),
            startAction = {
                Icon(
                    imageVector = Icons.Rounded.Memory,
                    modifier = Modifier.padding(end = 6.dp),
                    contentDescription = stringResource(R.string.kernel_modules_title),
                    tint = colorScheme.onBackground
                )
            },
            onClick = onOpen
        )
    }
}

@Composable
private fun AllowlistBackupSectionMiuix(
    onBackup: () -> Unit,
    onRestore: () -> Unit
) {
    AppCard(
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
    onApply: (SpoofCpuParams) -> Unit,
    onRestore: () -> Unit
) {
    var selectedPreset by remember { mutableStateOf("custom") }
    var midrValue by remember { mutableStateOf(currentCpuInfo?.midrHex ?: "0x0") }
    var bogomipsValue by remember { mutableStateOf(currentCpuInfo?.bogomips?.toString() ?: "0") }
    var hwcapValue by remember { mutableStateOf(currentCpuInfo?.hwcap ?: "0x0") }
    var hwcap2Value by remember { mutableStateOf(currentCpuInfo?.hwcap2 ?: "0x0") }
    val coreCount = currentCpuInfo?.coreCount ?: 8
    var selectedCores by remember { mutableStateOf((0 until coreCount).toList()) }
    val showDialogState = remember { mutableStateOf(true) }
    var advancedExpanded by remember { mutableStateOf(false) }

    val presetList = spoofCpuPresetList()
    val presetLabels = presetList.map { preset ->
        preset.coreTypeRes?.let { stringResource(it, preset.model) }
            ?: stringResource(R.string.spoof_cpu_midr_custom)
    }

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
                    TextButton(
                        text = stringResource(R.string.spoof_cpu_restore),
                        onClick = onRestore,
                        enabled = currentCpuInfo != null,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 40.dp),
                        cornerRadius = 8.dp
                    )

                    Text(
                        text = stringResource(R.string.spoof_cpu_warning),
                        color = colorScheme.error,
                        style = textStyles.body2
                    )

                    Text(
                        text = stringResource(R.string.spoof_cpu_field_midr),
                        color = colorScheme.onSurfaceVariantSummary,
                        style = textStyles.body2
                    )

                    OverlayDropdownPreference(
                        title = stringResource(R.string.spoof_cpu_midr_preset_label),
                        summary = presetLabels.getOrElse(presetList.indexOfFirst { it.id == selectedPreset }) { "" },
                        items = presetLabels,
                        selectedIndex = presetList.indexOfFirst { it.id == selectedPreset }.coerceAtLeast(0),
                        onSelectedIndexChange = { index ->
                            val preset = presetList[index]
                            selectedPreset = preset.id
                            if (preset.midrHex != "custom") {
                                midrValue = preset.midrHex
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

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(stringResource(R.string.spoof_cpu_field_cores), style = textStyles.body1)
                        TextButton(
                            text = stringResource(R.string.spoof_cpu_cores_all),
                            colors = if (selectedCores.size == coreCount) {
                                ButtonDefaults.textButtonColorsPrimary()
                            } else {
                                ButtonDefaults.textButtonColors()
                            },
                            onClick = {
                                selectedCores = if (selectedCores.size == coreCount) emptyList() else (0 until coreCount).toList()
                            }
                        )
                    }

                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        repeat(coreCount) { index ->
                            val selected = index in selectedCores
                            TextButton(
                                text = stringResource(R.string.spoof_cpu_cores_format, index),
                                colors = if (selected) {
                                    ButtonDefaults.textButtonColorsPrimary()
                                } else {
                                    ButtonDefaults.textButtonColors()
                                },
                                onClick = {
                                    selectedCores = if (selected) selectedCores - index else selectedCores + index
                                },
                                modifier = Modifier
                                    .heightIn(min = 40.dp)
                                    .semantics { this.selected = selected },
                                cornerRadius = 20.dp
                            )
                        }
                    }

                    TextButton(
                        text = stringResource(R.string.spoof_cpu_advanced),
                        colors = if (advancedExpanded) {
                            ButtonDefaults.textButtonColorsPrimary()
                        } else {
                            ButtonDefaults.textButtonColors()
                        },
                        onClick = { advancedExpanded = !advancedExpanded }
                    )

                    if (advancedExpanded) {
                        TextField(
                            value = bogomipsValue,
                            onValueChange = { bogomipsValue = it },
                            label = stringResource(R.string.spoof_cpu_field_bogomips),
                            useLabelAsPlaceholder = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        TextField(
                            value = hwcapValue,
                            onValueChange = { hwcapValue = it },
                            label = stringResource(R.string.spoof_cpu_field_hwcap),
                            useLabelAsPlaceholder = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        TextField(
                            value = hwcap2Value,
                            onValueChange = { hwcap2Value = it },
                            label = stringResource(R.string.spoof_cpu_field_hwcap2),
                            useLabelAsPlaceholder = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }

                    // 按钮
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        TextButton(
                            text = stringResource(R.string.spoof_cpu_cancel),
                            onClick = {
                                showDialogState.value = false
                                onDismiss()
                            },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .padding(vertical = 8.dp),
                            cornerRadius = 8.dp
                        )
                        TextButton(
                            text = stringResource(R.string.spoof_cpu_apply),
                            colors = ButtonDefaults.textButtonColorsPrimary(),
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
                        )
                    }
                }
            }
        )
    }
}
