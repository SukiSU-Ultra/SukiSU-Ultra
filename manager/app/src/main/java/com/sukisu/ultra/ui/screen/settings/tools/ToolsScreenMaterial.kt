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
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExposedDropdownMenu
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.KsuIsValid
import com.sukisu.ultra.ui.component.material.ExpressiveDialog
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.IconTile
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedListItem
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.util.getSELinuxStatusRaw

@Composable
fun ToolsMaterial(
    state: ToolsUiState,
    actions: ToolsActions,
) {
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())

    ExpressiveScaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.tools)) },
                navigationIcon = {
                    TopBarBackButton(onClick = actions.onBack)
                },
                scrollBehavior = scrollBehavior,
                colors = expressiveTopAppBarColors(),
            )
        },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxHeight()
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .padding(horizontal = 16.dp),
            contentPadding = innerPadding,
        ) {
            item {
                KsuIsValid {
                    SelinuxToggleSectionMaterial(
                        selinuxEnforcing = state.selinuxEnforcing,
                        selinuxLoading = state.selinuxLoading,
                        onSelinuxToggle = actions.onSelinuxToggle
                    )

                    KernelModulesSectionMaterial(
                        onOpen = actions.onOpenKernelModules
                    )

                    AllowlistBackupSectionMaterial(
                        onBackup = actions.onBackupAllowlist,
                        onRestore = actions.onRestoreAllowlist
                    )
                }
            }
        }
    }
}

@Composable
private fun SelinuxToggleSectionMaterial(
    selinuxEnforcing: Boolean,
    selinuxLoading: Boolean,
    onSelinuxToggle: (Boolean) -> Unit
) {
    SegmentedColumn(
        modifier = Modifier.padding(top = 12.dp),
        content = listOf({
            val statusLabel = getSELinuxStatusRaw()
            SegmentedListItem(
                headlineContent = { Text(stringResource(R.string.tools_selinux_toggle)) },
                supportingContent = { Text(stringResource(R.string.tools_selinux_summary, statusLabel)) },
                leadingContent = {
                    IconTile(Icons.Rounded.Security, stringResource(id = R.string.tools_selinux_toggle))
                },
                trailingContent = {
                    Switch(
                        checked = selinuxEnforcing,
                        enabled = !selinuxLoading,
                        onCheckedChange = onSelinuxToggle
                    )
                }
            )
        })
    )
}

@Composable
private fun KernelModulesSectionMaterial(
    onOpen: () -> Unit,
) {
    SegmentedColumn(
        modifier = Modifier.padding(top = 12.dp),
        content = listOf({
            SegmentedListItem(
                headlineContent = { Text(stringResource(R.string.kernel_modules_title)) },
                supportingContent = { Text(stringResource(R.string.tools_kernel_modules_summary)) },
                leadingContent = {
                    IconTile(
                        Icons.Rounded.Memory,
                        stringResource(R.string.kernel_modules_title),
                    )
                },
                onClick = onOpen,
            )
        })
    )
}

@Composable
private fun AllowlistBackupSectionMaterial(
    onBackup: () -> Unit,
    onRestore: () -> Unit
) {
    SegmentedColumn(
        modifier = Modifier.padding(vertical = 12.dp),
        content = listOf(
            {
                SegmentedListItem(
                    headlineContent = { Text(stringResource(R.string.allowlist_backup_title)) },
                    supportingContent = { Text(stringResource(R.string.allowlist_backup_summary_picker)) },
                    leadingContent = {
                        IconTile(Icons.Rounded.Backup, stringResource(R.string.allowlist_backup_title))
                    },
                    onClick = onBackup
                )
            },
            {
                SegmentedListItem(
                    headlineContent = { Text(stringResource(R.string.allowlist_restore_title)) },
                    supportingContent = { Text(stringResource(R.string.allowlist_restore_summary_picker)) },
                    leadingContent = {
                        IconTile(Icons.Rounded.Restore, stringResource(R.string.allowlist_restore_title))
                    },
                    onClick = onRestore
                )
            }
        )
    )
}

@Composable
fun SpoofCpuDialogMaterial(
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
    var presetExpanded by remember { mutableStateOf(false) }
    var advancedExpanded by rememberSaveable { mutableStateOf(false) }

    val presetList = spoofCpuPresetList()
    val presetLabels = presetList.map { preset ->
        preset.coreTypeRes?.let { stringResource(it, preset.model) }
            ?: stringResource(R.string.spoof_cpu_midr_custom)
    }

    ExpressiveDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.spoof_cpu_dialog_title)) },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedButton(
                    onClick = onRestore,
                    enabled = currentCpuInfo != null,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(stringResource(R.string.spoof_cpu_restore))
                }

                Text(
                    text = stringResource(R.string.spoof_cpu_warning),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )

                Text(
                    text = stringResource(R.string.spoof_cpu_field_midr),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                ExposedDropdownMenuBox(
                    expanded = presetExpanded,
                    onExpandedChange = { presetExpanded = it }
                ) {
                    OutlinedTextField(
                        value = presetLabels.getOrElse(presetList.indexOfFirst { it.id == selectedPreset }) { "" },
                        onValueChange = {},
                        readOnly = true,
                        label = { Text(stringResource(R.string.spoof_cpu_midr_preset_label)) },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = presetExpanded) },
                        modifier = Modifier
                            .menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable)
                            .fillMaxWidth()
                    )
                    ExposedDropdownMenu(
                        expanded = presetExpanded,
                        onDismissRequest = { presetExpanded = false }
                    ) {
                        presetList.forEach { preset ->
                            DropdownMenuItem(
                                text = { Text(presetLabels[presetList.indexOf(preset)]) },
                                onClick = {
                                    selectedPreset = preset.id
                                    if (preset.midrHex != "custom") {
                                        midrValue = preset.midrHex
                                    }
                                    presetExpanded = false
                                }
                            )
                        }
                    }
                }

                OutlinedTextField(
                    value = midrValue,
                    onValueChange = { midrValue = it; selectedPreset = "custom" },
                    label = { Text(stringResource(R.string.spoof_cpu_field_midr)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.spoof_cpu_field_cores),
                        style = MaterialTheme.typography.titleSmall,
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(
                        onClick = {
                            selectedCores = if (selectedCores.size == coreCount) emptyList() else (0 until coreCount).toList()
                        }
                    ) {
                        Text(stringResource(R.string.spoof_cpu_cores_all))
                    }
                }

                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    repeat(coreCount) { index ->
                        FilterChip(
                            selected = index in selectedCores,
                            onClick = {
                                selectedCores = if (index in selectedCores) selectedCores - index else selectedCores + index
                            },
                            label = { Text(stringResource(R.string.spoof_cpu_cores_format, index)) }
                        )
                    }
                }

                TextButton(onClick = { advancedExpanded = !advancedExpanded }) {
                    Text(stringResource(R.string.spoof_cpu_advanced))
                    Text(if (advancedExpanded) "−" else "+")
                }

                if (advancedExpanded) {
                    OutlinedTextField(
                        value = bogomipsValue,
                        onValueChange = { bogomipsValue = it },
                        label = { Text(stringResource(R.string.spoof_cpu_field_bogomips)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = hwcapValue,
                        onValueChange = { hwcapValue = it },
                        label = { Text(stringResource(R.string.spoof_cpu_field_hwcap)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = hwcap2Value,
                        onValueChange = { hwcap2Value = it },
                        label = { Text(stringResource(R.string.spoof_cpu_field_hwcap2)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val params = SpoofCpuParams(
                        cpuIndices = selectedCores,
                        midrHex = midrValue,
                        bogomips = bogomipsValue.toIntOrNull() ?: 0,
                        hwcapHex = hwcapValue,
                        hwcap2Hex = hwcap2Value
                    )
                    onApply(params)
                },
                enabled = selectedCores.isNotEmpty()
            ) {
                Text(stringResource(R.string.spoof_cpu_apply))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.spoof_cpu_cancel))
            }
        }
    )
}
