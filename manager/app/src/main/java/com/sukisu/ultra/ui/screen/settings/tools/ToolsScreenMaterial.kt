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
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenu
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
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

                    SegmentedColumn(
                        modifier = Modifier.padding(top = 12.dp),
                        content = listOf({
                            val umountManager = stringResource(id = R.string.umount_path_manager)
                            SegmentedListItem(
                                onClick = actions.onNavigateToUmountManager,
                                headlineContent = { Text(umountManager) },
                                leadingContent = {
                                    Icon(
                                        Icons.Rounded.FolderDelete,
                                        umountManager,
                                        tint = MaterialTheme.colorScheme.onSurface
                                    )
                                }
                            )
                        })
                    )

                    SegmentedColumn(
                        modifier = Modifier.padding(top = 12.dp),
                        content = listOf({
                            val spoofCpuTitle = stringResource(id = R.string.tools_spoof_cpu_title)
                            SegmentedListItem(
                                onClick = actions.onOpenSpoofCpuDialog,
                                headlineContent = { Text(spoofCpuTitle) },
                                supportingContent = { Text(stringResource(R.string.tools_spoof_cpu_summary)) },
                                leadingContent = {
                                    Icon(
                                        Icons.Rounded.Memory,
                                        spoofCpuTitle,
                                        tint = MaterialTheme.colorScheme.onSurface
                                    )
                                }
                            )
                        })
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
                    Icon(
                        imageVector = Icons.Rounded.Security,
                        contentDescription = stringResource(id = R.string.tools_selinux_toggle),
                        tint = MaterialTheme.colorScheme.onSurface
                    )
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
                        Icon(
                            imageVector = Icons.Rounded.Backup,
                            contentDescription = stringResource(R.string.allowlist_backup_title),
                            tint = MaterialTheme.colorScheme.onSurface
                        )
                    },
                    onClick = onBackup
                )
            },
            {
                SegmentedListItem(
                    headlineContent = { Text(stringResource(R.string.allowlist_restore_title)) },
                    supportingContent = { Text(stringResource(R.string.allowlist_restore_summary_picker)) },
                    leadingContent = {
                        Icon(
                            imageVector = Icons.Rounded.Restore,
                            contentDescription = stringResource(R.string.allowlist_restore_title),
                            tint = MaterialTheme.colorScheme.onSurface
                        )
                    },
                    onClick = onRestore
                )
            }
        )
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SpoofCpuDialogMaterial(
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
    var presetExpanded by remember { mutableStateOf(false) }

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
                Text(
                    text = stringResource(R.string.spoof_cpu_warning),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )

                ExposedDropdownMenuBox(
                    expanded = presetExpanded,
                    onExpandedChange = { presetExpanded = it }
                ) {
                    OutlinedTextField(
                        value = presetList.find { it.first == selectedPreset }?.second ?: "",
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
                        presetList.forEach { (value, label) ->
                            DropdownMenuItem(
                                text = { Text(label) },
                                onClick = {
                                    selectedPreset = value
                                    if (value != "custom") {
                                        midrValue = value
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
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = bogomipsValue,
                    onValueChange = { bogomipsValue = it },
                    label = { Text(stringResource(R.string.spoof_cpu_field_bogomips)) },
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = hwcapValue,
                    onValueChange = { hwcapValue = it },
                    label = { Text(stringResource(R.string.spoof_cpu_field_hwcap)) },
                    modifier = Modifier.fillMaxWidth()
                )

                OutlinedTextField(
                    value = hwcap2Value,
                    onValueChange = { hwcap2Value = it },
                    label = { Text(stringResource(R.string.spoof_cpu_field_hwcap2)) },
                    modifier = Modifier.fillMaxWidth()
                )

                Text(
                    text = stringResource(R.string.spoof_cpu_field_cores),
                    style = MaterialTheme.typography.titleSmall
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Checkbox(
                        checked = selectedCores.size == coreCount,
                        onCheckedChange = { checked ->
                            selectedCores = if (checked) (0 until coreCount).toList() else emptyList()
                        }
                    )
                    Text(stringResource(R.string.spoof_cpu_cores_all))
                }

                repeat(coreCount) { index ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Checkbox(
                            checked = selectedCores.contains(index),
                            onCheckedChange = { checked ->
                                selectedCores = if (checked) {
                                    selectedCores + index
                                } else {
                                    selectedCores - index
                                }
                            }
                        )
                        Text(stringResource(R.string.spoof_cpu_cores_format, index))
                    }
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
