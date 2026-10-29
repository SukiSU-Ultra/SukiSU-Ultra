package com.sukisu.ultra.ui.screen.extensions

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExposedDropdownMenu
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.LinearWavyProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.screen.settings.tools.SpoofCpuParams
import com.sukisu.ultra.ui.screen.settings.tools.spoofCpuPresetList
import com.sukisu.ultra.ui.theme.backgroundAwareColor

@Composable
internal fun CpuSpoofMaterial(s: CpuSpoofState, a: CpuSpoofActions) {
    val scroll = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
    ExpressiveScaffold(
        topBar = {
            LargeFlexibleTopAppBar(
                title = { Text(stringResource(R.string.spoof_cpu_dialog_title)) },
                navigationIcon = { TopBarBackButton(onClick = a.onBack) },
                colors = expressiveTopAppBarColors(),
                scrollBehavior = scroll,
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .nestedScroll(scroll.nestedScrollConnection)
                .verticalScroll(rememberScrollState())
                .imePadding()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            if (s.busy) LinearWavyProgressIndicator(Modifier.fillMaxWidth())
            CpuSpoofCurrentSection(s)
            CpuSpoofParamsSection(s, a)
            Spacer(Modifier.height(16.dp))
        }
    }
}

@Composable
private fun CpuSpoofCurrentSection(s: CpuSpoofState) {
    val info = s.currentInfo
    CpuSpoofSection(R.string.spoof_cpu_section_current) {
        when {
            s.loading -> LinearProgressIndicator(Modifier.fillMaxWidth())
            info == null -> Text(
                text = stringResource(R.string.spoof_cpu_current_unavailable),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
            else -> {
                CpuSpoofInfoRow(R.string.spoof_cpu_field_midr, info.midrHex)
                CpuSpoofInfoRow(R.string.spoof_cpu_field_bogomips, info.bogomips.toString())
                CpuSpoofInfoRow(R.string.spoof_cpu_field_hwcap, info.hwcap)
                CpuSpoofInfoRow(R.string.spoof_cpu_field_hwcap2, info.hwcap2)
                CpuSpoofInfoRow(R.string.spoof_cpu_field_cores, info.coreCount.toString())
            }
        }
    }
}

@Composable
private fun CpuSpoofInfoRow(label: Int, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(label),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f),
        )
        SelectionContainer {
            Text(
                text = value.ifBlank { "—" },
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
                textAlign = TextAlign.End,
            )
        }
    }
}

@Composable
private fun CpuSpoofParamsSection(s: CpuSpoofState, a: CpuSpoofActions) {
    val info = s.currentInfo
    val coreCount = info?.coreCount ?: 8
    val enabled = !s.busy
    var selectedPreset by remember(info) { mutableStateOf("custom") }
    var midr by remember(info) { mutableStateOf(info?.midrHex ?: "0x0") }
    var bogomips by remember(info) { mutableStateOf(info?.bogomips?.toString() ?: "0") }
    var hwcap by remember(info) { mutableStateOf(info?.hwcap ?: "0x0") }
    var hwcap2 by remember(info) { mutableStateOf(info?.hwcap2 ?: "0x0") }
    var selectedCores by remember(info) { mutableStateOf((0 until coreCount).toList()) }
    var presetExpanded by remember { mutableStateOf(false) }
    var advancedExpanded by rememberSaveable { mutableStateOf(false) }

    val presetList = spoofCpuPresetList()
    val presetLabels = presetList.map { preset ->
        preset.coreTypeRes?.let { stringResource(it, preset.model) }
            ?: stringResource(R.string.spoof_cpu_midr_custom)
    }

    CpuSpoofSection(R.string.spoof_cpu_section_params) {
        Text(
            text = stringResource(R.string.spoof_cpu_warning),
            color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodyMedium,
        )

        ExposedDropdownMenuBox(
            expanded = presetExpanded,
            onExpandedChange = { if (enabled) presetExpanded = it },
        ) {
            OutlinedTextField(
                value = presetLabels.getOrElse(presetList.indexOfFirst { it.id == selectedPreset }) { "" },
                onValueChange = {},
                readOnly = true,
                enabled = enabled,
                label = { Text(stringResource(R.string.spoof_cpu_midr_preset_label)) },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = presetExpanded) },
                shape = MaterialTheme.shapes.large,
                modifier = Modifier
                    .menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable)
                    .fillMaxWidth(),
            )
            ExposedDropdownMenu(
                expanded = presetExpanded,
                onDismissRequest = { presetExpanded = false },
            ) {
                presetList.forEachIndexed { index, preset ->
                    DropdownMenuItem(
                        text = { Text(presetLabels[index]) },
                        onClick = {
                            selectedPreset = preset.id
                            if (preset.midrHex != "custom") midr = preset.midrHex
                            presetExpanded = false
                        },
                    )
                }
            }
        }

        OutlinedTextField(
            value = midr,
            onValueChange = {
                midr = it
                selectedPreset = "custom"
            },
            label = { Text(stringResource(R.string.spoof_cpu_field_midr)) },
            singleLine = true,
            enabled = enabled,
            shape = MaterialTheme.shapes.large,
            modifier = Modifier.fillMaxWidth(),
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = stringResource(R.string.spoof_cpu_field_cores),
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.weight(1f),
            )
            TextButton(
                onClick = {
                    selectedCores = if (selectedCores.size == coreCount) {
                        emptyList()
                    } else {
                        (0 until coreCount).toList()
                    }
                },
                enabled = enabled,
            ) {
                Text(stringResource(R.string.spoof_cpu_cores_all))
            }
        }

        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            repeat(coreCount) { index ->
                FilterChip(
                    selected = index in selectedCores,
                    onClick = {
                        if (enabled) {
                            selectedCores = if (index in selectedCores) {
                                selectedCores - index
                            } else {
                                selectedCores + index
                            }
                        }
                    },
                    label = { Text(stringResource(R.string.spoof_cpu_cores_format, index)) },
                    enabled = enabled,
                )
            }
        }

        TextButton(
            onClick = { advancedExpanded = !advancedExpanded },
            enabled = enabled,
        ) {
            Text(stringResource(R.string.spoof_cpu_advanced))
            Text(if (advancedExpanded) "−" else "+")
        }

        if (advancedExpanded) {
            OutlinedTextField(
                value = bogomips,
                onValueChange = { bogomips = it },
                label = { Text(stringResource(R.string.spoof_cpu_field_bogomips)) },
                singleLine = true,
                enabled = enabled,
                shape = MaterialTheme.shapes.large,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = hwcap,
                onValueChange = { hwcap = it },
                label = { Text(stringResource(R.string.spoof_cpu_field_hwcap)) },
                singleLine = true,
                enabled = enabled,
                shape = MaterialTheme.shapes.large,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = hwcap2,
                onValueChange = { hwcap2 = it },
                label = { Text(stringResource(R.string.spoof_cpu_field_hwcap2)) },
                singleLine = true,
                enabled = enabled,
                shape = MaterialTheme.shapes.large,
                modifier = Modifier.fillMaxWidth(),
            )
        }

        Button(
            onClick = {
                a.onApply(
                    SpoofCpuParams(
                        cpuIndices = selectedCores,
                        midrHex = midr,
                        bogomips = bogomips.toIntOrNull() ?: 0,
                        hwcapHex = hwcap,
                        hwcap2Hex = hwcap2,
                    )
                )
            },
            enabled = enabled && selectedCores.isNotEmpty(),
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 52.dp),
        ) {
            Text(stringResource(R.string.spoof_cpu_apply))
        }
    }
}

@Composable
private fun CpuSpoofSection(title: Int, content: @Composable ColumnScope.() -> Unit) {
    Surface(
        shape = MaterialTheme.shapes.extraLarge,
        color = backgroundAwareColor(MaterialTheme.colorScheme.surfaceContainerLow),
        contentColor = MaterialTheme.colorScheme.onSurface,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text(
                text = stringResource(title),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.primary,
            )
            content()
        }
    }
}
