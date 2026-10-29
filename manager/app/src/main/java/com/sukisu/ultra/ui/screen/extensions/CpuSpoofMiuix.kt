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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.component.miuix.AppScaffold
import com.sukisu.ultra.ui.screen.settings.tools.SpoofCpuParams
import com.sukisu.ultra.ui.screen.settings.tools.spoofCpuPresetList
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.LinearProgressIndicator
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.preference.OverlayDropdownPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.textStyles

@Composable
internal fun CpuSpoofMiuix(s: CpuSpoofState, a: CpuSpoofActions) {
    val scroll = MiuixScrollBehavior()
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val enableBlur = LocalEnableBlur.current
    val backdrop = rememberBlurBackdrop(enableBlur)
    val blurActive = backdrop != null
    val barColor = if (blurActive || hasCustomBackground) Color.Transparent else colorScheme.surface

    AppScaffold(
        topBar = {
            BlurredBar(backdrop) {
                TopAppBar(
                    title = stringResource(R.string.spoof_cpu_dialog_title),
                    color = barColor,
                    navigationIcon = {
                        IconButton(onClick = a.onBack) {
                            val layoutDirection = LocalLayoutDirection.current
                            Icon(
                                modifier = Modifier.graphicsLayer {
                                    if (layoutDirection == LayoutDirection.Rtl) scaleX = -1f
                                },
                                imageVector = MiuixIcons.Back,
                                contentDescription = null,
                                tint = colorScheme.onBackground,
                            )
                        }
                    },
                    scrollBehavior = scroll,
                )
            }
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .then(if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier)
                .fillMaxSize()
                .nestedScroll(scroll.nestedScrollConnection)
                .verticalScroll(rememberScrollState())
                .imePadding()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            if (s.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            CpuSpoofCurrentSectionMiuix(s)
            CpuSpoofParamsSectionMiuix(s, a)
            Spacer(Modifier.height(16.dp))
        }
    }
}

@Composable
private fun CpuSpoofCurrentSectionMiuix(s: CpuSpoofState) {
    val info = s.currentInfo
    CpuSpoofSectionMiuix(R.string.spoof_cpu_section_current) {
        when {
            s.loading -> LinearProgressIndicator(Modifier.fillMaxWidth())
            info == null -> Text(
                text = stringResource(R.string.spoof_cpu_current_unavailable),
                color = colorScheme.error,
                style = textStyles.body2,
            )
            else -> {
                CpuSpoofInfoRowMiuix(R.string.spoof_cpu_field_midr, info.midrHex)
                CpuSpoofInfoRowMiuix(R.string.spoof_cpu_field_bogomips, info.bogomips.toString())
                CpuSpoofInfoRowMiuix(R.string.spoof_cpu_field_hwcap, info.hwcap)
                CpuSpoofInfoRowMiuix(R.string.spoof_cpu_field_hwcap2, info.hwcap2)
                CpuSpoofInfoRowMiuix(R.string.spoof_cpu_field_cores, info.coreCount.toString())
            }
        }
    }
}

@Composable
private fun CpuSpoofInfoRowMiuix(label: Int, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(label),
            style = textStyles.body2,
            color = colorScheme.onSurfaceVariantSummary,
            modifier = Modifier.weight(1f),
        )
        SelectionContainer {
            Text(
                text = value.ifBlank { "—" },
                style = textStyles.body2,
                fontFamily = FontFamily.Monospace,
            )
        }
    }
}

@Composable
private fun CpuSpoofParamsSectionMiuix(s: CpuSpoofState, a: CpuSpoofActions) {
    val info = s.currentInfo
    val coreCount = info?.coreCount ?: 8
    val enabled = !s.busy
    var selectedPreset by remember(info) { mutableStateOf("custom") }
    var midr by remember(info) { mutableStateOf(info?.midrHex ?: "0x0") }
    var bogomips by remember(info) { mutableStateOf(info?.bogomips?.toString() ?: "0") }
    var hwcap by remember(info) { mutableStateOf(info?.hwcap ?: "0x0") }
    var hwcap2 by remember(info) { mutableStateOf(info?.hwcap2 ?: "0x0") }
    var selectedCores by remember(info) { mutableStateOf((0 until coreCount).toList()) }
    var advancedExpanded by remember { mutableStateOf(false) }

    val presetList = spoofCpuPresetList()
    val presetLabels = presetList.map { preset ->
        preset.coreTypeRes?.let { stringResource(it, preset.model) }
            ?: stringResource(R.string.spoof_cpu_midr_custom)
    }

    CpuSpoofSectionMiuix(R.string.spoof_cpu_section_params) {
        Text(
            text = stringResource(R.string.spoof_cpu_warning),
            color = colorScheme.error,
            style = textStyles.body2,
        )

        OverlayDropdownPreference(
            title = stringResource(R.string.spoof_cpu_midr_preset_label),
            summary = presetLabels.getOrElse(presetList.indexOfFirst { it.id == selectedPreset }) { "" },
            items = presetLabels,
            selectedIndex = presetList.indexOfFirst { it.id == selectedPreset }.coerceAtLeast(0),
            onSelectedIndexChange = { index ->
                val preset = presetList[index]
                selectedPreset = preset.id
                if (preset.midrHex != "custom") midr = preset.midrHex
            },
            enabled = enabled,
        )

        TextField(
            value = midr,
            onValueChange = {
                midr = it
                selectedPreset = "custom"
            },
            label = stringResource(R.string.spoof_cpu_field_midr),
            useLabelAsPlaceholder = true,
            singleLine = true,
            enabled = enabled,
            modifier = Modifier.fillMaxWidth(),
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
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
                    selectedCores = if (selectedCores.size == coreCount) {
                        emptyList()
                    } else {
                        (0 until coreCount).toList()
                    }
                },
                enabled = enabled,
            )
        }

        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
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
                    enabled = enabled,
                    modifier = Modifier
                        .heightIn(min = 40.dp)
                        .semantics { this.selected = selected },
                    cornerRadius = 20.dp,
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
            onClick = { advancedExpanded = !advancedExpanded },
            enabled = enabled,
        )

        if (advancedExpanded) {
            TextField(
                value = bogomips,
                onValueChange = { bogomips = it },
                label = stringResource(R.string.spoof_cpu_field_bogomips),
                useLabelAsPlaceholder = true,
                singleLine = true,
                enabled = enabled,
                modifier = Modifier.fillMaxWidth(),
            )
            TextField(
                value = hwcap,
                onValueChange = { hwcap = it },
                label = stringResource(R.string.spoof_cpu_field_hwcap),
                useLabelAsPlaceholder = true,
                singleLine = true,
                enabled = enabled,
                modifier = Modifier.fillMaxWidth(),
            )
            TextField(
                value = hwcap2,
                onValueChange = { hwcap2 = it },
                label = stringResource(R.string.spoof_cpu_field_hwcap2),
                useLabelAsPlaceholder = true,
                singleLine = true,
                enabled = enabled,
                modifier = Modifier.fillMaxWidth(),
            )
        }

        TextButton(
            text = stringResource(R.string.spoof_cpu_apply),
            colors = ButtonDefaults.textButtonColorsPrimary(),
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
                .heightIn(min = 48.dp),
            cornerRadius = 8.dp,
        )
    }
}

@Composable
private fun CpuSpoofSectionMiuix(title: Int, content: @Composable ColumnScope.() -> Unit) {
    AppCard(Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text(
                text = stringResource(title),
                style = textStyles.title4,
                color = colorScheme.primary,
            )
            content()
        }
    }
}
