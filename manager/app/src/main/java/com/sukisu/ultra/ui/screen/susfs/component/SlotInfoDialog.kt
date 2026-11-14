@file:Suppress("SpellCheckingInspection")

package com.sukisu.ultra.ui.screen.susfs.component

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.screen.susfs.util.SlotInfo
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.basic.TextButton as MiuixTextButton
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.window.WindowDialog
import top.yukonga.miuix.kmp.basic.ButtonDefaults as MiuixButtonDefaults

@Composable
fun SlotInfoDialog(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    slotInfoList: List<SlotInfo>,
    currentActiveSlot: String,
    isLoadingSlotInfo: Boolean,
    error: String? = null,
    onRefresh: () -> Unit,
    onUseUname: (String) -> Unit,
    onUseBuildTime: (String) -> Unit,
) {
    if (!showDialog) return
    if (LocalUiMode.current == UiMode.Material) {
        SlotInfoSheetMaterial(
            onDismiss, slotInfoList, currentActiveSlot, isLoadingSlotInfo,
            error, onRefresh, onUseUname, onUseBuildTime,
        )
        return
    }
    val miuix = true
    var copiedFields by remember { mutableStateOf(emptySet<String>()) }
    var selectedSlot by remember(currentActiveSlot) { mutableStateOf(currentActiveSlot) }
    val selectedIndex = slotInfoList.indexOfFirst { it.slotName == selectedSlot }.coerceAtLeast(0)
    val body: @Composable () -> Unit = {
        Column(
            modifier = Modifier.fillMaxWidth().heightIn(max = 540.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            SlotText(stringResource(R.string.susfs_slot_draft_hint))
            if (isLoadingSlotInfo) {
                if (miuix) top.yukonga.miuix.kmp.basic.LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                else LinearWavyProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
            error?.let { SlotText(it) }
            if (!isLoadingSlotInfo && slotInfoList.isEmpty()) {
                SlotText(stringResource(R.string.susfs_slot_info_unavailable))
            }
            if (slotInfoList.isNotEmpty()) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    slotInfoList.forEachIndexed { index, slot ->
                        val name = slot.slotName.removePrefix("boot_").uppercase()
                        val label = if (slot.slotName == currentActiveSlot) {
                            "$name (${stringResource(R.string.susfs_slot_current_badge)})"
                        } else name
                        MiuixTextButton(
                            text = label,
                            onClick = { selectedSlot = slot.slotName },
                            enabled = !isLoadingSlotInfo,
                            modifier = Modifier.weight(1f).heightIn(min = 48.dp),
                            colors = if (index == selectedIndex) {
                                MiuixButtonDefaults.textButtonColorsPrimary()
                            } else {
                                MiuixButtonDefaults.textButtonColors()
                            },
                        )
                    }
                }
            }
            slotInfoList.getOrNull(selectedIndex)?.let { slot ->
                val slotContent: @Composable () -> Unit = {
                    Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                        SlotValue(
                            label = stringResource(R.string.susfs_uname_label), value = slot.uname,
                            enabled = !isLoadingSlotInfo,
                            action = stringResource(R.string.susfs_slot_use_uname),
                            selected = "${slot.slotName}:uname" in copiedFields,
                        ) {
                            onUseUname(slot.uname)
                            copiedFields = copiedFields.filterNot { it.endsWith(":uname") }.toSet() + "${slot.slotName}:uname"
                        }
                        SlotValue(
                            label = stringResource(R.string.susfs_build_time_label), value = slot.buildTime,
                            enabled = !isLoadingSlotInfo,
                            action = stringResource(R.string.susfs_slot_use_build_time),
                            selected = "${slot.slotName}:version" in copiedFields,
                        ) {
                            onUseBuildTime(slot.buildTime)
                            copiedFields = copiedFields.filterNot { it.endsWith(":version") }.toSet() + "${slot.slotName}:version"
                        }
                    }
                }
                if (miuix) {
                    AppCard(modifier = Modifier.fillMaxWidth()) { slotContent() }
                } else {
                    Surface(
                        shape = MaterialTheme.shapes.extraLarge,
                        color = if (slot.slotName == currentActiveSlot) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.surfaceContainerLow,
                        contentColor = if (slot.slotName == currentActiveSlot) MaterialTheme.colorScheme.onSecondaryContainer else MaterialTheme.colorScheme.onSurface,
                    ) { slotContent() }
                }
            }
        }
    }
    if (miuix) {
        WindowDialog(show = true, title = stringResource(R.string.susfs_slot_info_title), onDismissRequest = onDismiss) {
            Column(Modifier.fillMaxWidth().padding(horizontal = 24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                body()
                Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    MiuixTextButton(stringResource(R.string.refresh), onClick = onRefresh, enabled = !isLoadingSlotInfo, modifier = Modifier.weight(1f))
                    MiuixTextButton(stringResource(android.R.string.ok), onClick = onDismiss, modifier = Modifier.weight(1f), colors = MiuixButtonDefaults.textButtonColorsPrimary())
                }
            }
        }
    } else {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(stringResource(R.string.susfs_slot_info_title)) },
            text = body,
            confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(android.R.string.ok)) } },
            dismissButton = { TextButton(onClick = onRefresh, enabled = !isLoadingSlotInfo) { Text(stringResource(R.string.refresh)) } },
        )
    }
}

@Composable
private fun SlotText(text: String) {
    MiuixText(
        text,
        style = MiuixTheme.textStyles.body2,
        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
    )
}

@Composable
private fun SlotValue(
    label: String, value: String, enabled: Boolean,
    action: String, selected: Boolean, onUse: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        SlotText(label)
        SelectionContainer {
            val display = value.ifBlank { stringResource(R.string.susfs_slot_info_unavailable) }
            MiuixText(display, style = MiuixTheme.textStyles.body2)
        }
        if (value.isNotBlank()) {
            val text = if (selected) stringResource(R.string.susfs_slot_value_filled) else action
            MiuixTextButton(text, onClick = onUse, enabled = enabled, modifier = Modifier.fillMaxWidth())
        }
    }
}
