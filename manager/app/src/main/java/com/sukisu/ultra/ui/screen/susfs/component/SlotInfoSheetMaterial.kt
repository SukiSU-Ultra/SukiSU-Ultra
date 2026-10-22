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
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedDropdownItem
import com.sukisu.ultra.ui.component.material.SegmentedListItem
import com.sukisu.ultra.ui.screen.susfs.util.SlotInfo

/** Material uses a single selected slot, with details and actions in separate groups. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SlotInfoSheetMaterial(
    onDismiss: () -> Unit,
    slots: List<SlotInfo>,
    currentSlot: String,
    loading: Boolean,
    error: String?,
    onRefresh: () -> Unit,
    onUseUname: (String) -> Unit,
    onUseBuildTime: (String) -> Unit,
) {
    var selectedSlot by remember(currentSlot) { mutableStateOf(currentSlot) }
    var filledUname by remember { mutableStateOf<String?>(null) }
    var filledVersion by remember { mutableStateOf<String?>(null) }
    val selectedIndex = slots.indexOfFirst { it.slotName == selectedSlot }.coerceAtLeast(0)
    val slot = slots.getOrNull(selectedIndex)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberBottomSheetState(
            initialValue = SheetValue.Hidden,
            enabledValues = setOf(SheetValue.Hidden, SheetValue.Expanded),
        ),
        containerColor = MaterialTheme.colorScheme.surfaceContainer,
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().heightIn(max = 640.dp)
                .verticalScroll(rememberScrollState()).padding(horizontal = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(stringResource(R.string.susfs_slot_info_title), style = MaterialTheme.typography.headlineSmall)
            Text(stringResource(R.string.susfs_slot_draft_hint), style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (loading) LinearWavyProgressIndicator(modifier = Modifier.fillMaxWidth())
            error?.let {
                Surface(shape = MaterialTheme.shapes.large, color = MaterialTheme.colorScheme.errorContainer) {
                    Text(it, Modifier.fillMaxWidth().padding(16.dp), color = MaterialTheme.colorScheme.onErrorContainer)
                }
            }
            if (slots.isNotEmpty()) {
                SegmentedColumn(content = listOf({
                    SegmentedDropdownItem(
                        title = stringResource(R.string.select_slot_title),
                        items = slots.map {
                            val name = it.slotName.removePrefix("boot_").uppercase()
                            if (it.slotName == currentSlot) "$name (${stringResource(R.string.susfs_slot_current_badge)})" else name
                        },
                        selectedIndex = selectedIndex,
                        onItemSelected = { selectedSlot = slots[it].slotName },
                        enabled = !loading,
                    )
                }))
            }
            if (slot != null) {
                SegmentedColumn(content = listOf(
                    { SlotDetailMaterial(stringResource(R.string.susfs_uname_label), slot.uname) },
                    { SlotDetailMaterial(stringResource(R.string.susfs_build_time_label), slot.buildTime) },
                ))
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilledTonalButton(
                        onClick = { onUseUname(slot.uname); filledUname = slot.uname },
                        enabled = !loading && slot.uname.isNotBlank(),
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                    ) {
                        Text(stringResource(if (slot.uname.isNotBlank() && filledUname == slot.uname)
                            R.string.susfs_slot_value_filled else R.string.susfs_slot_use_uname))
                    }
                    FilledTonalButton(
                        onClick = { onUseBuildTime(slot.buildTime); filledVersion = slot.buildTime },
                        enabled = !loading && slot.buildTime.isNotBlank(),
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
                    ) {
                        Text(stringResource(if (slot.buildTime.isNotBlank() && filledVersion == slot.buildTime)
                            R.string.susfs_slot_value_filled else R.string.susfs_slot_use_build_time))
                    }
                }
            } else if (!loading) {
                Text(stringResource(R.string.susfs_slot_info_unavailable), color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedButton(onClick = onRefresh, enabled = !loading, modifier = Modifier.weight(1f).heightIn(min = 48.dp)) {
                    Text(stringResource(R.string.refresh))
                }
                Button(onClick = onDismiss, modifier = Modifier.weight(1f).heightIn(min = 48.dp)) {
                    Text(stringResource(android.R.string.ok))
                }
            }
            Spacer(Modifier.height(16.dp))
        }
    }
}

@Composable
private fun SlotDetailMaterial(label: String, value: String) {
    SegmentedListItem(
        overlineContent = { Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant) },
        headlineContent = {
            SelectionContainer {
                Text(value.ifBlank { stringResource(R.string.susfs_slot_info_unavailable) },
                    style = MaterialTheme.typography.bodyMedium)
            }
        },
    )
}
