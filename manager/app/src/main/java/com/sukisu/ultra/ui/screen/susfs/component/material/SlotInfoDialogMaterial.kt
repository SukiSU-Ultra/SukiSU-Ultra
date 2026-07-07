package com.sukisu.ultra.ui.screen.susfs.component.material

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.susfs.util.SlotInfo
import com.sukisu.ultra.ui.util.isAbDevice

@Composable
fun SlotInfoDialogMaterial(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    slotInfoList: List<SlotInfo>,
    currentActiveSlot: String,
    isLoadingSlotInfo: Boolean,
    onRefresh: () -> Unit,
    onUseUname: (String) -> Unit,
    onUseBuildTime: (String) -> Unit
) {
    val isAbDevice = produceState(initialValue = false) { value = isAbDevice() }.value
    val showDialogState = remember { mutableStateOf(showDialog && isAbDevice) }

    LaunchedEffect(showDialog, isAbDevice) {
        showDialogState.value = showDialog && isAbDevice
    }

    if (showDialogState.value) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(stringResource(R.string.susfs_slot_info_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        text = stringResource(R.string.susfs_current_active_slot, currentActiveSlot),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.Medium
                    )

                    if (slotInfoList.isNotEmpty()) {
                        slotInfoList.forEach { slotInfo ->
                            Card(modifier = Modifier.fillMaxWidth()) {
                                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(
                                            Icons.Default.Storage,
                                            contentDescription = null,
                                            tint = if (slotInfo.slotName == currentActiveSlot) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                                            modifier = Modifier.size(16.dp)
                                        )
                                        Spacer(Modifier.width(6.dp))
                                        Text(text = slotInfo.slotName, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold)
                                        if (slotInfo.slotName == currentActiveSlot) {
                                            Spacer(Modifier.width(6.dp))
                                            SuggestionChip(onClick = { }, label = { Text(stringResource(R.string.susfs_slot_current_badge)) })
                                        }
                                    }
                                    Text(text = stringResource(R.string.susfs_slot_uname, slotInfo.uname), style = MaterialTheme.typography.bodySmall)
                                    Text(text = stringResource(R.string.susfs_slot_build_time, slotInfo.buildTime), style = MaterialTheme.typography.bodySmall)
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Button(
                                            onClick = { onUseUname(slotInfo.uname) },
                                            modifier = Modifier.weight(1f)
                                        ) {
                                            Text(stringResource(R.string.susfs_slot_use_uname), maxLines = 2)
                                        }
                                        Button(
                                            onClick = { onUseBuildTime(slotInfo.buildTime) },
                                            modifier = Modifier.weight(1f)
                                        ) {
                                            Text(stringResource(R.string.susfs_slot_use_build_time), maxLines = 2)
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        Text(
                            text = stringResource(R.string.susfs_slot_info_unavailable),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.error
                        )
                    }

                    Button(
                        onClick = onRefresh,
                        enabled = !isLoadingSlotInfo,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(stringResource(R.string.refresh))
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}
