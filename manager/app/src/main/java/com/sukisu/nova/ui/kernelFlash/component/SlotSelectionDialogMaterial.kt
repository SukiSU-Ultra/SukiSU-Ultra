package com.sukisu.nova.ui.kernelFlash.component

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.SdStorage
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.sukisu.nova.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * 槽位选择对话框组件
 * 用于Kernel刷写时选择目标槽位
 */
@Composable
fun SlotSelectionDialogMaterial(
    show: Boolean,
    onDismiss: () -> Unit,
    onSlotSelected: (String) -> Unit
) {
    var currentSlot by remember { mutableStateOf<String?>(null) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var selectedSlot by remember { mutableStateOf<String?>(null) }
    val showDialog = remember { mutableStateOf(show) }
    val operationFailedString = stringResource(R.string.operation_failed)

    LaunchedEffect(show) {
        showDialog.value = show
        if (show) {
            try {
                currentSlot = withContext(Dispatchers.IO) { getCurrentSlot() }
                // 设置默认选择为当前槽位
                selectedSlot = when (currentSlot) {
                    "a" -> "a"
                    "b" -> "b"
                    else -> null
                }
                errorMessage = null
            } catch (_: Exception) {
                errorMessage = operationFailedString
                currentSlot = null
            }
        }
    }

    if (showDialog.value) {
        AlertDialog(
            onDismissRequest = {
                showDialog.value = false
                onDismiss()
            },
            title = {
                Text(
                    text = stringResource(id = R.string.select_slot_title),
                    fontWeight = FontWeight.Medium,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth()
                )
            },
            text = {
                Column(
                    modifier = Modifier.fillMaxWidth()
                ) {
                    // 当前槽位或错误信息
                    if (errorMessage != null) {
                        Text(
                            text = errorMessage ?: stringResource(R.string.operation_failed),
                            color = MaterialTheme.colorScheme.error,
                            textAlign = TextAlign.Center,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(bottom = 8.dp)
                        )
                    } else {
                        Text(
                            text = stringResource(
                                id = R.string.current_slot,
                                currentSlot?.uppercase() ?: stringResource(R.string.not_supported)
                            ),
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            textAlign = TextAlign.Center,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(bottom = 8.dp)
                        )
                    }

                    // 描述文本
                    Text(
                        text = stringResource(id = R.string.select_slot_description),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 16.dp)
                    )

                    // 槽位选项
                    val slotOptions = listOf(
                        SlotOption(
                            slot = "a",
                            titleText = stringResource(id = R.string.slot_a),
                            icon = Icons.Filled.SdStorage
                        ),
                        SlotOption(
                            slot = "b",
                            titleText = stringResource(id = R.string.slot_b),
                            icon = Icons.Filled.SdStorage
                        )
                    )

                    slotOptions.forEach { option ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .selectable(
                                    selected = selectedSlot == option.slot,
                                    onClick = { selectedSlot = option.slot },
                                    role = Role.RadioButton
                                )
                                .padding(vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = selectedSlot == option.slot,
                                onClick = null
                            )
                            Spacer(modifier = Modifier.padding(horizontal = 8.dp))
                            Icon(
                                imageVector = option.icon,
                                contentDescription = null,
                                tint = if (selectedSlot == option.slot) {
                                    MaterialTheme.colorScheme.primary
                                } else {
                                    MaterialTheme.colorScheme.onSurfaceVariant
                                }
                            )
                            Spacer(modifier = Modifier.padding(horizontal = 8.dp))
                            Text(
                                text = option.titleText,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showDialog.value = false
                        selectedSlot?.let { onSlotSelected(it) }
                    },
                    enabled = selectedSlot != null
                ) {
                    Text(stringResource(android.R.string.ok))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        showDialog.value = false
                        onDismiss()
                    }
                ) {
                    Text(stringResource(android.R.string.cancel))
                }
            }
        )
    }
}
