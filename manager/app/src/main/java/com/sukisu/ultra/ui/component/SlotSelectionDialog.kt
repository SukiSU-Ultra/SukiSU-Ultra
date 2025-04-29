package com.sukisu.ultra.ui.component

import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.material3.HorizontalDivider
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.theme.ThemeConfig
import androidx.compose.foundation.shape.CornerSize

/**
 * 槽位选择对话框组件
 * 用于HorizonKernel刷写时选择目标槽位
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SlotSelectionDialog(
    show: Boolean,
    onDismiss: () -> Unit,
    onSlotSelected: (String) -> Unit
) {
    val context = LocalContext.current
    var currentSlot by remember { mutableStateOf<String?>(null) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        try {
            currentSlot = getCurrentSlot(context)
            errorMessage = null
        } catch (e: Exception) {
            errorMessage = e.message
            currentSlot = null
        }
    }

    if (show) {
        val backgroundColor = if (!ThemeConfig.useDynamicColor) {
            ThemeConfig.currentTheme.ButtonContrast.copy(alpha = 1.0f)
        } else {
            MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 1.0f)
        }

        Dialog(onDismissRequest = onDismiss) {
            Card(
                shape = MaterialTheme.shapes.medium.copy(
                    topStart = CornerSize(16.dp),
                    topEnd = CornerSize(16.dp),
                    bottomEnd = CornerSize(16.dp),
                    bottomStart = CornerSize(16.dp)
                ),
                colors = CardDefaults.cardColors(
                    containerColor = backgroundColor
                ),
                elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
            ) {
                Column(
                    modifier = Modifier
                        .padding(24.dp)
                        .fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = stringResource(id = R.string.select_slot_title),
                        style = MaterialTheme.typography.headlineSmall,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(bottom = 16.dp)
                    )

                    if (errorMessage != null) {
                        Text(
                            text = "Error: $errorMessage",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.error,
                            textAlign = TextAlign.Center
                        )
                    } else {
                        Text(
                            text = stringResource(
                                id = R.string.current_slot,
                                currentSlot ?: "Unknown"
                            ),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            textAlign = TextAlign.Center
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Text(
                        text = stringResource(id = R.string.select_slot_description),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center
                    )

                    Spacer(modifier = Modifier.height(24.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        val isDefaultSlotA = currentSlot == "_a" || currentSlot == "a"
                        Button(
                            onClick = { onSlotSelected("a") },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = if (isDefaultSlotA)
                                    MaterialTheme.colorScheme.primary
                                else
                                    MaterialTheme.colorScheme.primaryContainer,
                                contentColor = if (isDefaultSlotA)
                                    MaterialTheme.colorScheme.onPrimary
                                else
                                    MaterialTheme.colorScheme.onPrimaryContainer
                            )
                        ) {
                            Text(
                                text = stringResource(id = R.string.slot_a),
                                style = MaterialTheme.typography.labelLarge
                            )
                        }

                        val isDefaultSlotB = currentSlot == "_b" || currentSlot == "b"
                        Button(
                            onClick = { onSlotSelected("b") },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = if (isDefaultSlotB)
                                    MaterialTheme.colorScheme.secondary
                                else
                                    MaterialTheme.colorScheme.secondaryContainer,
                                contentColor = if (isDefaultSlotB)
                                    MaterialTheme.colorScheme.onSecondary
                                else
                                    MaterialTheme.colorScheme.onSecondaryContainer
                            )
                        ) {
                            Text(
                                text = stringResource(id = R.string.slot_b),
                                style = MaterialTheme.typography.labelLarge
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(24.dp))

                    HorizontalDivider(
                        modifier = Modifier.fillMaxWidth(),
                        thickness = 1.dp,
                        color = MaterialTheme.colorScheme.outline
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        TextButton(
                            onClick = onDismiss,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(text = stringResource(id = android.R.string.cancel))
                        }
                        TextButton(
                            onClick = {
                                currentSlot?.let { onSlotSelected(it) }
                                onDismiss()
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(text = stringResource(id = android.R.string.ok))
                        }
                    }
                }
            }
        }
    }
}

// 获取当前槽位信息
private fun getCurrentSlot(context: Context): String? {
    return runCommandGetOutput(true, "getprop ro.boot.slot_suffix")?.let {
        if (it.startsWith("_")) it.substring(1) else it
    }
}

private fun runCommandGetOutput(su: Boolean, cmd: String): String? {
    return try {
        val process = ProcessBuilder(if (su) "su" else "sh").start()
        process.outputStream.bufferedWriter().use { writer ->
            writer.write("$cmd\n")
            writer.write("exit\n")
            writer.flush()
        }
        process.inputStream.bufferedReader().use { reader ->
            reader.readText().trim()
        }
    } catch (_: Exception) {
        null
    }
}