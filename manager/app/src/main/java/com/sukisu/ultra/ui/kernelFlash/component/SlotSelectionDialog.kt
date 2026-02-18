package com.sukisu.ultra.ui.kernelFlash.component

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.SdStorage
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.getRootShell
import com.topjohnwu.superuser.ShellUtils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.extra.SuperArrow
import top.yukonga.miuix.kmp.extra.SuperDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme

/**
 * 槽位选择对话框组件
 * 用于Kernel刷写时选择目标槽位
 */
@Composable
fun SlotSelectionDialog(
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

    SuperDialog(
        show = showDialog,
        insideMargin = DpSize(0.dp, 0.dp),
        onDismissRequest = {
            showDialog.value = false
            onDismiss()
        },
        content = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 24.dp)
            ) {
                // 标题
                Text(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp, vertical = 12.dp),
                    text = stringResource(id = R.string.select_slot_title),
                    fontSize = MiuixTheme.textStyles.title4.fontSize,
                    fontWeight = FontWeight.Medium,
                    textAlign = TextAlign.Center,
                    color = colorScheme.onSurface
                )

                // 当前槽位或错误信息
                if (errorMessage != null) {
                    Text(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 24.dp, vertical = 8.dp),
                        text = errorMessage ?: stringResource(R.string.operation_failed),
                        fontSize = MiuixTheme.textStyles.body2.fontSize,
                        color = colorScheme.error,
                        textAlign = TextAlign.Center
                    )
                } else {
                    Text(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 24.dp, vertical = 8.dp),
                        text = stringResource(
                            id = R.string.current_slot,
                            currentSlot?.uppercase() ?: stringResource(R.string.not_supported)
                        ),
                        fontSize = MiuixTheme.textStyles.body2.fontSize,
                        color = colorScheme.onSurfaceVariantSummary,
                        textAlign = TextAlign.Center
                    )
                }

                // 描述文本
                Text(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp, vertical = 8.dp),
                    text = stringResource(id = R.string.select_slot_description),
                    fontSize = MiuixTheme.textStyles.body2.fontSize,
                    color = colorScheme.onSurfaceVariantSummary,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(12.dp))

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
                    SuperArrow(
                        title = option.titleText,
                        startAction = {
                            Icon(
                                imageVector = option.icon,
                                contentDescription = null,
                                tint = if (selectedSlot == option.slot) {
                                    colorScheme.primary
                                } else {
                                    colorScheme.onSurfaceVariantSummary
                                }
                            )
                        },
                        onClick = {
                            selectedSlot = option.slot
                        },
                        insideMargin = PaddingValues(horizontal = 24.dp, vertical = 12.dp)
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))

                // 按钮行
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    TextButton(
                        text = stringResource(android.R.string.cancel),
                        onClick = {
                            showDialog.value = false
                            onDismiss()
                        },
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(
                        text = stringResource(android.R.string.ok),
                        onClick = {
                            selectedSlot?.let { onSlotSelected(it) }
                            showDialog.value = false
                            onDismiss()
                        },
                        enabled = selectedSlot != null,
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }
    )
}

// Data class for slot options
data class SlotOption(
    val slot: String,
    val titleText: String,
    val icon: ImageVector
)

// Utility function to get current slot
private fun getCurrentSlot(): String? {
    return try {
        val shell = getRootShell()
        val result = ShellUtils.fastCmd(shell, "getprop ro.boot.slot_suffix").trim()
        if (result.startsWith("_")) {
            result.substring(1)
        } else {
            result
        }.takeIf { it.isNotEmpty() }
    } catch (_: Exception) {
        null
    }
}
