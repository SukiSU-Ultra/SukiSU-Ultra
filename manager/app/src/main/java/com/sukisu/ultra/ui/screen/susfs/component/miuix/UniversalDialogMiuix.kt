package com.sukisu.ultra.ui.screen.susfs.component.miuix

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sukisu.ultra.R
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.preference.OverlayDropdownPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme

sealed class DialogFieldMiuix {
    data class TextField(
        val value: String,
        val onValueChange: (String) -> Unit,
        val labelRes: Int,
        val enabled: Boolean = true,
        val modifier: Modifier = Modifier.fillMaxWidth()
    ) : DialogFieldMiuix()

    data class Dropdown(
        val titleRes: Int,
        val summary: String,
        val items: List<String>,
        val selectedIndex: Int,
        val onSelectedIndexChange: (Int) -> Unit,
        val enabled: Boolean = true
    ) : DialogFieldMiuix()

    data class CustomContent(
        val content: @Composable ColumnScope.() -> Unit
    ) : DialogFieldMiuix()
}

@Composable
fun UniversalDialogMiuix(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    onConfirm: () -> Boolean,
    titleRes: Int,
    isLoading: Boolean = false,
    fields: List<DialogFieldMiuix>,
    confirmTextRes: Int = R.string.add,
    cancelTextRes: Int = R.string.cancel,
    isConfirmEnabled: Boolean = true,
    scrollable: Boolean = false,
    onReset: (() -> Unit)? = null
) {
    val showDialogState = remember { mutableStateOf(showDialog) }

    LaunchedEffect(showDialog) {
        showDialogState.value = showDialog
    }

    if (showDialogState.value) {
        OverlayDialog(
            show = showDialogState.value,
            title = stringResource(titleRes),
            onDismissRequest = {
                onDismiss()
                onReset?.invoke()
            },
            content = {
                val contentModifier = if (scrollable) {
                    Modifier
                        .verticalScroll(rememberScrollState())
                        .padding(horizontal = 24.dp)
                } else {
                    Modifier.padding(horizontal = 24.dp)
                }

                Column(
                    modifier = contentModifier,
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    fields.forEach { field ->
                        when (field) {
                            is DialogFieldMiuix.TextField -> {
                                TextField(
                                    value = field.value,
                                    onValueChange = field.onValueChange,
                                    label = stringResource(field.labelRes),
                                    useLabelAsPlaceholder = true,
                                    modifier = field.modifier,
                                    enabled = field.enabled && !isLoading
                                )
                            }
                            is DialogFieldMiuix.Dropdown -> {
                                OverlayDropdownPreference(
                                    title = stringResource(field.titleRes),
                                    summary = field.summary,
                                    items = field.items,
                                    selectedIndex = field.selectedIndex,
                                    onSelectedIndexChange = field.onSelectedIndexChange,
                                    enabled = field.enabled && !isLoading
                                )
                            }
                            is DialogFieldMiuix.CustomContent -> {
                                field.content.invoke(this)
                            }
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Button(
                            onClick = {
                                onDismiss()
                                onReset?.invoke()
                            },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .padding(vertical = 8.dp),
                            cornerRadius = 8.dp
                        ) {
                            Text(
                                text = stringResource(cancelTextRes)
                            )
                        }
                        Button(
                            onClick = {
                                if (onConfirm()) {
                                    onDismiss()
                                    onReset?.invoke()
                                }
                            },
                            enabled = isConfirmEnabled && !isLoading,
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .padding(vertical = 8.dp),
                            cornerRadius = 8.dp
                        ) {
                            Text(
                                text = stringResource(confirmTextRes)
                            )
                        }
                    }
                }
            }
        )
    }
}

@Composable
fun DescriptionCardMiuix(
    title: String,
    description: String,
    modifier: Modifier = Modifier,
    warning: String? = null,
    additionalInfo: String? = null
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.defaultColors(
            color = colorScheme.surfaceVariant.copy(alpha = 0.3f)
        ),
        cornerRadius = 8.dp
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Text(
                text = title,
                style = MiuixTheme.textStyles.body1,
                fontWeight = FontWeight.Medium,
                color = colorScheme.primary
            )
            Text(
                text = description,
                style = MiuixTheme.textStyles.body2,
                color = colorScheme.onSurfaceVariantSummary,
                lineHeight = 16.sp
            )
            warning?.let {
                Text(
                    text = it,
                    style = MiuixTheme.textStyles.body2,
                    color = colorScheme.secondary,
                    fontWeight = FontWeight.Medium,
                    lineHeight = 16.sp
                )
            }
            additionalInfo?.let {
                Text(
                    text = it,
                    style = MiuixTheme.textStyles.body2,
                    color = colorScheme.onSurfaceVariantSummary.copy(alpha = 0.8f),
                    lineHeight = 14.sp
                )
            }
        }
    }
}

@Composable
fun ConfirmDialogMiuix(
    showDialog: Boolean,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
    titleRes: Int,
    messageRes: Int,
    isLoading: Boolean = false
) {
    UniversalDialogMiuix(
        showDialog = showDialog,
        onDismiss = onDismiss,
        onConfirm = {
            onConfirm()
            true
        },
        titleRes = titleRes,
        isLoading = isLoading,
        fields = listOf(
            DialogFieldMiuix.CustomContent {
                Text(
                    text = stringResource(messageRes),
                    style = MiuixTheme.textStyles.body2
                )
            }
        ),
        confirmTextRes = R.string.confirm,
        cancelTextRes = R.string.cancel,
        isConfirmEnabled = !isLoading
    )
}

@Composable
fun EmptyStateCardMiuix(
    message: String,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.defaultColors(
            color = colorScheme.surfaceVariant.copy(alpha = 0.15f)
        ),
        cornerRadius = 8.dp
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = message,
                style = MiuixTheme.textStyles.body2,
                color = colorScheme.onSurfaceVariantSummary,
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
fun SectionHeaderMiuix(
    title: String,
    subtitle: String?,
    icon: ImageVector,
    count: Int
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.defaultColors(
            color = colorScheme.surfaceVariant.copy(alpha = 0.25f)
        ),
        cornerRadius = 8.dp
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = colorScheme.primary,
                modifier = Modifier.size(22.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = MiuixTheme.textStyles.body1,
                    fontWeight = FontWeight.Medium,
                    color = colorScheme.onSurface
                )
                subtitle?.let {
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = it,
                        style = MiuixTheme.textStyles.body2,
                        color = colorScheme.onSurfaceVariantSummary
                    )
                }
            }
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(12.dp))
                    .background(colorScheme.primaryContainer)
                    .padding(horizontal = 10.dp, vertical = 5.dp)
            ) {
                Text(
                    text = count.toString(),
                    style = MiuixTheme.textStyles.body2.copy(fontSize = 12.sp),
                    color = colorScheme.onPrimaryContainer,
                    fontWeight = FontWeight.Medium
                )
            }
        }
    }
}
