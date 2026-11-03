package com.sukisu.ultra.ui.component.themeimport

import android.net.Uri
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.LightMode
import androidx.compose.material.icons.rounded.DarkMode
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularWavyProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon as MaterialIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text as MaterialText
import androidx.compose.material3.TextButton as MaterialTextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.screen.themestore.ThemeStoreInlineNotice
import com.sukisu.ultra.ui.theme.MaterialExpressivePalette
import com.sukisu.ultra.ui.util.ThemePackageStorage
import top.yukonga.miuix.kmp.basic.ButtonDefaults as MiuixButtonDefaults
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.window.WindowDialog
import java.io.File
import kotlinx.coroutines.launch

/**
 * Adaptive theme maker. A light set and a dark set are picked either from existing .sukisu
 * packages or as snapshots of the current device appearance; both are merged into one v3
 * adaptive package. Depending on the provided callbacks the result is exported/applied
 * (appearance page) or handed straight back as the submission package (store upload).
 */
@Composable
fun ThemeMergeDialog(
    show: Boolean,
    onDismissRequest: () -> Unit,
    onSnapshotCurrent: suspend () -> File?,
    onApplyMerged: ((File) -> Unit)? = null,
    onUseForUpload: ((File) -> Unit)? = null,
) {
    if (!show) return

    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val unsetLabel = stringResource(R.string.theme_merge_unset)
    val currentLabel = stringResource(R.string.theme_merge_use_current)
    val mergeFailed = stringResource(R.string.theme_merge_failed)
    val busyLabel = stringResource(R.string.theme_merge_busy)

    var lightPath by rememberSaveable { mutableStateOf<String?>(null) }
    var darkPath by rememberSaveable { mutableStateOf<String?>(null) }
    var lightLabel by rememberSaveable { mutableStateOf<String?>(null) }
    var darkLabel by rememberSaveable { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var errorText by rememberSaveable { mutableStateOf<String?>(null) }
    var pendingMerged by remember { mutableStateOf<File?>(null) }

    fun slotFile(name: String) = File(context.cacheDir, name)

    fun displayName(uri: Uri): String = runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null }
            ?: uri.lastPathSegment.orEmpty()
    }.getOrDefault(uri.lastPathSegment.orEmpty())

    fun stageUri(uri: Uri, target: File): Boolean = runCatching {
        context.contentResolver.openInputStream(uri)?.use { input ->
            target.outputStream().buffered().use { input.copyTo(it) }
        } ?: error("Cannot open the theme package")
        true
    }.getOrDefault(false)

    fun stageSnapshot(source: File, target: File): Boolean = runCatching {
        source.copyTo(target, overwrite = true)
        true
    }.getOrDefault(false)

    val packageMimes = arrayOf(
        ThemePackageStorage.THEME_MIME_TYPE,
        "application/octet-stream",
        "application/zip",
        "application/x-zip-compressed",
        "*/*",
    )
    val lightPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val target = slotFile("adaptive_slot_light.sukisu")
        if (stageUri(uri, target)) {
            lightPath = target.absolutePath
            lightLabel = displayName(uri)
            errorText = null
        } else {
            errorText = mergeFailed
        }
    }
    val darkPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val target = slotFile("adaptive_slot_dark.sukisu")
        if (stageUri(uri, target)) {
            darkPath = target.absolutePath
            darkLabel = displayName(uri)
            errorText = null
        } else {
            errorText = mergeFailed
        }
    }
    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("*/*"),
    ) { uri ->
        val file = pendingMerged
        pendingMerged = null
        if (uri == null || file == null) return@rememberLauncherForActivityResult
        val ok = runCatching {
            context.contentResolver.openOutputStream(uri)?.use { output ->
                file.inputStream().buffered().use { it.copyTo(output) }
            } ?: error("Cannot open the destination file")
        }.isSuccess
        Toast.makeText(
            context,
            if (ok) R.string.theme_export_success else R.string.theme_export_failed,
            Toast.LENGTH_SHORT,
        ).show()
        if (ok) onDismissRequest()
    }

    fun snapshot(intoDark: Boolean) {
        if (busy) return
        scope.launch {
            busy = true
            val source = onSnapshotCurrent()
            val target = slotFile(if (intoDark) "adaptive_slot_dark.sukisu" else "adaptive_slot_light.sukisu")
            if (source != null && stageSnapshot(source, target)) {
                if (intoDark) {
                    darkPath = target.absolutePath
                    darkLabel = currentLabel
                } else {
                    lightPath = target.absolutePath
                    lightLabel = currentLabel
                }
                errorText = null
            } else {
                errorText = mergeFailed
            }
            busy = false
        }
    }

    fun merge(onResult: (File) -> Unit) {
        if (busy) return
        val light = lightPath ?: return
        val dark = darkPath ?: return
        scope.launch {
            busy = true
            errorText = null
            val result = ThemePackageStorage.mergeAdaptive(
                context,
                Uri.fromFile(File(light)),
                Uri.fromFile(File(dark)),
            )
            busy = false
            result.onSuccess(onResult).onFailure {
                errorText = mergeFailed
            }
        }
    }

    val ready = lightPath != null && darkPath != null
    val forUpload = onUseForUpload != null

    when (LocalUiMode.current) {
        UiMode.Miuix -> WindowDialog(
            show = true,
            title = stringResource(R.string.theme_merge_title),
            onDismissRequest = onDismissRequest,
            content = {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(
                        text = stringResource(R.string.theme_merge_summary),
                        style = MiuixTheme.textStyles.body2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                    Spacer(Modifier.height(4.dp))
                    MergeSlotRowMiuix(
                        title = stringResource(R.string.theme_merge_light),
                        value = lightLabel ?: unsetLabel,
                        enabled = !busy,
                        onPick = { lightPicker.launch(packageMimes) },
                        onCurrent = { snapshot(intoDark = false) },
                    )
                    MergeSlotRowMiuix(
                        title = stringResource(R.string.theme_merge_dark),
                        value = darkLabel ?: unsetLabel,
                        enabled = !busy,
                        onPick = { darkPicker.launch(packageMimes) },
                        onCurrent = { snapshot(intoDark = true) },
                    )
                    if (errorText != null) {
                        Text(
                            text = errorText.orEmpty(),
                            style = MiuixTheme.textStyles.body2,
                            color = MiuixTheme.colorScheme.primary,
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        TextButton(
                            text = if (busy) busyLabel else stringResource(R.string.cancel),
                            onClick = onDismissRequest,
                            modifier = Modifier.weight(1f),
                        )
                        if (forUpload) {
                            TextButton(
                                text = if (busy) busyLabel else stringResource(R.string.theme_merge_use_for_upload),
                                onClick = {
                                    merge { file ->
                                        onUseForUpload.invoke(file)
                                        onDismissRequest()
                                    }
                                },
                                enabled = ready && !busy,
                                colors = MiuixButtonDefaults.textButtonColorsPrimary(),
                                modifier = Modifier.weight(1f),
                            )
                        } else {
                            TextButton(
                                text = if (busy) busyLabel else stringResource(R.string.theme_merge_apply),
                                onClick = {
                                    merge { file ->
                                        onApplyMerged?.invoke(file)
                                        onDismissRequest()
                                    }
                                },
                                enabled = ready && !busy,
                                modifier = Modifier.weight(1f),
                            )
                            TextButton(
                                text = if (busy) busyLabel else stringResource(R.string.theme_merge_export),
                                onClick = {
                                    merge { file ->
                                        pendingMerged = file
                                        exportLauncher.launch(ThemePackageStorage.packageFileName())
                                    }
                                },
                                enabled = ready && !busy,
                                colors = MiuixButtonDefaults.textButtonColorsPrimary(),
                                modifier = Modifier.weight(1f),
                            )
                        }
                    }
                }
            },
        )
        UiMode.Material -> MaterialExpressivePalette {
            AlertDialog(
                onDismissRequest = onDismissRequest,
                icon = {
                    MaterialIcon(
                        imageVector = Icons.Rounded.DarkMode,
                        contentDescription = null,
                    )
                },
                title = { MaterialText(stringResource(R.string.theme_merge_title)) },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        MaterialText(
                            text = stringResource(R.string.theme_merge_summary),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        MergeSlotCardMaterial(
                            title = stringResource(R.string.theme_merge_light),
                            value = lightLabel ?: unsetLabel,
                            icon = Icons.Rounded.LightMode,
                            enabled = !busy,
                            onPick = { lightPicker.launch(packageMimes) },
                            onCurrent = { snapshot(intoDark = false) },
                        )
                        MergeSlotCardMaterial(
                            title = stringResource(R.string.theme_merge_dark),
                            value = darkLabel ?: unsetLabel,
                            icon = Icons.Rounded.DarkMode,
                            enabled = !busy,
                            onPick = { darkPicker.launch(packageMimes) },
                            onCurrent = { snapshot(intoDark = true) },
                        )
                        if (errorText != null) {
                            ThemeStoreInlineNotice(
                                text = errorText.orEmpty(),
                                isError = true,
                            )
                        }
                        if (forUpload) {
                            MergeActionButtonMaterial(
                                label = if (busy) busyLabel else stringResource(R.string.theme_merge_use_for_upload),
                                busy = busy,
                                modifier = Modifier.fillMaxWidth(),
                                onClick = {
                                    merge { file ->
                                        onUseForUpload.invoke(file)
                                        onDismissRequest()
                                    }
                                },
                            )
                        } else {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(10.dp),
                            ) {
                                OutlinedButton(
                                    onClick = {
                                        merge { file ->
                                            onApplyMerged?.invoke(file)
                                            onDismissRequest()
                                        }
                                    },
                                    enabled = ready && !busy,
                                    shapes = ButtonDefaults.shapes(),
                                    modifier = Modifier
                                        .weight(1f)
                                        .height(44.dp),
                                ) {
                                    MaterialText(
                                        text = if (busy) {
                                            busyLabel
                                        } else {
                                            stringResource(R.string.theme_merge_apply)
                                        },
                                        style = MaterialTheme.typography.labelLarge,
                                    )
                                }
                                MergeActionButtonMaterial(
                                    label = if (busy) busyLabel else stringResource(R.string.theme_merge_export),
                                    busy = busy,
                                    modifier = Modifier.weight(1f),
                                    onClick = {
                                        merge { file ->
                                            pendingMerged = file
                                            exportLauncher.launch(ThemePackageStorage.packageFileName())
                                        }
                                    },
                                )
                            }
                        }
                    }
                },
                confirmButton = {
                    MaterialTextButton(
                        onClick = onDismissRequest,
                        enabled = !busy,
                    ) {
                        MaterialText(stringResource(R.string.cancel))
                    }
                },
            )
        }
    }
}

/** MD3E action button: expressive shapes with the wavy progress indicator while merging. */
@Composable
private fun MergeActionButtonMaterial(
    label: String,
    busy: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    Button(
        onClick = onClick,
        enabled = !busy,
        shapes = ButtonDefaults.shapes(),
        modifier = modifier.height(44.dp),
    ) {
        if (busy) {
            CircularWavyProgressIndicator(
                modifier = Modifier.size(18.dp),
                color = MaterialTheme.colorScheme.onPrimary,
                trackColor = Color.Transparent,
                stroke = Stroke(width = 2f),
            )
            Spacer(Modifier.size(6.dp))
        }
        MaterialText(
            text = label,
            style = MaterialTheme.typography.labelLarge,
        )
    }
}

/** MD3E slot card: tonal container, circular icon tile and expressive filter chips. */
@Composable
private fun MergeSlotCardMaterial(
    title: String,
    value: String,
    icon: ImageVector,
    enabled: Boolean,
    onPick: () -> Unit,
    onCurrent: () -> Unit,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Surface(
                    modifier = Modifier.size(34.dp),
                    shape = CircleShape,
                    color = MaterialTheme.colorScheme.primaryContainer,
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        MaterialIcon(
                            imageVector = icon,
                            contentDescription = null,
                            modifier = Modifier.size(19.dp),
                            tint = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                    }
                }
                Column(modifier = Modifier.weight(1f)) {
                    MaterialText(
                        text = title,
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    MaterialText(
                        text = value,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = false,
                    onClick = onPick,
                    enabled = enabled,
                    label = {
                        MaterialText(
                            text = stringResource(R.string.theme_merge_pick),
                            style = MaterialTheme.typography.labelLarge,
                        )
                    },
                    shapes = FilterChipDefaults.shapes(),
                )
                FilterChip(
                    selected = false,
                    onClick = onCurrent,
                    enabled = enabled,
                    label = {
                        MaterialText(
                            text = stringResource(R.string.theme_merge_use_current),
                            style = MaterialTheme.typography.labelLarge,
                        )
                    },
                    shapes = FilterChipDefaults.shapes(),
                )
            }
        }
    }
}

@Composable
private fun MergeSlotRowMiuix(
    title: String,
    value: String,
    enabled: Boolean,
    onPick: () -> Unit,
    onCurrent: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(
            text = title,
            style = MiuixTheme.textStyles.body2,
            color = MiuixTheme.colorScheme.primary,
        )
        Text(
            text = value,
            style = MiuixTheme.textStyles.body2,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(
                text = stringResource(R.string.theme_merge_pick),
                onClick = onPick,
                enabled = enabled,
            )
            TextButton(
                text = stringResource(R.string.theme_merge_use_current),
                onClick = onCurrent,
                enabled = enabled,
            )
        }
    }
}

