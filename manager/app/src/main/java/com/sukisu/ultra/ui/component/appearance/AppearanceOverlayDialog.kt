package com.sukisu.ultra.ui.component.appearance

import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.component.material.ExpressiveDialog
import com.sukisu.ultra.ui.util.AppearanceOverlayData
import com.sukisu.ultra.ui.util.AppearanceOverlayStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.basic.TextButton as MiuixTextButton
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * Editor for the static appearance overlay. The JSON is validated only on Apply/Import, never
 * per keystroke and never during composition.
 */
@Composable
fun AppearanceOverlayDialog(
    show: Boolean,
    initialJson: String,
    onDismissRequest: () -> Unit,
    onApply: (AppearanceOverlayData) -> Unit,
    onReset: () -> Unit,
) {
    if (!show) return

    val context = LocalContext.current
    val resources = LocalResources.current
    val scope = rememberCoroutineScope()
    val miuix = LocalUiMode.current == UiMode.Miuix
    var text by rememberSaveable(initialJson) {
        mutableStateOf(
            if (initialJson.isBlank()) {
                AppearanceOverlayStore.encodePretty(AppearanceOverlayData())
            } else {
                runCatching {
                    AppearanceOverlayStore.parse(initialJson).getOrThrow()
                }.map { AppearanceOverlayStore.encodePretty(it.data) }
                    .getOrDefault(initialJson)
            }
        )
    }
    var error by remember { mutableStateOf<String?>(null) }
    var pendingExport by rememberSaveable { mutableStateOf("") }

    fun apply() {
        AppearanceOverlayStore.parse(text)
            .onSuccess {
                error = null
                onApply(it.data)
                onDismissRequest()
            }
            .onFailure {
                error = resources.getString(
                    R.string.appearance_overlay_invalid,
                    it.message.orEmpty(),
                )
            }
    }

    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        scope.launch {
            val loaded = withContext(Dispatchers.IO) {
                runCatching {
                    context.contentResolver.openInputStream(uri)?.use { stream ->
                        AppearanceOverlayStore.readText(stream)
                    } ?: error("empty")
                }
            }
            loaded.onSuccess { raw ->
                text = AppearanceOverlayStore.parse(raw).getOrNull()
                    ?.let { AppearanceOverlayStore.encodePretty(it.data) }
                    ?: raw
                error = null
            }.onFailure {
                error = resources.getString(R.string.appearance_overlay_read_failed)
            }
        }
    }
    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        val textToWrite = pendingExport
        scope.launch {
            val written = withContext(Dispatchers.IO) {
                runCatching {
                    context.contentResolver.openOutputStream(uri)?.use { stream ->
                        stream.write(textToWrite.toByteArray(Charsets.UTF_8))
                    } ?: error("empty")
                }
            }
            if (written.isFailure) {
                Toast.makeText(
                    context,
                    R.string.appearance_overlay_write_failed,
                    Toast.LENGTH_SHORT,
                ).show()
            }
        }
    }

    val exportFileName = stringResource(R.string.appearance_overlay_file_name)
    val editor: @Composable () -> Unit = {
        AppearanceEditor(
            text = text,
            onTextChange = { text = it; error = null },
            error = error,
            miuix = miuix,
            onPreset = { preset ->
                // Presets describe text colours; keep the user's current image effects.
                val currentImage = AppearanceOverlayStore.parse(text).getOrNull()?.data?.image
                text = AppearanceOverlayStore.encodePretty(
                    preset.data.copy(image = currentImage),
                )
                error = null
            },
            onImport = {
                importLauncher.launch(
                    arrayOf("application/json", "text/plain", "application/octet-stream"),
                )
            },
            onExport = {
                pendingExport = text
                exportLauncher.launch(exportFileName)
            },
            onReset = {
                onReset()
                onDismissRequest()
            },
        )
    }

    when (LocalUiMode.current) {
        UiMode.Miuix -> OverlayDialog(
            show = true,
            title = stringResource(R.string.appearance_overlay_dialog_title),
            summary = stringResource(R.string.appearance_overlay_dialog_message),
            onDismissRequest = onDismissRequest,
            insideMargin = DpSize(0.dp, 24.dp),
            content = {
                Column(modifier = Modifier.heightIn(max = 520.dp)) {
                    LazyColumn(modifier = Modifier.weight(1f, fill = false)) {
                        item { editor() }
                    }
                    Spacer(Modifier.height(12.dp))
                    Row(
                        modifier = Modifier.padding(horizontal = 24.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        MiuixTextButton(
                            text = stringResource(R.string.cancel),
                            onClick = onDismissRequest,
                            modifier = Modifier.weight(1f),
                        )
                        Spacer(Modifier.width(20.dp))
                        MiuixTextButton(
                            text = stringResource(R.string.appearance_overlay_apply),
                            onClick = { apply() },
                            modifier = Modifier.weight(1f),
                            colors = top.yukonga.miuix.kmp.basic.ButtonDefaults.textButtonColorsPrimary(),
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                }
            },
        )

        UiMode.Material -> ExpressiveDialog(
            onDismissRequest = onDismissRequest,
            title = { MaterialText(stringResource(R.string.appearance_overlay_dialog_title)) },
            text = { editor() },
            confirmButton = {
                MaterialTextButton(onClick = { apply() }) {
                    MaterialText(stringResource(R.string.appearance_overlay_apply))
                }
            },
            dismissButton = {
                MaterialTextButton(onClick = onDismissRequest) {
                    MaterialText(stringResource(R.string.cancel))
                }
            },
        )
    }
}

@Composable
private fun AppearanceEditor(
    text: String,
    onTextChange: (String) -> Unit,
    error: String?,
    miuix: Boolean,
    onPreset: (OverlayPreset) -> Unit,
    onImport: () -> Unit,
    onExport: () -> Unit,
    onReset: () -> Unit,
) {
    val onSurface = if (miuix) {
        MiuixTheme.colorScheme.onSurface
    } else {
        MaterialTheme.colorScheme.onSurface
    }
    val primary = if (miuix) {
        MiuixTheme.colorScheme.primary
    } else {
        MaterialTheme.colorScheme.primary
    }
    val surface = if (miuix) {
        MiuixTheme.colorScheme.surfaceContainer
    } else {
        MaterialTheme.colorScheme.surfaceContainerHigh
    }
    val errorColor = if (miuix) {
        MiuixTheme.colorScheme.error
    } else {
        MaterialTheme.colorScheme.error
    }
    val outlineColor = if (miuix) {
        MiuixTheme.colorScheme.outline
    } else {
        MaterialTheme.colorScheme.outline
    }

    Column {
        SchemaNote(
            text = stringResource(R.string.appearance_overlay_schema_hint),
            color = onSurface.copy(alpha = 0.8f),
            miuix = miuix,
        )
        Spacer(Modifier.height(10.dp))
        EditorNote(
            text = stringResource(R.string.appearance_overlay_presets),
            color = primary,
            miuix = miuix,
        )
        Spacer(Modifier.height(2.dp))
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(surface, RoundedCornerShape(12.dp))
                .border(1.dp, outlineColor.copy(alpha = 0.2f), RoundedCornerShape(12.dp)),
        ) {
            OverlayPresets.forEachIndexed { index, preset ->
                if (index > 0) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(1.dp)
                            .background(outlineColor.copy(alpha = 0.18f)),
                    )
                }
                PresetEntry(
                    title = stringResource(preset.titleRes),
                    color = primary,
                    miuix = miuix,
                    onClick = { onPreset(preset) },
                )
            }
        }
        Spacer(Modifier.height(6.dp))
        EditorNote(
            text = stringResource(R.string.appearance_preset_apply_summary),
            color = onSurface.copy(alpha = 0.65f),
            miuix = miuix,
        )
        Spacer(Modifier.height(10.dp))
        EditorNote(
            text = stringResource(R.string.appearance_overlay_editor_label),
            color = onSurface,
            miuix = miuix,
        )
        Spacer(Modifier.height(4.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(220.dp)
                .background(surface, RoundedCornerShape(12.dp))
                .border(1.dp, outlineColor.copy(alpha = 0.25f), RoundedCornerShape(12.dp))
                .padding(12.dp),
        ) {
            BasicTextField(
                value = text,
                onValueChange = onTextChange,
                textStyle = TextStyle(
                    color = onSurface,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                ),
                cursorBrush = SolidColor(primary),
                modifier = Modifier.fillMaxWidth().heightIn(max = 196.dp),
            )
        }
        if (error != null) {
            Spacer(Modifier.height(6.dp))
            EditorNote(text = error, color = errorColor, miuix = miuix)
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            Spacer(Modifier.height(6.dp))
            EditorNote(
                text = stringResource(R.string.appearance_overlay_sharpen_api_notice),
                color = primary,
                miuix = miuix,
            )
        }
        Spacer(Modifier.height(10.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(outlineColor.copy(alpha = 0.18f)),
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextAction(
                text = stringResource(R.string.appearance_overlay_import),
                color = primary,
                miuix = miuix,
                onClick = onImport,
            )
            TextAction(
                text = stringResource(R.string.appearance_overlay_export),
                color = primary,
                miuix = miuix,
                onClick = onExport,
            )
            Spacer(Modifier.weight(1f))
            TextAction(
                text = stringResource(R.string.appearance_overlay_reset),
                color = errorColor,
                miuix = miuix,
                onClick = onReset,
            )
        }
    }
}

@Composable
private fun PresetEntry(
    title: String,
    color: androidx.compose.ui.graphics.Color,
    miuix: Boolean,
    onClick: () -> Unit,
) {
    if (miuix) {
        MiuixText(
            text = title,
            color = color,
            style = MiuixTheme.textStyles.body1,
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onClick)
                .padding(horizontal = 14.dp, vertical = 12.dp),
        )
    } else {
        MaterialText(
            text = title,
            color = color,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onClick)
                .padding(horizontal = 14.dp, vertical = 12.dp),
        )
    }
}

@Composable
private fun SchemaNote(
    text: String,
    color: androidx.compose.ui.graphics.Color,
    miuix: Boolean,
) {
    if (miuix) {
        MiuixText(
            text = text,
            color = color,
            style = MiuixTheme.textStyles.body2.copy(
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                lineHeight = 15.sp,
            ),
        )
    } else {
        MaterialText(
            text = text,
            color = color,
            style = MaterialTheme.typography.bodySmall.copy(
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                lineHeight = 15.sp,
            ),
        )
    }
}

@Composable
private fun EditorNote(
    text: String,
    color: androidx.compose.ui.graphics.Color,
    miuix: Boolean,
) {
    if (miuix) {
        MiuixText(
            text = text,
            color = color,
            style = MiuixTheme.textStyles.body2,
        )
    } else {
        MaterialText(
            text = text,
            color = color,
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

@Composable
private fun TextAction(
    text: String,
    color: androidx.compose.ui.graphics.Color,
    miuix: Boolean,
    onClick: () -> Unit,
) {
    if (miuix) {
        MiuixText(
            text = text,
            color = color,
            style = MiuixTheme.textStyles.body2,
            modifier = Modifier
                .clickable(onClick = onClick)
                .padding(horizontal = 10.dp, vertical = 8.dp),
        )
    } else {
        MaterialText(
            text = text,
            color = color,
            style = MaterialTheme.typography.labelLarge,
            modifier = Modifier
                .clickable(onClick = onClick)
                .padding(horizontal = 10.dp, vertical = 8.dp),
        )
    }
}
