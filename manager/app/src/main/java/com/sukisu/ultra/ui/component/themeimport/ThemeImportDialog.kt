package com.sukisu.ultra.ui.component.themeimport

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text as MaterialText
import androidx.compose.material3.TextButton as MaterialTextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.screen.settings.ThemeImportOptions
import com.sukisu.ultra.ui.util.ImportedTheme
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.preference.CheckboxPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.window.WindowDialog

@Composable
fun ThemeImportDialog(
    show: Boolean,
    theme: ImportedTheme?,
    onDismissRequest: () -> Unit,
    onConfirm: (ThemeImportOptions) -> Unit,
) {
    if (!show || theme == null) return

    val hasImages = theme.backgroundPath != null || theme.cardBackgroundPath != null
    val hasAppIcon = theme.data.appIconId != null
    val hasTexts = !theme.data.customTexts.isNullOrEmpty() || !theme.data.customHomeTitle.isNullOrBlank()

    var importAppearance by remember(theme) { mutableStateOf(true) }
    var importImages by remember(theme) { mutableStateOf(hasImages) }
    var importAppIcon by remember(theme) { mutableStateOf(hasAppIcon) }
    var importCustomTexts by remember(theme) { mutableStateOf(hasTexts) }
    var importCustomConfig by remember(theme) { mutableStateOf(true) }

    val options = ThemeImportOptions(
        importAppearance = importAppearance,
        importImages = importImages && hasImages,
        importAppIcon = importAppIcon && hasAppIcon,
        importCustomTexts = importCustomTexts && hasTexts,
        importCustomConfig = importCustomConfig,
    )

    when (LocalUiMode.current) {
        UiMode.Miuix -> {
            WindowDialog(
                show = show,
                title = stringResource(R.string.theme_import_dialog_title),
                onDismissRequest = onDismissRequest,
                content = {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 24.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(
                            text = stringResource(R.string.theme_import_dialog_message),
                            style = MiuixTheme.textStyles.body2,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                        Spacer(Modifier.height(4.dp))
                        CheckboxPreference(
                            title = stringResource(R.string.theme_import_opt_appearance),
                            checked = importAppearance,
                            onCheckedChange = { importAppearance = it },
                        )
                        if (hasImages) {
                            CheckboxPreference(
                                title = stringResource(R.string.theme_import_opt_images),
                                checked = importImages,
                                onCheckedChange = { importImages = it },
                            )
                        }
                        if (hasAppIcon) {
                            CheckboxPreference(
                                title = stringResource(R.string.theme_import_opt_app_icon),
                                checked = importAppIcon,
                                onCheckedChange = { importAppIcon = it },
                            )
                        }
                        if (hasTexts) {
                            CheckboxPreference(
                                title = stringResource(R.string.theme_import_opt_custom_texts),
                                checked = importCustomTexts,
                                onCheckedChange = { importCustomTexts = it },
                            )
                        }
                        CheckboxPreference(
                            title = stringResource(R.string.theme_import_opt_custom_config),
                            checked = importCustomConfig,
                            onCheckedChange = { importCustomConfig = it },
                        )
                        Spacer(Modifier.height(12.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            TextButton(
                                text = stringResource(R.string.cancel),
                                onClick = onDismissRequest,
                                modifier = Modifier.weight(1f),
                            )
                            TextButton(
                                text = stringResource(R.string.confirm),
                                colors = ButtonDefaults.textButtonColorsPrimary(),
                                onClick = {
                                    onConfirm(options)
                                },
                                modifier = Modifier.weight(1f),
                            )
                        }
                    }
                }
            )
        }
        UiMode.Material -> {
            AlertDialog(
                onDismissRequest = onDismissRequest,
                title = { MaterialText(stringResource(R.string.theme_import_dialog_title)) },
                text = {
                    Column(modifier = Modifier.fillMaxWidth()) {
                        MaterialText(
                            text = stringResource(R.string.theme_import_dialog_message),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(bottom = 12.dp)
                        )
                        MaterialCheckboxRow(
                            title = stringResource(R.string.theme_import_opt_appearance),
                            checked = importAppearance,
                            onCheckedChange = { importAppearance = it },
                        )
                        if (hasImages) {
                            MaterialCheckboxRow(
                                title = stringResource(R.string.theme_import_opt_images),
                                checked = importImages,
                                onCheckedChange = { importImages = it },
                            )
                        }
                        if (hasAppIcon) {
                            MaterialCheckboxRow(
                                title = stringResource(R.string.theme_import_opt_app_icon),
                                checked = importAppIcon,
                                onCheckedChange = { importAppIcon = it },
                            )
                        }
                        if (hasTexts) {
                            MaterialCheckboxRow(
                                title = stringResource(R.string.theme_import_opt_custom_texts),
                                checked = importCustomTexts,
                                onCheckedChange = { importCustomTexts = it },
                            )
                        }
                        MaterialCheckboxRow(
                            title = stringResource(R.string.theme_import_opt_custom_config),
                            checked = importCustomConfig,
                            onCheckedChange = { importCustomConfig = it },
                        )
                    }
                },
                confirmButton = {
                    MaterialTextButton(onClick = { onConfirm(options) }) {
                        MaterialText(stringResource(R.string.confirm))
                    }
                },
                dismissButton = {
                    MaterialTextButton(onClick = onDismissRequest) {
                        MaterialText(stringResource(R.string.cancel))
                    }
                }
            )
        }
    }
}

@Composable
private fun MaterialCheckboxRow(
    title: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCheckedChange(!checked) }
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(
            checked = checked,
            onCheckedChange = onCheckedChange,
        )
        Spacer(Modifier.width(8.dp))
        MaterialText(
            text = title,
            style = MaterialTheme.typography.bodyLarge,
        )
    }
}