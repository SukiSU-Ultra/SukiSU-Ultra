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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text as MaterialText
import androidx.compose.material3.TextButton as MaterialTextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.screen.settings.ThemePackageOptions
import com.sukisu.ultra.ui.theme.MaterialExpressivePalette
import com.sukisu.ultra.ui.util.CustomTextGroup
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.preference.CheckboxPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.window.WindowDialog

/**
 * Theme package import/export picker. The groups mirror the appearance page's sections and the
 * entries under each group select individual parts.
 */
@Composable
fun ThemeOptionsDialog(
    show: Boolean,
    title: String,
    message: String,
    hasBackgroundImage: Boolean,
    hasCardImage: Boolean,
    hasStickers: Boolean,
    hasAppIcon: Boolean,
    availableCustomTextGroups: Set<CustomTextGroup>,
    onDismissRequest: () -> Unit,
    onConfirm: (ThemePackageOptions) -> Unit,
    formatVersion: Int? = null,
    forceMaterial: Boolean = false,
) {
    if (!show) return

    var colors by rememberSaveable { mutableStateOf(true) }
    var backgroundImage by rememberSaveable { mutableStateOf(true) }
    var backgroundAppearance by rememberSaveable { mutableStateOf(true) }
    var homeCardImage by rememberSaveable { mutableStateOf(true) }
    var stickers by rememberSaveable { mutableStateOf(true) }
    var homeCardDisplay by rememberSaveable { mutableStateOf(true) }
    var appIcon by rememberSaveable { mutableStateOf(true) }
    var customTexts by rememberSaveable { mutableStateOf(true) }
    var customTextHome by rememberSaveable { mutableStateOf(true) }
    var customTextPageMain by rememberSaveable { mutableStateOf(true) }
    var customTextPageFeature by rememberSaveable { mutableStateOf(true) }
    var customTextSettings by rememberSaveable { mutableStateOf(true) }
    var customConfig by rememberSaveable { mutableStateOf(true) }

    val selectedTextGroups = buildSet {
        if (customTextHome) add(CustomTextGroup.HOME)
        if (customTextPageMain) add(CustomTextGroup.PAGE_MAIN)
        if (customTextPageFeature) add(CustomTextGroup.PAGE_FEATURE)
        if (customTextSettings) add(CustomTextGroup.SETTINGS)
    }.intersect(availableCustomTextGroups)

    fun setTextGroupChecked(group: CustomTextGroup, checked: Boolean) {
        when (group) {
            CustomTextGroup.HOME -> customTextHome = checked
            CustomTextGroup.PAGE_MAIN -> customTextPageMain = checked
            CustomTextGroup.PAGE_FEATURE -> customTextPageFeature = checked
            CustomTextGroup.SETTINGS -> customTextSettings = checked
        }
    }

    val options = ThemePackageOptions(
        colors = colors,
        backgroundImage = backgroundImage && hasBackgroundImage,
        backgroundAppearance = backgroundAppearance,
        homeCardImage = homeCardImage && hasCardImage,
        stickers = stickers && hasStickers,
        homeCardDisplay = homeCardDisplay,
        appIcon = appIcon && hasAppIcon,
        customTexts = customTexts && availableCustomTextGroups.isNotEmpty(),
        customTextGroups = selectedTextGroups,
        customConfig = customConfig,
    )

    when (if (forceMaterial) UiMode.Material else LocalUiMode.current) {
        UiMode.Miuix -> {
            WindowDialog(
                show = show,
                title = title,
                onDismissRequest = onDismissRequest,
                content = {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .verticalScroll(rememberScrollState())
                            .padding(horizontal = 24.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Text(
                            text = message,
                            style = MiuixTheme.textStyles.body2,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                        if (formatVersion != null) {
                            Text(
                                text = stringResource(R.string.theme_package_format_version, formatVersion),
                                style = MiuixTheme.textStyles.body2,
                                color = MiuixTheme.colorScheme.primary,
                            )
                        }
                        Spacer(Modifier.height(4.dp))
                        OptionGroupLabel(stringResource(R.string.settings_section_colors))
                        CheckboxPreference(
                            title = stringResource(R.string.theme_opt_colors),
                            checked = colors,
                            onCheckedChange = { colors = it },
                        )
                        OptionGroupLabel(stringResource(R.string.settings_section_background))
                        if (hasBackgroundImage) {
                            CheckboxPreference(
                                title = stringResource(R.string.theme_opt_background_image),
                                checked = backgroundImage,
                                onCheckedChange = { backgroundImage = it },
                            )
                        }
                        CheckboxPreference(
                            title = stringResource(R.string.theme_opt_background_appearance),
                            checked = backgroundAppearance,
                            onCheckedChange = { backgroundAppearance = it },
                        )
                        OptionGroupLabel(stringResource(R.string.settings_section_home_card))
                        if (hasCardImage) {
                            CheckboxPreference(
                                title = stringResource(R.string.theme_opt_home_card_image),
                                checked = homeCardImage,
                                onCheckedChange = { homeCardImage = it },
                            )
                        }
                        if (hasStickers) {
                            CheckboxPreference(
                                title = stringResource(R.string.theme_opt_stickers),
                                checked = stickers,
                                onCheckedChange = { stickers = it },
                            )
                        }
                        CheckboxPreference(
                            title = stringResource(R.string.theme_opt_home_card_display),
                            checked = homeCardDisplay,
                            onCheckedChange = { homeCardDisplay = it },
                        )
                        OptionGroupLabel(stringResource(R.string.settings_section_appearance))
                        if (hasAppIcon) {
                            CheckboxPreference(
                                title = stringResource(R.string.theme_opt_app_icon),
                                checked = appIcon,
                                onCheckedChange = { appIcon = it },
                            )
                        }
                        if (availableCustomTextGroups.isNotEmpty()) {
                            CheckboxPreference(
                                title = stringResource(R.string.theme_opt_custom_texts),
                                checked = customTexts,
                                onCheckedChange = { customTexts = it },
                            )
                            if (customTexts) {
                                CustomTextGroup.entries
                                    .filter { it in availableCustomTextGroups }
                                    .forEach { group ->
                                        CheckboxPreference(
                                            title = stringResource(group.titleRes),
                                            checked = group in selectedTextGroups,
                                            onCheckedChange = { setTextGroupChecked(group, it) },
                                            modifier = Modifier.padding(start = 12.dp),
                                        )
                                    }
                            }
                        }
                        OptionGroupLabel(stringResource(R.string.theme_opt_other))
                        CheckboxPreference(
                            title = stringResource(R.string.theme_opt_custom_config),
                            checked = customConfig,
                            onCheckedChange = { customConfig = it },
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
                                onClick = { onConfirm(options) },
                                modifier = Modifier.weight(1f),
                            )
                        }
                    }
                }
            )
        }
        UiMode.Material -> MaterialExpressivePalette {
            AlertDialog(
                onDismissRequest = onDismissRequest,
                title = { MaterialText(title) },
                text = {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .verticalScroll(rememberScrollState())
                    ) {
                        MaterialText(
                            text = message,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        if (formatVersion != null) {
                            MaterialText(
                                text = stringResource(R.string.theme_package_format_version, formatVersion),
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.padding(bottom = 12.dp),
                            )
                        } else {
                            Spacer(Modifier.height(12.dp))
                        }
                        MaterialOptionGroupLabel(stringResource(R.string.settings_section_colors))
                        MaterialCheckboxRow(
                            title = stringResource(R.string.theme_opt_colors),
                            checked = colors,
                            onCheckedChange = { colors = it },
                        )
                        MaterialOptionGroupLabel(stringResource(R.string.settings_section_background))
                        if (hasBackgroundImage) {
                            MaterialCheckboxRow(
                                title = stringResource(R.string.theme_opt_background_image),
                                checked = backgroundImage,
                                onCheckedChange = { backgroundImage = it },
                            )
                        }
                        MaterialCheckboxRow(
                            title = stringResource(R.string.theme_opt_background_appearance),
                            checked = backgroundAppearance,
                            onCheckedChange = { backgroundAppearance = it },
                        )
                        MaterialOptionGroupLabel(stringResource(R.string.settings_section_home_card))
                        if (hasCardImage) {
                            MaterialCheckboxRow(
                                title = stringResource(R.string.theme_opt_home_card_image),
                                checked = homeCardImage,
                                onCheckedChange = { homeCardImage = it },
                            )
                        }
                        if (hasStickers) {
                            MaterialCheckboxRow(
                                title = stringResource(R.string.theme_opt_stickers),
                                checked = stickers,
                                onCheckedChange = { stickers = it },
                            )
                        }
                        MaterialCheckboxRow(
                            title = stringResource(R.string.theme_opt_home_card_display),
                            checked = homeCardDisplay,
                            onCheckedChange = { homeCardDisplay = it },
                        )
                        MaterialOptionGroupLabel(stringResource(R.string.settings_section_appearance))
                        if (hasAppIcon) {
                            MaterialCheckboxRow(
                                title = stringResource(R.string.theme_opt_app_icon),
                                checked = appIcon,
                                onCheckedChange = { appIcon = it },
                            )
                        }
                        if (availableCustomTextGroups.isNotEmpty()) {
                            MaterialCheckboxRow(
                                title = stringResource(R.string.theme_opt_custom_texts),
                                checked = customTexts,
                                onCheckedChange = { customTexts = it },
                            )
                            if (customTexts) {
                                CustomTextGroup.entries
                                    .filter { it in availableCustomTextGroups }
                                    .forEach { group ->
                                        MaterialCheckboxRow(
                                            title = stringResource(group.titleRes),
                                            checked = group in selectedTextGroups,
                                            onCheckedChange = { setTextGroupChecked(group, it) },
                                            modifier = Modifier.padding(start = 16.dp),
                                        )
                                    }
                            }
                        }
                        MaterialOptionGroupLabel(stringResource(R.string.theme_opt_other))
                        MaterialCheckboxRow(
                            title = stringResource(R.string.theme_opt_custom_config),
                            checked = customConfig,
                            onCheckedChange = { customConfig = it },
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
private fun OptionGroupLabel(text: String) {
    Text(
        text = text,
        style = MiuixTheme.textStyles.body2,
        color = MiuixTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 8.dp),
    )
}

@Composable
private fun MaterialOptionGroupLabel(text: String) {
    MaterialText(
        text = text,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 12.dp, bottom = 2.dp),
    )
}

@Composable
private fun MaterialCheckboxRow(
    title: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
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
