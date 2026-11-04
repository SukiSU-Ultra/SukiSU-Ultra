package com.sukisu.ultra.ui.component.themeimport

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.component.material.ExpressiveDialog
import com.sukisu.ultra.ui.screen.settings.ThemePackageOptions
import com.sukisu.ultra.ui.theme.MaterialExpressivePalette
import com.sukisu.ultra.ui.util.CustomTextGroup
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.preference.CheckboxLocation
import top.yukonga.miuix.kmp.preference.CheckboxPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme

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
    adaptive: Boolean = false,
    adaptiveNotice: Int = R.string.theme_adaptive_import_notice,
    forceMaterial: Boolean = false,
    hasCustomColors: Boolean = false,
    hasImageEffects: Boolean = false,
) {
    if (!show) return

    var colors by rememberSaveable { mutableStateOf(true) }
    var customColors by rememberSaveable { mutableStateOf(true) }
    var imageEffects by rememberSaveable { mutableStateOf(true) }
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
    var interfaceMode by rememberSaveable { mutableStateOf(true) }
    var interfaceSwitches by rememberSaveable { mutableStateOf(true) }
    var interactionBehavior by rememberSaveable { mutableStateOf(true) }
    var moduleDisplay by rememberSaveable { mutableStateOf(true) }

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
        interfaceMode = interfaceMode,
        interfaceSwitches = interfaceSwitches,
        interactionBehavior = interactionBehavior,
        moduleDisplay = moduleDisplay,
        customColors = customColors && hasCustomColors,
        imageEffects = imageEffects && hasImageEffects,
    )

    when (if (forceMaterial) UiMode.Material else LocalUiMode.current) {
        UiMode.Miuix -> {
            OverlayDialog(
                show = true,
                title = title,
                summary = message,
                onDismissRequest = onDismissRequest,
                insideMargin = DpSize(0.dp, 24.dp),
                content = {
                    Column(modifier = Modifier.heightIn(max = 500.dp)) {
                        LazyColumn(modifier = Modifier.weight(1f, fill = false)) {
                            if (formatVersion != null) {
                                item {
                                    MiuixInfoLine(
                                        stringResource(R.string.theme_package_format_version, formatVersion),
                                    )
                                }
                            }
                            if (adaptive) {
                                item { MiuixInfoLine(stringResource(adaptiveNotice)) }
                            }
                            item { OptionGroupLabel(stringResource(R.string.settings_section_colors)) }
                            item {
                                MiuixOptionRow(
                                    title = stringResource(R.string.theme_opt_colors),
                                    checked = colors,
                                    onCheckedChange = { colors = it },
                                )
                            }
                            if (hasCustomColors) {
                                item {
                                    MiuixOptionRow(
                                        title = stringResource(R.string.theme_opt_custom_colors),
                                        checked = customColors,
                                        onCheckedChange = { customColors = it },
                                        nested = true,
                                    )
                                }
                            }
                            item { OptionGroupLabel(stringResource(R.string.settings_section_background)) }
                            if (hasBackgroundImage) {
                                item {
                                    MiuixOptionRow(
                                        title = stringResource(R.string.theme_opt_background_image),
                                        checked = backgroundImage,
                                        onCheckedChange = { backgroundImage = it },
                                    )
                                }
                            }
                            item {
                                MiuixOptionRow(
                                    title = stringResource(R.string.theme_opt_background_appearance),
                                    checked = backgroundAppearance,
                                    onCheckedChange = { backgroundAppearance = it },
                                )
                            }
                            if (hasImageEffects) {
                                item {
                                    MiuixOptionRow(
                                        title = stringResource(R.string.theme_opt_image_effects),
                                        checked = imageEffects,
                                        onCheckedChange = { imageEffects = it },
                                        nested = true,
                                    )
                                }
                            }
                            item { OptionGroupLabel(stringResource(R.string.settings_section_home_card)) }
                            if (hasCardImage) {
                                item {
                                    MiuixOptionRow(
                                        title = stringResource(R.string.theme_opt_home_card_image),
                                        checked = homeCardImage,
                                        onCheckedChange = { homeCardImage = it },
                                    )
                                }
                            }
                            if (hasStickers) {
                                item {
                                    MiuixOptionRow(
                                        title = stringResource(R.string.theme_opt_stickers),
                                        checked = stickers,
                                        onCheckedChange = { stickers = it },
                                    )
                                }
                            }
                            item {
                                MiuixOptionRow(
                                    title = stringResource(R.string.theme_opt_home_card_display),
                                    checked = homeCardDisplay,
                                    onCheckedChange = { homeCardDisplay = it },
                                )
                            }
                            item { OptionGroupLabel(stringResource(R.string.settings_section_appearance)) }
                            if (hasAppIcon) {
                                item {
                                    MiuixOptionRow(
                                        title = stringResource(R.string.theme_opt_app_icon),
                                        checked = appIcon,
                                        onCheckedChange = { appIcon = it },
                                    )
                                }
                            }
                            if (availableCustomTextGroups.isNotEmpty()) {
                                item {
                                    MiuixOptionRow(
                                        title = stringResource(R.string.theme_opt_custom_texts),
                                        checked = customTexts,
                                        onCheckedChange = { customTexts = it },
                                    )
                                }
                                if (customTexts) {
                                    items(
                                        CustomTextGroup.entries.filter { it in availableCustomTextGroups },
                                    ) { group ->
                                        MiuixOptionRow(
                                            title = stringResource(group.titleRes),
                                            checked = group in selectedTextGroups,
                                            onCheckedChange = { setTextGroupChecked(group, it) },
                                            nested = true,
                                        )
                                    }
                                }
                            }
                            item { OptionGroupLabel(stringResource(R.string.theme_opt_other)) }
                            item {
                                MiuixOptionRow(
                                    title = stringResource(R.string.theme_opt_interface_mode),
                                    checked = interfaceMode,
                                    onCheckedChange = { interfaceMode = it },
                                )
                            }
                            item {
                                MiuixOptionRow(
                                    title = stringResource(R.string.theme_opt_interface_switches),
                                    checked = interfaceSwitches,
                                    onCheckedChange = { interfaceSwitches = it },
                                )
                            }
                            item {
                                MiuixOptionRow(
                                    title = stringResource(R.string.theme_opt_interaction),
                                    checked = interactionBehavior,
                                    onCheckedChange = { interactionBehavior = it },
                                )
                            }
                            item {
                                MiuixOptionRow(
                                    title = stringResource(R.string.theme_opt_module_display),
                                    checked = moduleDisplay,
                                    onCheckedChange = { moduleDisplay = it },
                                )
                            }
                        }
                        Spacer(Modifier.height(12.dp))
                        Row(
                            modifier = Modifier.padding(horizontal = 24.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            TextButton(
                                text = stringResource(R.string.cancel),
                                onClick = onDismissRequest,
                                modifier = Modifier.weight(1f),
                            )
                            Spacer(Modifier.width(20.dp))
                            TextButton(
                                text = stringResource(R.string.confirm),
                                onClick = { onConfirm(options) },
                                modifier = Modifier.weight(1f),
                                colors = ButtonDefaults.textButtonColorsPrimary(),
                            )
                        }
                    }
                },
            )
        }
        UiMode.Material -> MaterialExpressivePalette {
            ExpressiveDialog(
                onDismissRequest = onDismissRequest,
                title = { MaterialText(title) },
                text = {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .verticalScroll(rememberScrollState()),
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
                                modifier = Modifier.padding(top = 12.dp),
                            )
                        }
                        if (adaptive) {
                            MaterialText(
                                text = stringResource(adaptiveNotice),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.padding(top = 8.dp),
                            )
                        }
                        MaterialOptionGroupLabel(stringResource(R.string.settings_section_colors))
                        MaterialCheckboxRow(
                            title = stringResource(R.string.theme_opt_colors),
                            checked = colors,
                            onCheckedChange = { colors = it },
                        )
                        if (hasCustomColors) {
                            MaterialCheckboxRow(
                                title = stringResource(R.string.theme_opt_custom_colors),
                                checked = customColors,
                                onCheckedChange = { customColors = it },
                                modifier = Modifier.padding(start = 16.dp),
                            )
                        }
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
                        if (hasImageEffects) {
                            MaterialCheckboxRow(
                                title = stringResource(R.string.theme_opt_image_effects),
                                checked = imageEffects,
                                onCheckedChange = { imageEffects = it },
                                modifier = Modifier.padding(start = 16.dp),
                            )
                        }
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
                            title = stringResource(R.string.theme_opt_interface_mode),
                            checked = interfaceMode,
                            onCheckedChange = { interfaceMode = it },
                        )
                        MaterialCheckboxRow(
                            title = stringResource(R.string.theme_opt_interface_switches),
                            checked = interfaceSwitches,
                            onCheckedChange = { interfaceSwitches = it },
                        )
                        MaterialCheckboxRow(
                            title = stringResource(R.string.theme_opt_interaction),
                            checked = interactionBehavior,
                            onCheckedChange = { interactionBehavior = it },
                        )
                        MaterialCheckboxRow(
                            title = stringResource(R.string.theme_opt_module_display),
                            checked = moduleDisplay,
                            onCheckedChange = { moduleDisplay = it },
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
                },
            )
        }
    }
}

@Composable
private fun MiuixInfoLine(text: String) {
    Text(
        text = text,
        style = MiuixTheme.textStyles.body2,
        color = MiuixTheme.colorScheme.primary,
        modifier = Modifier.padding(horizontal = 24.dp, vertical = 4.dp),
    )
}

@Composable
private fun OptionGroupLabel(text: String) {
    Text(
        text = text,
        style = MiuixTheme.textStyles.body2,
        color = MiuixTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 24.dp, end = 24.dp, top = 10.dp, bottom = 4.dp),
    )
}

@Composable
private fun MiuixOptionRow(
    title: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    nested: Boolean = false,
) {
    CheckboxPreference(
        title = title,
        checked = checked,
        onCheckedChange = onCheckedChange,
        checkboxLocation = CheckboxLocation.End,
        insideMargin = if (nested) {
            PaddingValues(start = 46.dp, end = 30.dp, top = 16.dp, bottom = 16.dp)
        } else {
            PaddingValues(horizontal = 30.dp, vertical = 16.dp)
        },
        holdDownState = checked,
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
