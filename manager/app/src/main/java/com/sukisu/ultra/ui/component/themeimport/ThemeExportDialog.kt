package com.sukisu.ultra.ui.component.themeimport

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.settings.ThemePackageOptions
import com.sukisu.ultra.ui.util.CustomTextGroup

@Composable
fun ThemeExportDialog(
    show: Boolean,
    hasBackgroundImage: Boolean,
    hasCardImage: Boolean,
    hasStickers: Boolean,
    hasAppIcon: Boolean,
    availableCustomTextGroups: Set<CustomTextGroup>,
    onDismissRequest: () -> Unit,
    onConfirm: (ThemePackageOptions) -> Unit,
) {
    ThemeOptionsDialog(
        show = show,
        title = stringResource(R.string.theme_export),
        message = stringResource(R.string.theme_export_dialog_message),
        hasBackgroundImage = hasBackgroundImage,
        hasCardImage = hasCardImage,
        hasStickers = hasStickers,
        hasAppIcon = hasAppIcon,
        availableCustomTextGroups = availableCustomTextGroups,
        onDismissRequest = onDismissRequest,
        onConfirm = onConfirm,
        formatVersion = com.sukisu.ultra.ui.util.ThemePackageStorage.CURRENT_VERSION,
        forceMaterial = true,
    )
}
