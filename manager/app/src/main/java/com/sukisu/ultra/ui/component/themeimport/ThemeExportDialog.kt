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
    adaptive: Boolean = false,
) {
    ThemeOptionsDialog(
        show = show,
        title = stringResource(R.string.theme_export),
        message = stringResource(
            if (adaptive) R.string.theme_adaptive_export_dialog_message
            else R.string.theme_export_dialog_message,
        ),
        hasBackgroundImage = hasBackgroundImage,
        hasCardImage = hasCardImage,
        hasStickers = hasStickers,
        hasAppIcon = hasAppIcon,
        availableCustomTextGroups = availableCustomTextGroups,
        onDismissRequest = onDismissRequest,
        onConfirm = onConfirm,
        formatVersion = if (adaptive) {
            com.sukisu.ultra.ui.util.ThemePackageStorage.ADAPTIVE_FORMAT_VERSION
        } else {
            com.sukisu.ultra.ui.util.ThemePackageStorage.PLAIN_FORMAT_VERSION
        },
        adaptive = adaptive,
        forceMaterial = true,
    )
}
