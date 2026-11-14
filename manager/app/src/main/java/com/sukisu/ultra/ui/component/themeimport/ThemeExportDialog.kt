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
    hasCustomColors: Boolean = false,
    hasImageEffects: Boolean = false,
    immersiveHome: Boolean = false,
    hasBottomBarIcons: Boolean = false,
    onUpload: ((ThemePackageOptions) -> Unit)? = null,
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
        formatVersion = when {
            immersiveHome || hasBottomBarIcons ->
                com.sukisu.ultra.ui.util.ThemePackageStorage.HOME_STATUS_VERSION

            hasCustomColors || hasImageEffects ->
                com.sukisu.ultra.ui.util.ThemePackageStorage.APPEARANCE_VERSION

            adaptive -> com.sukisu.ultra.ui.util.ThemePackageStorage.ADAPTIVE_VERSION
            else -> com.sukisu.ultra.ui.util.ThemePackageStorage.BASE_VERSION
        },
        adaptive = adaptive,
        adaptiveNotice = R.string.theme_adaptive_export_notice,
        hasCustomColors = hasCustomColors,
        hasImageEffects = hasImageEffects,
        hasBottomBarIcons = hasBottomBarIcons,
        onUpload = onUpload,
    )
}
