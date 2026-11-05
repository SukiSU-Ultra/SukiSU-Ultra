package com.sukisu.ultra.ui.component.themeimport

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.settings.ThemePackageOptions
import com.sukisu.ultra.ui.util.ImportedTheme
import com.sukisu.ultra.ui.util.customTextGroupsIn

@Composable
fun ThemeImportDialog(
    show: Boolean,
    theme: ImportedTheme?,
    onDismissRequest: () -> Unit,
    onConfirm: (ThemePackageOptions) -> Unit,
    forceMaterial: Boolean = true,
) {
    if (!show || theme == null) return

    val data = theme.data
    val customTextGroups = remember(data.customTexts, data.customHomeTitle) {
        customTextGroupsIn(data.customTexts ?: emptyMap(), data.customHomeTitle.orEmpty())
    }
    ThemeOptionsDialog(
        show = show,
        title = stringResource(R.string.theme_import_dialog_title),
        message = stringResource(R.string.theme_import_dialog_message),
        hasBackgroundImage = theme.backgroundPath != null ||
            theme.light?.backgroundPath != null ||
            theme.dark?.backgroundPath != null ||
            (!theme.isAdaptive && data.hasBackground == false),
        hasCardImage = theme.cardBackgroundPath != null ||
            theme.light?.cardBackgroundPath != null ||
            theme.dark?.cardBackgroundPath != null ||
            (!theme.isAdaptive && data.hasCardBackground == false),
        hasStickers = theme.stickerPaths.isNotEmpty() ||
            theme.light?.stickerPaths?.isNotEmpty() == true ||
            theme.dark?.stickerPaths?.isNotEmpty() == true ||
            (!theme.isAdaptive && data.homeCardStickerTransforms != null),
        hasAppIcon = data.appIconId != null,
        availableCustomTextGroups = customTextGroups,
        onDismissRequest = onDismissRequest,
        onConfirm = onConfirm,
        formatVersion = theme.data.version,
        adaptive = theme.isAdaptive,
        forceMaterial = forceMaterial,
        hasCustomColors = data.appearance?.colors != null,
        hasImageEffects = data.appearance?.image != null,
        hasBottomBarIcons = data.bottomBarIcons != null || theme.bottomBarIconPaths.isNotEmpty(),
    )
}
