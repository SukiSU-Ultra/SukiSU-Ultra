package com.sukisu.ultra.ui.screen.colorpalette

import android.net.Uri
import androidx.activity.compose.LocalActivity
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.dropUnlessResumed
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.KernelSUApplication
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.navigation3.Route
import com.sukisu.ultra.ui.util.ImageStorage
import com.sukisu.ultra.ui.viewmodel.SettingsViewModel
import com.sukisu.ultra.ui.component.themeimport.ThemeImportDialog

@Composable
fun ColorPaletteScreen(section: String? = null, importUri: String? = null) {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val activity = LocalActivity.current
    val viewModel = viewModel<SettingsViewModel>()
    // The page state is projected in the view model, so nothing is parsed while composing.
    val state by viewModel.colorPaletteState.collectAsStateWithLifecycle()
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    var consumedImportUri by rememberSaveable { mutableStateOf<String?>(null) }

    // A package opened from another app is forwarded through the route so the dialog is shown
    // by the destination's own view model instead of the activity-scoped dispatcher one.
    LaunchedEffect(importUri) {
        if (!importUri.isNullOrBlank() && consumedImportUri != importUri) {
            consumedImportUri = importUri
            viewModel.importTheme(context, Uri.parse(importUri))
        }
    }

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        viewModel.refreshBackgroundAppearance()
    }
    val actions = ColorPaletteScreenActions(
        onBack = dropUnlessResumed { navigator.pop() },
        onSetThemeMode = viewModel::setThemeMode,
        onSetMiuixMonet = viewModel::setMiuixMonet,
        onSetKeyColor = viewModel::setKeyColor,
        onSetColorMode = viewModel::setColorMode,
        onSetColorStyle = viewModel::setColorStyle,
        onSetColorSpec = viewModel::setColorSpec,
        onSetEnableBlur = viewModel::setEnableBlur,
        onSetEnableFloatingBottomBar = viewModel::setEnableFloatingBottomBar,
        onSetEnableFloatingBottomBarBlur = viewModel::setEnableFloatingBottomBarBlur,
        onSetEnableNavigationBadge = viewModel::setEnableNavigationBadge,
        onSetEnablePredictiveBack = {
            viewModel.setEnablePredictiveBack(it)
            KernelSUApplication.setEnableOnBackInvokedCallback(context.applicationInfo, it)
            activity?.recreate()
        },
        onSetEnableSwipeDismiss = viewModel::setEnableSwipeDismiss,
        onSetPagerInterceptionMode = viewModel::setPagerInterceptionMode,
        onSetPageScale = viewModel::setPageScale,
        onSetModuleDescriptionMaxLines = viewModel::setModuleDescriptionMaxLines,
        onSetShowFullStatus = viewModel::setShowFullStatus,
        onSetHideHomeWarnings = viewModel::setHideHomeWarnings,
        onSetShowAiHomeCard = viewModel::setShowAiHomeCard,
        onOpenAppIcon = { navigator.push(Route.AppIcon) },
        onSetBackgroundAppearanceExpanded = viewModel::setBackgroundAppearanceExpanded,
        onSetBackgroundSectionExpanded = viewModel::setBackgroundSectionExpanded,
        onSetThemePackageSectionExpanded = viewModel::setThemePackageSectionExpanded,
        onSetAppearanceSectionExpanded = viewModel::setAppearanceSectionExpanded,
        onSetHomeCardSectionExpanded = viewModel::setHomeCardSectionExpanded,
        onSetColorsSectionExpanded = viewModel::setColorsSectionExpanded,
        onSetCustomHomeTitle = viewModel::setCustomHomeTitle,
        onPickCustomBackground = { ctx, uri ->
            viewModel.stagePickedBackground(ctx, uri) { path ->
                if (path != null) {
                    if (navigator.current() is Route.ColorPalette) {
                        navigator.push(Route.BackgroundCrop(path))
                    } else {
                        ImageStorage.discardStaged(path)
                    }
                }
            }
        },
        onCropCurrentBackground = { ctx ->
            viewModel.stageCurrentBackground(ctx) { path ->
                if (path != null) {
                    if (navigator.current() is Route.ColorPalette) {
                        navigator.push(Route.BackgroundCrop(path))
                    } else {
                        ImageStorage.discardStaged(path)
                    }
                }
            }
        },
        onClearCustomBackground = viewModel::clearCustomBackground,
        onPickHomeCardImage = viewModel::pickHomeCardImage,
        onClearHomeCardImage = viewModel::clearHomeCardImage,
        onSetHideHomeCardStatusText = viewModel::setHideHomeCardStatusText,
        onSetHideHomeCardDecoration = viewModel::setHideHomeCardDecoration,
        onPickHomeCardSticker = viewModel::addHomeCardSticker,
        onRemoveHomeCardSticker = viewModel::removeHomeCardSticker,
        onUpdateHomeCardStickerTransform = viewModel::updateHomeCardStickerTransform,
        onSetUseSystemWallpaper = viewModel::setUseSystemWallpaper,
        onSetExtractColorFromBackground = viewModel::setExtractColorFromBackground,
        onSetCardBackgroundAlphaPercent = viewModel::setCardBackgroundAlphaPercent,
        onSetCustomBackgroundBlurPercent = viewModel::setCustomBackgroundBlurPercent,
        onSetCustomBackgroundScrimPercent = viewModel::setCustomBackgroundScrimPercent,
        onExportTheme = viewModel::exportTheme,
        onImportTheme = viewModel::importTheme,
        onExportImages = viewModel::exportImages,
        onExportCustomBackground = viewModel::exportCustomBackground,
        onConfirmImportTheme = viewModel::confirmImportTheme,
        onDismissImportThemeDialog = viewModel::dismissImportThemeDialog,
        onSetCustomText = viewModel::setCustomText,
        onResetAllCustomTexts = viewModel::resetAllCustomTexts,
        onOpenCustomTexts = { navigator.push(Route.CustomTexts) },
        onOpenThemeStore = { navigator.push(Route.ThemeStore) },
        onResetBackgroundAppearance = viewModel::resetBackgroundAppearance,
        onClearAllAppearance = viewModel::clearAllAppearance,
    )

    ThemeImportDialog(
        show = uiState.showThemeImportDialog,
        theme = uiState.pendingImportTheme,
        onDismissRequest = viewModel::dismissImportThemeDialog,
        onConfirm = { options ->
            viewModel.confirmImportTheme(context, options)
        }
    )

    // The first frame would otherwise render the preview from placeholder defaults.
    if (state.loading) return

    when (LocalUiMode.current) {
        UiMode.Miuix -> ColorPaletteScreenMiuix(state, actions, section)
        UiMode.Material -> ColorPaletteScreenMaterial(state, actions, section)
    }
}
