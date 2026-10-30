package com.sukisu.ultra.ui.screen.colorpalette

import androidx.activity.compose.LocalActivity
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.dropUnlessResumed
import androidx.lifecycle.viewmodel.compose.viewModel
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.sukisu.ultra.KernelSUApplication
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.navigation3.Route
import com.sukisu.ultra.ui.theme.ColorMode
import com.sukisu.ultra.ui.util.BgStorage
import com.sukisu.ultra.ui.viewmodel.SettingsViewModel
import com.sukisu.ultra.ui.component.themeimport.ThemeImportDialog

@Composable
fun ColorPaletteScreen() {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val activity = LocalActivity.current
    val viewModel = viewModel<SettingsViewModel>()
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        viewModel.refreshBackgroundAppearance()
    }
    val currentPaletteStyle = try {
        PaletteStyle.valueOf(uiState.colorStyle)
    } catch (_: Exception) {
        PaletteStyle.TonalSpot
    }
    val currentColorSpec = try {
        ColorSpec.SpecVersion.valueOf(uiState.colorSpec)
    } catch (_: Exception) {
        ColorSpec.SpecVersion.SPEC_2025
    }
    val state = ColorPaletteUiState(
        uiState = uiState,
        currentColorMode = ColorMode.fromValue(uiState.themeMode),
        currentPaletteStyle = currentPaletteStyle,
        currentColorSpec = currentColorSpec,
        showFullStatus = uiState.showFullStatus,
        hideHomeWarnings = uiState.hideHomeWarnings,
    )
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
        onOpenAppIcon = { navigator.push(Route.AppIcon) },
        onSetBackgroundAppearanceExpanded = viewModel::setBackgroundAppearanceExpanded,
        onSetCustomHomeTitle = viewModel::setCustomHomeTitle,
        onPickCustomBackground = { ctx, uri ->
            viewModel.stagePickedBackground(ctx, uri) { path ->
                if (path != null) {
                    if (navigator.current() == Route.ColorPalette) {
                        navigator.push(Route.BackgroundCrop(path))
                    } else {
                        BgStorage.discardStaged(path)
                    }
                }
            }
        },
        onCropCurrentBackground = { ctx ->
            viewModel.stageCurrentBackground(ctx) { path ->
                if (path != null) {
                    if (navigator.current() == Route.ColorPalette) {
                        navigator.push(Route.BackgroundCrop(path))
                    } else {
                        BgStorage.discardStaged(path)
                    }
                }
            }
        },
        onClearCustomBackground = viewModel::clearCustomBackground,
        onSetUseSystemWallpaper = viewModel::setUseSystemWallpaper,
        onSetExtractColorFromBackground = viewModel::setExtractColorFromBackground,
        onSetCardBackgroundAlphaPercent = viewModel::setCardBackgroundAlphaPercent,
        onSetCustomBackgroundBlurPercent = viewModel::setCustomBackgroundBlurPercent,
        onSetCustomBackgroundScrimPercent = viewModel::setCustomBackgroundScrimPercent,
        onExportTheme = viewModel::exportTheme,
        onImportTheme = viewModel::importTheme,
        onExportCustomBackground = viewModel::exportCustomBackground,
        onConfirmImportTheme = viewModel::confirmImportTheme,
        onDismissImportThemeDialog = viewModel::dismissImportThemeDialog,
        onSetCustomText = viewModel::setCustomText,
        onResetAllCustomTexts = viewModel::resetAllCustomTexts,
        onOpenCustomTexts = { navigator.push(Route.CustomTexts) },
        onResetBackgroundAppearance = viewModel::resetBackgroundAppearance,
    )

    ThemeImportDialog(
        show = uiState.showThemeImportDialog,
        theme = uiState.pendingImportTheme,
        onDismissRequest = viewModel::dismissImportThemeDialog,
        onConfirm = { options ->
            viewModel.confirmImportTheme(context, options)
        }
    )

    when (LocalUiMode.current) {
        UiMode.Miuix -> ColorPaletteScreenMiuix(state, actions)
        UiMode.Material -> ColorPaletteScreenMaterial(state, actions)
    }
}
