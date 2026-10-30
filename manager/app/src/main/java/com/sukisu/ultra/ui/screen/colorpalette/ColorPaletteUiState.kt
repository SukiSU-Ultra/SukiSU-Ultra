package com.sukisu.ultra.ui.screen.colorpalette

import androidx.compose.runtime.Immutable
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.sukisu.ultra.ui.screen.settings.SettingsUiState
import com.sukisu.ultra.ui.theme.ColorMode

@Immutable
data class ColorPaletteUiState(
    val uiState: SettingsUiState,
    val currentColorMode: ColorMode,
    val currentPaletteStyle: PaletteStyle,
    val currentColorSpec: ColorSpec.SpecVersion,
    val showFullStatus: Boolean,
    val hideHomeWarnings: Boolean,
)

@Immutable
data class ColorPaletteScreenActions(
    val onBack: () -> Unit,
    val onSetThemeMode: (Int) -> Unit,
    val onSetMiuixMonet: (Boolean) -> Unit,
    val onSetKeyColor: (Int) -> Unit,
    val onSetColorMode: (ColorMode) -> Unit,
    val onSetColorStyle: (String) -> Unit,
    val onSetColorSpec: (String) -> Unit,
    val onSetEnableBlur: (Boolean) -> Unit,
    val onSetEnableFloatingBottomBar: (Boolean) -> Unit,
    val onSetEnableFloatingBottomBarBlur: (Boolean) -> Unit,
    val onSetEnableNavigationBadge: (Boolean) -> Unit,
    val onSetEnablePredictiveBack: (Boolean) -> Unit,
    val onSetEnableSwipeDismiss: (Boolean) -> Unit,
    val onSetPagerInterceptionMode: (Int) -> Unit,
    val onSetPageScale: (Float) -> Unit,
    val onSetModuleDescriptionMaxLines: (Int) -> Unit,
    val onSetShowFullStatus: (Boolean) -> Unit,
    val onSetHideHomeWarnings: (Boolean) -> Unit,
    val onOpenAppIcon: () -> Unit,
    val onSetBackgroundAppearanceExpanded: (Boolean) -> Unit = {},
    val onSetCustomHomeTitle: (String) -> Unit = {},
    val onSetCustomWorkingTitle: (String) -> Unit = {},
    val onSetCustomKernelModeSuffix: (String) -> Unit = {},
    val onPickHomeCardImage: (android.content.Context, android.net.Uri) -> Unit = { _, _ -> },
    val onClearHomeCardImage: () -> Unit = {},
    val onPickCustomBackground: (android.content.Context, android.net.Uri) -> Unit = { _, _ -> },
    val onCropCurrentBackground: (android.content.Context) -> Unit = {},
    val onClearCustomBackground: (android.content.Context) -> Unit = {},
    val onSetUseSystemWallpaper: (android.content.Context, Boolean) -> Unit = { _, _ -> },
    val onSetExtractColorFromBackground: (Boolean) -> Unit = {},
    val onSetCardBackgroundAlphaPercent: (Int) -> Unit = {},
    val onSetCustomBackgroundBlurPercent: (Int) -> Unit = {},
    val onSetCustomBackgroundScrimPercent: (Int) -> Unit = {},
    val onExportTheme: (android.content.Context, android.net.Uri) -> Unit = { _, _ -> },
    val onImportTheme: (android.content.Context, android.net.Uri) -> Unit = { _, _ -> },
    val onResetBackgroundAppearance: () -> Unit = {},
)
