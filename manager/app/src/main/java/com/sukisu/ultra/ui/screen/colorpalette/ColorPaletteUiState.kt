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
    val onSetEnablePredictiveBack: (Boolean) -> Unit,
    val onSetEnableSmoothCorner: (Boolean) -> Unit,
    val onSetPageScale: (Float) -> Unit,
)
