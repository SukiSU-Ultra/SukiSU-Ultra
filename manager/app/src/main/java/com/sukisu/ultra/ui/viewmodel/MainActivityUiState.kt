package com.sukisu.ultra.ui.viewmodel

import androidx.compose.runtime.Immutable
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.theme.AppSettings

@Immutable
data class MainActivityUiState(
    val appSettings: AppSettings,
    val pageScale: Float,
    val enableBlur: Boolean,
    val enableFloatingBottomBar: Boolean,
    val enableFloatingBottomBarBlur: Boolean,
    val enableSmoothCorner: Boolean,
    val uiMode: UiMode,
)
