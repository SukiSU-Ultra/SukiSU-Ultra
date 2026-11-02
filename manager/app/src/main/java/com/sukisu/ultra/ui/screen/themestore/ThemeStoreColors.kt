package com.sukisu.ultra.ui.screen.themestore

import androidx.compose.material3.IconButtonColors
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.isInDarkTheme

@Composable
internal fun themeStoreCardColor(): Color {
    if (LocalBackgroundImagePath.current.isEmpty()) {
        return MaterialTheme.colorScheme.surfaceContainerLow
    }
    return if (isInDarkTheme()) {
        Color(0xFF0E1118).copy(alpha = 0.56f)
    } else {
        Color.White.copy(alpha = 0.64f)
    }
}

@Composable
internal fun themeStoreSearchColor(): Color {
    if (LocalBackgroundImagePath.current.isEmpty()) {
        return MaterialTheme.colorScheme.surfaceContainerHigh
    }
    return if (isInDarkTheme()) {
        Color(0xFF11151E).copy(alpha = 0.56f)
    } else {
        Color.White.copy(alpha = 0.60f)
    }
}

@Composable
internal fun themeStoreCardBorderColor(): Color {
    if (LocalBackgroundImagePath.current.isEmpty()) {
        return MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.12f)
    }
    return if (isInDarkTheme()) {
        Color.White.copy(alpha = 0.14f)
    } else {
        Color.White.copy(alpha = 0.70f)
    }
}

/** Same filled treatment as the top-bar back button so action icons stay readable on wallpapers. */
@Composable
internal fun themeStoreTopBarIconColors(): IconButtonColors =
    IconButtonDefaults.iconButtonColors(
        containerColor = MaterialTheme.colorScheme.surfaceContainerHighest,
        contentColor = MaterialTheme.colorScheme.onSurface,
    )
