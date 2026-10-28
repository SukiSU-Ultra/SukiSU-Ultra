package com.sukisu.ultra.ui.theme

import android.app.Activity
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialExpressiveTheme
import androidx.compose.material3.MotionScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.core.view.WindowInsetsControllerCompat
import com.sukisu.ultra.ui.webui.MonetColorsProvider

@Composable
fun MaterialKernelSUTheme(
    appSettings: AppSettings,
    content: @Composable () -> Unit
) {
    val context = LocalContext.current
    val systemDarkTheme = isSystemInDarkTheme()
    val darkTheme = appSettings.colorMode.isDark || (appSettings.colorMode.isSystem && systemDarkTheme)
    val amoledMode = appSettings.colorMode.isAmoled
    val dynamicColor = appSettings.keyColor == 0

    val colorScheme = rememberKernelSUColorScheme(
        seedColor = if (dynamicColor) Color.Unspecified else Color(appSettings.keyColor),
        isDark = darkTheme,
        isAmoled = amoledMode,
        paletteStyle = appSettings.paletteStyle,
        colorSpec = appSettings.colorSpec,
    )

    LaunchedEffect(darkTheme) {
        val window = (context as? Activity)?.window ?: return@LaunchedEffect
        WindowInsetsControllerCompat(window, window.decorView).apply {
            isAppearanceLightStatusBars = !darkTheme
            isAppearanceLightNavigationBars = !darkTheme
        }
    }

    val animatedColorScheme = colorScheme.animateAsState()

    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val cardAlpha = LocalCardBackgroundAlpha.current
    // Default Card/Surface containers bypass backgroundAwareColor(), so apply the card opacity
    // to the card surface roles themselves. Menu/dialog/sheet tokens stay opaque: making them
    // translucent lets their elevation shadow show through (a dark rectangular halo behind the
    // rounded popup).
    val surfaceAwareColorScheme = remember(animatedColorScheme, hasCustomBackground, cardAlpha) {
        if (!hasCustomBackground) {
            animatedColorScheme
        } else {
            animatedColorScheme.copy(
                surfaceBright = animatedColorScheme.surfaceBright.copy(alpha = cardAlpha),
                surfaceContainerLowest = animatedColorScheme.surfaceContainerLowest.copy(alpha = cardAlpha),
                surfaceContainerHighest = animatedColorScheme.surfaceContainerHighest.copy(alpha = cardAlpha),
            )
        }
    }

    MaterialExpressiveTheme(
        colorScheme = surfaceAwareColorScheme,
        motionScheme = MotionScheme.expressive(),
        shapes = Shapes,
        typography = Typography,
        content = {
            MonetColorsProvider.UpdateCss(colorScheme)
            content()
        }
    )
}
