package com.sukisu.ultra.ui.screen.colorpalette

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.theme.AppSettings
import com.sukisu.ultra.ui.theme.ColorMode
import com.sukisu.ultra.ui.theme.KernelSUTheme

/**
 * Design-time previews for [ThemePreviewMiuix] and [ThemePreviewMaterial].
 *
 * They only exist so the previews can be rendered without a device (for example with
 * `android preview render`); the runtime screens build the same composables from live settings.
 */

private val SampleKeyColor = 0xFF6750A4.toInt()

@Preview(name = "Theme preview - Miuix light", widthDp = 412, heightDp = 915, showBackground = true)
@Composable
private fun ThemePreviewMiuixLight() {
    ThemePreviewSample(uiMode = UiMode.Miuix, isDark = false) {
        ThemePreviewMiuix(
            spec = ThemePreviewSpec(
                keyColor = SampleKeyColor,
                isDark = false,
                miuixMonet = true,
                paletteStyle = PaletteStyle.TonalSpot,
                colorSpec = ColorSpec.SpecVersion.SPEC_2025,
                navigationBadge = true,
            ),
            modifier = Modifier.padding(horizontal = 12.dp),
        )
    }
}

@Preview(name = "Theme preview - Miuix dark floating", widthDp = 412, heightDp = 915, showBackground = true)
@Composable
private fun ThemePreviewMiuixDark() {
    ThemePreviewSample(uiMode = UiMode.Miuix, isDark = true) {
        ThemePreviewMiuix(
            spec = ThemePreviewSpec(
                keyColor = SampleKeyColor,
                isDark = true,
                miuixMonet = true,
                paletteStyle = PaletteStyle.Expressive,
                colorSpec = ColorSpec.SpecVersion.SPEC_2025,
                floatingBottomBar = true,
                floatingBottomBarBlur = true,
                navigationBadge = true,
            ),
            modifier = Modifier.padding(horizontal = 12.dp),
        )
    }
}

@Preview(name = "Theme preview - MD3E light", widthDp = 412, heightDp = 915, showBackground = true)
@Composable
private fun ThemePreviewMaterialLight() {
    ThemePreviewSample(uiMode = UiMode.Material, isDark = false) {
        ThemePreviewMaterial(
            spec = ThemePreviewSpec(
                keyColor = SampleKeyColor,
                isDark = false,
                paletteStyle = PaletteStyle.TonalSpot,
                colorSpec = ColorSpec.SpecVersion.SPEC_2025,
                floatingBottomBar = true,
                navigationBadge = true,
            ),
        )
    }
}

@Preview(name = "Theme preview - MD3E dark", widthDp = 412, heightDp = 915, showBackground = true)
@Composable
private fun ThemePreviewMaterialDark() {
    ThemePreviewSample(uiMode = UiMode.Material, isDark = true) {
        ThemePreviewMaterial(
            spec = ThemePreviewSpec(
                keyColor = SampleKeyColor,
                isDark = true,
                paletteStyle = PaletteStyle.Vibrant,
                colorSpec = ColorSpec.SpecVersion.SPEC_2025,
                floatingBottomBar = true,
                navigationBadge = true,
            ),
        )
    }
}

@Composable
private fun ThemePreviewSample(
    uiMode: UiMode,
    isDark: Boolean,
    content: @Composable () -> Unit,
) {
    KernelSUTheme(
        appSettings = AppSettings(
            colorMode = if (isDark) ColorMode.DARK else ColorMode.LIGHT,
            keyColor = SampleKeyColor,
            paletteStyle = PaletteStyle.TonalSpot,
            colorSpec = ColorSpec.SpecVersion.SPEC_2025,
        ),
        uiMode = uiMode,
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(if (isDark) Color(0xFF1C1B1F) else Color(0xFFE7E0EC))
                .padding(top = 20.dp)
        ) {
            content()
        }
    }
}
