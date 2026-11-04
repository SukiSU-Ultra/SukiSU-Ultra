package com.sukisu.ultra.ui.component.appearance

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.AppearanceColorMode
import com.sukisu.ultra.ui.util.AppearanceColorToken
import com.sukisu.ultra.ui.util.AppearanceEffectKey

fun AppearanceColorToken.titleRes(): Int = when (this) {
    AppearanceColorToken.ACCENT -> R.string.appearance_color_accent
    AppearanceColorToken.ON_ACCENT -> R.string.appearance_color_on_accent
    AppearanceColorToken.TEXT_PRIMARY -> R.string.appearance_color_text_primary
    AppearanceColorToken.TEXT_SECONDARY -> R.string.appearance_color_text_secondary
    AppearanceColorToken.TEXT_DISABLED -> R.string.appearance_color_text_disabled
    AppearanceColorToken.SURFACE -> R.string.appearance_color_surface
    AppearanceColorToken.CARD -> R.string.appearance_color_card
    AppearanceColorToken.OUTLINE -> R.string.appearance_color_outline
    AppearanceColorToken.ERROR -> R.string.appearance_color_error
}

fun AppearanceColorMode.titleRes(): Int = when (this) {
    AppearanceColorMode.SHARED -> R.string.appearance_mode_shared
    AppearanceColorMode.LIGHT -> R.string.appearance_mode_light
    AppearanceColorMode.DARK -> R.string.appearance_mode_dark
}

fun AppearanceEffectKey.titleRes(): Int = when (this) {
    AppearanceEffectKey.SHARPEN -> R.string.appearance_effect_sharpen
    AppearanceEffectKey.SATURATION -> R.string.appearance_effect_saturation
    AppearanceEffectKey.CONTRAST -> R.string.appearance_effect_contrast
    AppearanceEffectKey.BRIGHTNESS -> R.string.appearance_effect_brightness
}

/** Filled circle for an override; a slashed outline when the token follows the theme. */
@Composable
fun OverlayColorSwatch(
    color: Color?,
    outlineColor: Color,
    emptyColor: Color,
    modifier: Modifier = Modifier,
    size: Dp = 26.dp,
) {
    Canvas(modifier = modifier.size(size)) {
        val radius = this.size.minDimension / 2f - 1.dp.toPx()
        if (color == null) {
            drawCircle(color = emptyColor, radius = radius)
            drawCircle(
                color = outlineColor,
                radius = radius,
                style = Stroke(width = 1.dp.toPx()),
            )
            drawLine(
                color = outlineColor,
                start = Offset(radius * 0.35f, radius * 0.35f),
                end = Offset(this.size.width - radius * 0.35f, this.size.height - radius * 0.35f),
                strokeWidth = 1.dp.toPx(),
            )
        } else {
            drawCircle(color = color, radius = radius)
            drawCircle(
                color = outlineColor,
                radius = radius,
                style = Stroke(width = 1.dp.toPx()),
            )
        }
    }
}
