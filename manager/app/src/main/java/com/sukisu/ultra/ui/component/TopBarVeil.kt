package com.sukisu.ultra.ui.component

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.LocalCardBackgroundAlpha
import com.sukisu.ultra.ui.theme.LocalEnableProgressiveBlur
import com.sukisu.ultra.ui.util.OpaqueBarTintAlpha
import com.sukisu.ultra.ui.util.rememberProgressiveBarBlurModifier
import top.yukonga.miuix.kmp.blur.Backdrop
import top.yukonga.miuix.kmp.blur.ProgressiveBlur
import top.yukonga.miuix.kmp.shader.isRuntimeShaderSupported

/**
 * The backdrop treatment behind a transparent top bar.
 *
 * With [LocalEnableProgressiveBlur] on, the bar draws a progressive blur band that is strongest
 * at the screen edge. [blurBackdrop] is the page capture supplied by the Material scaffold; the
 * Miuix shell passes nothing because its top bar already draws the band inside `BlurredBar`.
 *
 * Otherwise this is a soft scrim while a custom background is active. It keeps the bar and its
 * icons readable without hiding the background image, and it works the same way in both shells.
 */
@Composable
fun TopBarVeil(
    color: Color,
    blurBackdrop: Backdrop? = null,
    content: @Composable () -> Unit,
) {
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val progressiveBlur = LocalEnableProgressiveBlur.current && isRuntimeShaderSupported()
    // Keep a single Box across modes so enabling the setting does not recreate the top bar's
    // composition (and its scroll state) while the switch is being flipped.
    val modifier = when {
        progressiveBlur && blurBackdrop != null -> rememberProgressiveBarBlurModifier(
            backdrop = blurBackdrop,
            gradient = ProgressiveBlur.Top,
            tint = color,
            tintAlpha = if (hasCustomBackground) {
                LocalCardBackgroundAlpha.current
            } else {
                OpaqueBarTintAlpha
            },
        )

        progressiveBlur -> Modifier

        hasCustomBackground -> Modifier
            .fillMaxWidth()
            .background(
                Brush.verticalGradient(
                    0f to color.copy(alpha = 0.28f),
                    0.65f to color.copy(alpha = 0.12f),
                    1f to color.copy(alpha = 0f),
                )
            )

        else -> Modifier
    }
    Box(modifier = modifier) {
        content()
    }
}
