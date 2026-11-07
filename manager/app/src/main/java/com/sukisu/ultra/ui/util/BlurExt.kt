package com.sukisu.ultra.ui.util

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.graphics.Shape
import com.sukisu.ultra.ui.component.liquid.rememberCombinedBackdrop
import com.sukisu.ultra.ui.theme.LocalAppBackgroundBackdrop
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.LocalCardBackgroundAlpha
import com.sukisu.ultra.ui.theme.LocalEnableProgressiveBlur
import top.yukonga.miuix.kmp.basic.ScrollBehavior
import top.yukonga.miuix.kmp.blur.Backdrop
import top.yukonga.miuix.kmp.blur.BlendColorEntry
import top.yukonga.miuix.kmp.blur.BlurColors
import top.yukonga.miuix.kmp.blur.LayerBackdrop
import top.yukonga.miuix.kmp.blur.ProgressiveBlur
import top.yukonga.miuix.kmp.blur.progressiveTextureBlur
import top.yukonga.miuix.kmp.blur.rememberLayerBackdrop
import top.yukonga.miuix.kmp.blur.textureBlur
import top.yukonga.miuix.kmp.shader.isRenderEffectSupported
import top.yukonga.miuix.kmp.shader.isRuntimeShaderSupported
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** Blur radius shared by the standard bar blur and its progressive variant. */
const val BarBlurRadius: Float = 25f

/**
 * Solid-enough tint layered over the bar blur. Over a custom background the cards already use
 * [LocalCardBackgroundAlpha], so the bar follows them; without one the tint has to be strong
 * enough to keep the bar chrome readable while content scrolls underneath.
 */
const val OpaqueBarTintAlpha = 0.87f

@Composable
fun rememberBlurBackdrop(
    enableBlur: Boolean,
    allowProgressive: Boolean = true,
): LayerBackdrop? {
    // The progressive mode draws a blur band even when the plain bar blur is off, so it needs the
    // same page capture. Callers that only want the page layer for another purpose can opt out.
    val progressiveBlur = allowProgressive && LocalEnableProgressiveBlur.current &&
        isRuntimeShaderSupported()
    if (!enableBlur && !progressiveBlur) return null
    if (!isRenderEffectSupported()) return null
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val surfaceColor = MiuixTheme.colorScheme.surface
    return rememberLayerBackdrop {
        // Without a custom background the layer has to be opaque on its own. With one, the page
        // stays transparent so the wallpaper shows through, and BlurredBar adds the wallpaper
        // back underneath when it samples this layer.
        if (!hasCustomBackground) {
            drawRect(surfaceColor)
        }
        drawContent()
    }
}

/**
 * Stacks the app background under the page layer captured by [backdrop].
 *
 * Over a custom background the page layer is transparent wherever the page paints nothing, and
 * blurring those pixels bleeds black into the bar. The background image fills exactly those
 * pixels, so drawing both layers reproduces what is really on screen behind the bar.
 *
 * Returns null when only the page layer is available; [BlurredBar] then falls back to a plain
 * translucent surface instead of blurring an incomplete backdrop.
 */
@Composable
fun rememberBackdropWithAppBackground(backdrop: Backdrop?): Backdrop? {
    if (backdrop == null) return null
    val appBackground = LocalAppBackgroundBackdrop.current
    if (appBackground != null) return rememberCombinedBackdrop(appBackground, backdrop)
    // Over a custom background the page layer alone is transparent wherever nothing is drawn,
    // so leaving it out is only safe when the layer was filled with the opaque surface color.
    return backdrop.takeIf { LocalBackgroundImagePath.current.isEmpty() }
}

/**
 * Modifier that paints the progressive edge blur behind a bar.
 *
 * The blur ramps from [gradient]'s strong edge (usually the screen edge) to a fully sharp,
 * full-resolution clear end, so content fades out of blur instead of meeting the bar with a hard
 * line. Works over a custom background (the wallpaper is layered under the page capture) and
 * without one (the page layer is opaque, so only scrolling content changes).
 *
 * [shape] clips the effect, so a floating pill only blurs inside its own outline and leaves the
 * page elements around it untouched.
 */
@Composable
fun rememberProgressiveBarBlurModifier(
    backdrop: Backdrop?,
    gradient: ProgressiveBlur,
    tint: Color,
    tintAlpha: Float,
    blurRadius: Float = BarBlurRadius,
    shape: Shape = RectangleShape,
): Modifier {
    if (!isRuntimeShaderSupported()) return Modifier
    val effectiveBackdrop = rememberBackdropWithAppBackground(backdrop) ?: return Modifier
    return remember(effectiveBackdrop, gradient, tint, tintAlpha, blurRadius, shape) {
        Modifier.progressiveTextureBlur(
            backdrop = effectiveBackdrop,
            shape = shape,
            blurRadius = blurRadius,
            gradient = gradient,
            colors = BlurColors(
                blendColors = listOf(BlendColorEntry(color = tint.copy(alpha = tintAlpha))),
            ),
        )
    }
}

@Composable
fun BlurredBar(
    backdrop: LayerBackdrop?,
    modifier: Modifier = Modifier,
    scrollBehavior: ScrollBehavior? = null,
    blurActive: Boolean? = null,
    progressiveGradient: ProgressiveBlur = ProgressiveBlur.Top,
    content: @Composable () -> Unit,
) {
    val isScrolled by remember(scrollBehavior) {
        derivedStateOf {
            scrollBehavior?.state?.collapsedFraction?.let { it > 0.01f } ?: true
        }
    }
    val effectiveBlurActive = blurActive ?: (scrollBehavior == null || isScrolled)
    val progressiveBlur = LocalEnableProgressiveBlur.current && isRuntimeShaderSupported()
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val cardAlpha = LocalCardBackgroundAlpha.current
    val surfaceColor = MiuixTheme.colorScheme.surface
    val blurBackdrop = rememberBackdropWithAppBackground(backdrop)
    val tintAlpha = if (hasCustomBackground) cardAlpha else OpaqueBarTintAlpha

    val blurModifier = if (progressiveBlur) {
        // Always active: over a custom background the wallpaper edge should be frosted even before
        // the page is scrolled, and without one the flat surface keeps the band invisible at rest.
        rememberProgressiveBarBlurModifier(
            backdrop = backdrop,
            gradient = progressiveGradient,
            tint = surfaceColor,
            tintAlpha = tintAlpha,
        )
    } else if (effectiveBlurActive && blurBackdrop != null) {
        Modifier.textureBlur(
            backdrop = blurBackdrop,
            shape = RectangleShape,
            blurRadius = BarBlurRadius,
            colors = BlurColors(
                blendColors = listOf(
                    BlendColorEntry(color = surfaceColor.copy(tintAlpha)),
                ),
            ),
        )
    } else if (effectiveBlurActive && hasCustomBackground) {
        Modifier.background(surfaceColor.copy(alpha = cardAlpha))
    } else {
        Modifier
    }

    Box(
        modifier = modifier.then(blurModifier)
    ) {
        content()
    }
}
