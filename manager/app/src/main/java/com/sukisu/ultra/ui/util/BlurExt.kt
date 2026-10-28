package com.sukisu.ultra.ui.util

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.RectangleShape
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.LocalCardBackgroundAlpha
import top.yukonga.miuix.kmp.basic.ScrollBehavior
import top.yukonga.miuix.kmp.blur.BlendColorEntry
import top.yukonga.miuix.kmp.blur.BlurColors
import top.yukonga.miuix.kmp.blur.LayerBackdrop
import top.yukonga.miuix.kmp.blur.rememberLayerBackdrop
import top.yukonga.miuix.kmp.blur.textureBlur
import top.yukonga.miuix.kmp.shader.isRenderEffectSupported
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
fun rememberBlurBackdrop(enableBlur: Boolean): LayerBackdrop? {
    if (!enableBlur || !isRenderEffectSupported()) return null
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val surfaceColor = MiuixTheme.colorScheme.surface
    return rememberLayerBackdrop {
        if (!hasCustomBackground) {
            drawRect(surfaceColor)
        }
        drawContent()
    }
}

@Composable
fun BlurredBar(
    backdrop: LayerBackdrop?,
    modifier: Modifier = Modifier,
    scrollBehavior: ScrollBehavior? = null,
    blurActive: Boolean? = null,
    content: @Composable () -> Unit,
) {
    val isScrolled by remember(scrollBehavior) {
        derivedStateOf {
            scrollBehavior?.state?.collapsedFraction?.let { it > 0.01f } ?: true
        }
    }
    val effectiveBlurActive = blurActive ?: (scrollBehavior == null || isScrolled)
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val cardAlpha = LocalCardBackgroundAlpha.current
    val surfaceColor = MiuixTheme.colorScheme.surface

    val blurModifier = if (effectiveBlurActive && backdrop != null) {
        val tintAlpha = if (hasCustomBackground) cardAlpha else 0.87f
        Modifier.textureBlur(
            backdrop = backdrop,
            shape = RectangleShape,
            blurRadius = 25f,
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
