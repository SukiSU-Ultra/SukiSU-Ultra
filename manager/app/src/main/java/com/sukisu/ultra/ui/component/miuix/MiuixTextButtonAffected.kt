package com.sukisu.ultra.ui.component.miuix

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.TextAutoSize
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sukisu.ultra.ui.theme.LocalCardBackgroundAlpha
import com.sukisu.ultra.ui.theme.backgroundAwareColor
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * Inline action text for Miuix list rows that follows the current key color.
 *
 * Miuix's default [TextButton] fills with `secondaryVariant`, which is usually a neutral
 * light/dark surface, so an inline row action reads as a stray box and does not pick up the
 * palette. On top of a custom background that fill is not translucent either, so it ignores
 * the card alpha. This keeps the tap target of [TextButton] but draws a primary pill that
 * follows the key color and the card alpha.
 *
 * The label needs care on two fronts:
 * - Contrast: `primary` is the middle tone of the palette, so a tint of it behind `primary`
 *   text sits barely one step away from the card. The label is therefore `onPrimary` on a
 *   `primary` pill, which keeps the usual filled-button contrast even when the card alpha is
 *   low or the scrim pushes the wallpaper bright or dark.
 * - Width: it follows the page scale (the screen rescales `LocalDensity.density`, `fontScale`
 *   stays untouched), so at large scales a fixed label plus the row title can overflow. It
 *   shrinks instead of truncating, with a floor above MIUI's smallest legal text size.
 */
@Composable
fun MiuixTextButtonAffectedByBackground(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val colors = MiuixTheme.colorScheme
    val cardAlpha = LocalCardBackgroundAlpha.current
    val shape = remember { RoundedCornerShape(percent = 50) }
    val pillColor = backgroundAwareColor(colors.primary, cardAlpha)
    // The surface of the pill, text and click all live in one node so the tap target covers
    // the padded label while the tint is clipped to the pill shape.
    Box(
        modifier = modifier
            .minimumInteractiveComponentSize()
            .clip(shape)
            .background(pillColor, shape)
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 6.dp),
    ) {
        Text(
            text = text,
            style = MiuixTheme.textStyles.button,
            color = colors.onPrimary,
            maxLines = 1,
            softWrap = false,
            autoSize = TextAutoSize.StepBased(
                minFontSize = 12.sp,
                maxFontSize = MiuixTheme.textStyles.button.fontSize,
            ),
        )
    }
}