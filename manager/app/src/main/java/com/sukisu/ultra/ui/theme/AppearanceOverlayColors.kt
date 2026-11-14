package com.sukisu.ultra.ui.theme

import androidx.compose.material3.ColorScheme
import androidx.compose.ui.graphics.Color
import com.sukisu.ultra.ui.util.AppearanceColorToken
import com.sukisu.ultra.ui.util.ResolvedColorTokens
import top.yukonga.miuix.kmp.theme.Colors

private fun ResolvedColorTokens.color(token: AppearanceColorToken): Color? =
    values[token]?.let(::Color)

/**
 * Applies the semantic overlay to the generated Miuix palette. Only provided tokens are
 * replaced, so an overlay that fixes secondary text keeps the rest of the generated scheme.
 *
 * Keep this mapping in one place: Miuix role names are library details and may move between
 * releases, while the JSON token names are part of the theme package format.
 */
fun Colors.withAppearance(tokens: ResolvedColorTokens?): Colors {
    if (tokens == null || tokens.isEmpty) return this
    val accent = tokens.color(AppearanceColorToken.ACCENT)
    val onAccent = tokens.color(AppearanceColorToken.ON_ACCENT)
    val textPrimary = tokens.color(AppearanceColorToken.TEXT_PRIMARY)
    val textSecondary = tokens.color(AppearanceColorToken.TEXT_SECONDARY)
    val textDisabled = tokens.color(AppearanceColorToken.TEXT_DISABLED)
    val surfaceColor = tokens.color(AppearanceColorToken.SURFACE)
    val card = tokens.color(AppearanceColorToken.CARD)
    val outlineColor = tokens.color(AppearanceColorToken.OUTLINE)
    val errorColor = tokens.color(AppearanceColorToken.ERROR)

    return copy(
        primary = accent ?: primary,
        primaryVariant = accent ?: primaryVariant,
        onPrimary = onAccent ?: onPrimary,
        onPrimaryVariant = onAccent ?: onPrimaryVariant,
        error = errorColor ?: error,
        onBackground = textPrimary ?: onBackground,
        onBackgroundVariant = textSecondary ?: onBackgroundVariant,
        onSurface = textPrimary ?: onSurface,
        onSurfaceSecondary = textPrimary ?: onSurfaceSecondary,
        onSurfaceContainer = textPrimary ?: onSurfaceContainer,
        onSurfaceContainerVariant = textPrimary ?: onSurfaceContainerVariant,
        onSurfaceContainerHigh = textPrimary ?: onSurfaceContainerHigh,
        onSurfaceContainerHighest = textPrimary ?: onSurfaceContainerHighest,
        onSurfaceVariantSummary = textSecondary ?: onSurfaceVariantSummary,
        onSurfaceVariantActions = textSecondary ?: onSurfaceVariantActions,
        disabledOnSurface = textDisabled ?: disabledOnSurface,
        disabledOnSecondary = textDisabled ?: disabledOnSecondary,
        disabledOnSecondaryVariant = textDisabled ?: disabledOnSecondaryVariant,
        surface = surfaceColor ?: surface,
        background = surfaceColor ?: background,
        surfaceContainer = card ?: surfaceContainer,
        surfaceContainerHigh = card ?: surfaceContainerHigh,
        surfaceContainerHighest = card ?: surfaceContainerHighest,
        outline = outlineColor ?: outline,
        dividerLine = outlineColor ?: dividerLine,
    )
}

/**
 * The Material 3 counterpart. Material has no disabled text role (components lower the alpha
 * themselves), so `textDisabled` intentionally has no Material mapping.
 */
fun ColorScheme.withAppearance(tokens: ResolvedColorTokens?): ColorScheme {
    if (tokens == null || tokens.isEmpty) return this
    val accent = tokens.color(AppearanceColorToken.ACCENT)
    val onAccent = tokens.color(AppearanceColorToken.ON_ACCENT)
    val textPrimary = tokens.color(AppearanceColorToken.TEXT_PRIMARY)
    val textSecondary = tokens.color(AppearanceColorToken.TEXT_SECONDARY)
    val surfaceColor = tokens.color(AppearanceColorToken.SURFACE)
    val card = tokens.color(AppearanceColorToken.CARD)
    val outlineColor = tokens.color(AppearanceColorToken.OUTLINE)
    val errorColor = tokens.color(AppearanceColorToken.ERROR)

    return copy(
        primary = accent ?: primary,
        onPrimary = onAccent ?: onPrimary,
        error = errorColor ?: error,
        onBackground = textPrimary ?: onBackground,
        onSurface = textPrimary ?: onSurface,
        onSurfaceVariant = textSecondary ?: onSurfaceVariant,
        surface = surfaceColor ?: surface,
        background = surfaceColor ?: background,
        surfaceContainer = card ?: surfaceContainer,
        surfaceContainerLow = card ?: surfaceContainerLow,
        surfaceContainerHigh = card ?: surfaceContainerHigh,
        surfaceContainerHighest = card ?: surfaceContainerHighest,
        outline = outlineColor ?: outline,
        outlineVariant = outlineColor ?: outlineVariant,
    )
}
