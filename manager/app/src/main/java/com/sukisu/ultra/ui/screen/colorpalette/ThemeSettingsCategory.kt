package com.sukisu.ultra.ui.screen.colorpalette

import androidx.annotation.StringRes
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CallToAction
import androidx.compose.material.icons.rounded.Colorize
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.Home
import androidx.compose.material.icons.rounded.Palette
import androidx.compose.material.icons.rounded.Swipe
import androidx.compose.material.icons.rounded.Wallpaper
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R

/**
 * The categories the appearance page is split into.
 *
 * Only one category's settings are composed at a time; the category box above the content area
 * switches between them instead of stacking every section in one long list.
 */
enum class ThemeSettingsCategory(
    @StringRes val labelRes: Int,
    @StringRes val titleRes: Int,
    @StringRes val summaryRes: Int,
    val icon: ImageVector,
) {
    COLORS(
        labelRes = R.string.theme_category_colors,
        titleRes = R.string.settings_section_colors,
        summaryRes = R.string.settings_section_colors_summary,
        icon = Icons.Rounded.Colorize,
    ),
    BACKGROUND(
        labelRes = R.string.theme_category_background,
        titleRes = R.string.settings_section_background,
        summaryRes = R.string.settings_section_background_summary,
        icon = Icons.Rounded.Wallpaper,
    ),
    ICON_TEXT(
        labelRes = R.string.theme_category_icon_text,
        titleRes = R.string.settings_section_icon_text,
        summaryRes = R.string.settings_section_icon_text_summary,
        icon = Icons.Rounded.Edit,
    ),
    HOME_CARD(
        labelRes = R.string.theme_category_home_card,
        titleRes = R.string.settings_section_home_card,
        summaryRes = R.string.settings_section_home_card_summary,
        icon = Icons.Rounded.Home,
    ),
    BOTTOM_BAR(
        labelRes = R.string.theme_category_bottom_bar,
        titleRes = R.string.settings_section_bottom_bar,
        summaryRes = R.string.settings_section_bottom_bar_summary,
        icon = Icons.Rounded.CallToAction,
    ),
    INTERACTION(
        labelRes = R.string.theme_category_interaction,
        titleRes = R.string.settings_section_interaction,
        summaryRes = R.string.settings_section_interaction_summary,
        icon = Icons.Rounded.Swipe,
    ),
    DETAILS(
        labelRes = R.string.theme_category_details,
        titleRes = R.string.settings_section_details,
        summaryRes = R.string.settings_section_details_summary,
        icon = Icons.Rounded.Description,
    ),
    THEME_PACKAGE(
        labelRes = R.string.theme_category_theme_package,
        titleRes = R.string.settings_section_theme_package,
        summaryRes = R.string.settings_section_theme_package_summary,
        icon = Icons.Rounded.Palette,
    );

    companion object {
        /** Maps the legacy `section` route argument (used by the AI bridge) to a category. */
        fun fromSection(section: String?): ThemeSettingsCategory? {
            val id = section
                ?.trim()
                ?.lowercase()
                ?.replace('-', '_')
                ?.takeIf { it.isNotEmpty() }
                ?: return null
            return when (id) {
                "preview" -> null
                "colors", "color_mode", "theme_mode", "palette" -> COLORS
                "background", "wallpaper" -> BACKGROUND
                "appearance", "icon_text", "icon", "text", "custom_texts" -> ICON_TEXT
                "home", "home_card", "sticker" -> HOME_CARD
                "bottom_bar", "chrome", "navigation", "navbar" -> BOTTOM_BAR
                "behavior", "gestures", "predictive_back", "scale", "interaction" -> INTERACTION
                "details", "module_description" -> DETAILS
                "theme_package", "theme_store", "adaptive" -> THEME_PACKAGE
                else -> null
            }
        }
    }
}

/** A row of theme color dots used by the pinned compact preview. */
@Composable
internal fun ThemePaletteSwatches(
    colors: List<Color>,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        colors.forEach { color ->
            Box(
                modifier = Modifier
                    .size(18.dp)
                    .clip(CircleShape)
                    .background(color),
            )
        }
    }
}
