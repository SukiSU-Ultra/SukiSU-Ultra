package com.sukisu.nova.ui.component.appearance

import com.sukisu.nova.R
import com.sukisu.nova.ui.util.AppearanceColorsData
import com.sukisu.nova.ui.util.AppearanceOverlayData
import com.sukisu.nova.ui.util.ColorTokensData

internal data class OverlayPreset(
    val titleRes: Int,
    val data: AppearanceOverlayData,
)

/** Static presets. They only describe colours; the screen preserves the current image effects. */
internal val OverlayPresets = listOf(
    OverlayPreset(
        R.string.appearance_overlay_preset_dark_background,
        AppearanceOverlayData(
            colors = AppearanceColorsData(
                shared = ColorTokensData(
                    textPrimary = "#FFFFFFFF",
                    textSecondary = "#E6FFFFFF",
                    textDisabled = "#80FFFFFF",
                ),
            ),
        ),
    ),
    OverlayPreset(
        R.string.appearance_overlay_preset_light_background,
        AppearanceOverlayData(
            colors = AppearanceColorsData(
                shared = ColorTokensData(
                    textPrimary = "#FF111111",
                    textSecondary = "#FF333333",
                    textDisabled = "#66111111",
                ),
            ),
        ),
    ),
    OverlayPreset(
        R.string.appearance_overlay_preset_secondary,
        AppearanceOverlayData(
            colors = AppearanceColorsData(
                light = ColorTokensData(
                    textPrimary = "#FF111111",
                    textSecondary = "#FF333333",
                    textDisabled = "#66111111",
                ),
                dark = ColorTokensData(
                    textPrimary = "#FFF5F5F5",
                    textSecondary = "#FFE0E0E0",
                    textDisabled = "#66F5F5F5",
                ),
            ),
        ),
    ),
)
