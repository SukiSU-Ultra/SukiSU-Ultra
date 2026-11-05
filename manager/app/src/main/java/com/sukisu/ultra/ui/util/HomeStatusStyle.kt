package com.sukisu.ultra.ui.util

import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * The home page status card layout. [CLASSIC] is the original full-width card; [IMMERSIVE] is the
 * compact pill with an optional image window or banner.
 */
enum class HomeLayout(val value: String) {
    CLASSIC("classic"),
    IMMERSIVE("immersive"),
    ;

    companion object {
        fun fromValue(value: String?): HomeLayout =
            entries.firstOrNull { it.value == value } ?: CLASSIC
    }
}

/** How the immersive layout presents the optional status card image. */
enum class HomeCardImageStyle(val value: String) {
    /** A full-width image card below the status pill. */
    BANNER("banner"),

    /** No image; the status area is just the pill. */
    OFF("off"),
    ;

    companion object {
        fun fromValue(value: String?): HomeCardImageStyle = when (value) {
            OFF.value -> OFF
            // Legacy packages/settings used "window"; keep them on the banner instead.
            else -> BANNER
        }
    }
}

/** Horizontal placement of the immersive status area and its pill. */
enum class HomeStatusAlignment(val value: String) {
    START("start"),
    END("end"),
    ;

    companion object {
        fun fromValue(value: String?): HomeStatusAlignment =
            if (value == END.value) END else START
    }
}

/**
 * Single source of truth for the immersive status area's base geometry.
 *
 * The status-area height and width only size the image banner; the pill has its own scale so the
 * working-status chip stays independent from the image card. Keeping the constants in one place
 * keeps the home screen, the theme preview and the sticker editor aligned.
 */
object HomeStatusStyle {
    const val SCALE_MIN = 0.5f
    const val SCALE_MAX = 3f
    const val SCALE_DEFAULT = 1f

    /** Width of the image banner relative to the page content width. */
    const val WIDTH_MIN = 0.45f
    const val WIDTH_MAX = 1f
    const val WIDTH_DEFAULT = 1f

    /** Independent scale for the working-status pill. */
    const val PILL_SCALE_MIN = 0.5f
    const val PILL_SCALE_MAX = 1.5f
    const val PILL_SCALE_DEFAULT = 1f

    val PillMinHeight = 46.dp
    val PillHorizontalPadding = 15.dp
    val PillContentGap = 9.dp
    val PillTouchTarget = 48.dp
    val DotSize = 8.dp
    val DividerWidth = 1.dp
    val DividerHeight = 16.dp
    const val LabelSizeSp = 15f
    const val MetaSizeSp = 11.5f

    val BannerHeight = 88.dp
    val BannerCorner = 20.dp
    val ClusterGap = 10.dp

    /** Clamps a persisted/imported status-area height scale. */
    fun coerceScale(value: Float): Float = value.coerceIn(SCALE_MIN, SCALE_MAX)

    /** Clamps the image banner width fraction to the supported range. */
    fun coerceWidth(value: Float): Float = value.coerceIn(WIDTH_MIN, WIDTH_MAX)

    /** Clamps the independent pill scale. */
    fun coercePillScale(value: Float): Float =
        value.coerceIn(PILL_SCALE_MIN, PILL_SCALE_MAX)

    /** Height scale for the image banner. */
    fun scaledDp(base: Dp, scale: Float): Dp = base * coerceScale(scale)

    /** Pill dimensions use their own scale and never follow the image card. */
    fun pillDp(base: Dp, pillScale: Float): Dp = base * coercePillScale(pillScale)

    fun pillSp(base: Float, pillScale: Float): TextUnit =
        (base * coercePillScale(pillScale)).sp
}

/**
 * The card image is part of the background-first layout: without a custom background it is
 * hidden by default, unless the user explicitly opts in.
 */
fun shouldShowHomeCardImage(
    path: String,
    hasCustomBackground: Boolean,
    showWithoutBackground: Boolean,
): Boolean = path.isNotEmpty() && (hasCustomBackground || showWithoutBackground)
