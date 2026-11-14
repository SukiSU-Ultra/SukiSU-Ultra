package com.sukisu.ultra.ui.util

import kotlinx.serialization.Serializable
import kotlin.math.min

/**
 * Placement of the optional sticker on the home status card.
 *
 * [offsetX] and [size] are fractions of the card width. [offsetY] is the legacy vertical offset,
 * also a fraction of the card width, measured from the card center; it is kept so older managers
 * and the classic layout can render the sticker unchanged.
 *
 * [offsetYPct], when present, is the vertical offset as a fraction of the card **height**, from the
 * center. The immersive banner uses this field so the sticker keeps its relative position when the
 * card height changes. Null means "convert from [offsetY] using the legacy editor ratio".
 */
@Serializable
data class HomeCardStickerTransform(
    val offsetX: Float = DEFAULT_OFFSET_X,
    val offsetY: Float = DEFAULT_OFFSET_Y,
    val rotation: Float = DEFAULT_ROTATION,
    val size: Float = DEFAULT_SIZE,
    val offsetYPct: Float? = null,
) {
    fun coerced(): HomeCardStickerTransform = copy(
        offsetX = offsetX.coerceIn(-OFFSET_LIMIT, OFFSET_LIMIT),
        offsetY = offsetY.coerceIn(-OFFSET_LIMIT, OFFSET_LIMIT),
        rotation = rotation.coerceIn(ROTATION_MIN, ROTATION_MAX),
        size = size.coerceIn(SIZE_MIN, SIZE_MAX),
        offsetYPct = offsetYPct?.coerceIn(-OFFSET_LIMIT, OFFSET_LIMIT),
    )

    /** The vertical offset in card-height units, converting the legacy value when necessary. */
    fun resolvedOffsetYPct(): Float = (offsetYPct ?: (offsetY / LEGACY_EDITOR_HEIGHT_RATIO))
        .coerceIn(-OFFSET_LIMIT, OFFSET_LIMIT)

    /** Sets only the height-normalized offset, leaving [offsetY] for classic/older renderers. */
    fun withHeightOffset(pct: Float): HomeCardStickerTransform =
        copy(offsetYPct = pct.coerceIn(-OFFSET_LIMIT, OFFSET_LIMIT))

    /**
     * Largest width-fraction size that still fits the card height with a small margin. Used by the
     * immersive banner editor and renderer so a sticker cannot become taller than its card.
     */
    fun maxSizeFor(cardWidth: Float, cardHeight: Float): Float {
        if (cardWidth <= 0f || cardHeight <= 0f) return SIZE_MAX
        return min(SIZE_MAX, 0.9f * cardHeight / cardWidth)
    }

    companion object {
        const val DEFAULT_OFFSET_X = 0.30f
        const val DEFAULT_OFFSET_Y = -0.28f
        const val DEFAULT_ROTATION = -8f
        const val DEFAULT_SIZE = 0.20f

        const val OFFSET_LIMIT = 0.5f
        const val ROTATION_MIN = -180f
        const val ROTATION_MAX = 180f
        const val SIZE_MIN = 0.12f
        const val SIZE_MAX = 0.35f

        /** The classic sticker editor stage was 360:196; used to migrate legacy Y offsets. */
        const val LEGACY_EDITOR_HEIGHT_RATIO = 196f / 360f
    }
}


@Serializable
data class HomeCardSticker(
    val path: String,
    val transform: HomeCardStickerTransform = HomeCardStickerTransform(),
) {
    companion object {
        const val MAX_COUNT = 5
    }
}
