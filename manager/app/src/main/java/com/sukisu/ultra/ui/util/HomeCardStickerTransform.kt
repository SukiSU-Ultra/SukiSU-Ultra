package com.sukisu.ultra.ui.util

import kotlinx.serialization.Serializable

/**
 * Placement of the optional sticker on the home status card.
 *
 * [offsetX] and [offsetY] are fractions of the card width, measured from the card center, so the
 * sticker keeps its relative position when the card is rendered at a different size (home,
 * preview, editor). [size] is also a fraction of the card width.
 */
@Serializable
data class HomeCardStickerTransform(
    val offsetX: Float = DEFAULT_OFFSET_X,
    val offsetY: Float = DEFAULT_OFFSET_Y,
    val rotation: Float = DEFAULT_ROTATION,
    val size: Float = DEFAULT_SIZE,
) {
    fun coerced(): HomeCardStickerTransform = copy(
        offsetX = offsetX.coerceIn(-OFFSET_LIMIT, OFFSET_LIMIT),
        offsetY = offsetY.coerceIn(-OFFSET_LIMIT, OFFSET_LIMIT),
        rotation = rotation.coerceIn(ROTATION_MIN, ROTATION_MAX),
        size = size.coerceIn(SIZE_MIN, SIZE_MAX),
    )

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
