package com.sukisu.ultra.ui.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class HomeCardStickerTransformTest {

    @Test
    fun legacyOffsetIsConvertedToCardHeight() {
        val transform = HomeCardStickerTransform(offsetY = -0.28f)
        assertNull(transform.offsetYPct)
        // The legacy editor stage was 360:196, so a width fraction maps to a larger height fraction.
        assertEquals(-0.5f, transform.resolvedOffsetYPct(), 0.0001f)
        assertEquals(-0.28f, transform.offsetY, 0f)
    }

    @Test
    fun heightOffsetDoesNotRewriteLegacyValue() {
        val updated = HomeCardStickerTransform(offsetY = -0.28f).withHeightOffset(0.2f)
        assertEquals(0.2f, updated.offsetYPct)
        assertEquals(-0.28f, updated.offsetY, 0f)
        assertEquals(0.2f, updated.resolvedOffsetYPct(), 0f)
    }

    @Test
    fun heightOffsetIsCoerced() {
        assertEquals(
            0.5f,
            HomeCardStickerTransform(offsetYPct = 2f).coerced().offsetYPct,
        )
        assertEquals(
            -0.5f,
            HomeCardStickerTransform(offsetYPct = -2f).coerced().offsetYPct,
        )
    }

    @Test
    fun maxSizeFitsTheCardHeight() {
        // A 360 x 88 banner: a 0.35 width fraction would be 126dp tall, so the cap is lower.
        assertEquals(0.22f, HomeCardStickerTransform().maxSizeFor(360f, 88f), 0.0001f)
        // A tall card keeps the normal maximum.
        assertEquals(HomeCardStickerTransform.SIZE_MAX, HomeCardStickerTransform().maxSizeFor(360f, 400f), 0f)
    }
}
