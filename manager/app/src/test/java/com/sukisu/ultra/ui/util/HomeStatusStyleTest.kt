package com.sukisu.ultra.ui.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HomeStatusStyleTest {

    @Test
    fun layoutParsingFallsBackToClassic() {
        assertEquals(HomeLayout.IMMERSIVE, HomeLayout.fromValue("immersive"))
        assertEquals(HomeLayout.CLASSIC, HomeLayout.fromValue("classic"))
        assertEquals(HomeLayout.CLASSIC, HomeLayout.fromValue(null))
        assertEquals(HomeLayout.CLASSIC, HomeLayout.fromValue("unknown"))
    }

    @Test
    fun imageStyleParsingFallsBackToBanner() {
        assertEquals(HomeCardImageStyle.BANNER, HomeCardImageStyle.fromValue("banner"))
        assertEquals(HomeCardImageStyle.OFF, HomeCardImageStyle.fromValue("off"))
        assertEquals(HomeCardImageStyle.BANNER, HomeCardImageStyle.fromValue(null))
        assertEquals(HomeCardImageStyle.BANNER, HomeCardImageStyle.fromValue("unknown"))
        // Legacy "window" settings/packages now use the banner.
        assertEquals(HomeCardImageStyle.BANNER, HomeCardImageStyle.fromValue("window"))
    }

    @Test
    fun alignmentParsingFallsBackToStart() {
        assertEquals(HomeStatusAlignment.END, HomeStatusAlignment.fromValue("end"))
        assertEquals(HomeStatusAlignment.START, HomeStatusAlignment.fromValue("start"))
        assertEquals(HomeStatusAlignment.START, HomeStatusAlignment.fromValue(null))
        assertEquals(HomeStatusAlignment.START, HomeStatusAlignment.fromValue("unknown"))
    }

    @Test
    fun scaleIsClampedToSupportedRange() {
        assertEquals(HomeStatusStyle.SCALE_MIN, HomeStatusStyle.coerceScale(0.1f), 0f)
        assertEquals(HomeStatusStyle.SCALE_MAX, HomeStatusStyle.coerceScale(9f), 0f)
        assertEquals(2.5f, HomeStatusStyle.coerceScale(2.5f), 0f)
    }

    @Test
    fun pillScaleIsClampedSeparately() {
        assertEquals(HomeStatusStyle.PILL_SCALE_MIN, HomeStatusStyle.coercePillScale(0.1f), 0f)
        assertEquals(HomeStatusStyle.PILL_SCALE_MAX, HomeStatusStyle.coercePillScale(9f), 0f)
        assertEquals(1.2f, HomeStatusStyle.coercePillScale(1.2f), 0f)
    }

    @Test
    fun widthIsClampedToSupportedRange() {
        assertEquals(HomeStatusStyle.WIDTH_MIN, HomeStatusStyle.coerceWidth(0.1f), 0f)
        assertEquals(HomeStatusStyle.WIDTH_MAX, HomeStatusStyle.coerceWidth(2f), 0f)
        assertEquals(0.8f, HomeStatusStyle.coerceWidth(0.8f), 0f)
    }

    @Test
    fun imageVisibilityRequiresPathAndBackgroundOrOptIn() {
        assertTrue(shouldShowHomeCardImage("path", hasCustomBackground = true, showWithoutBackground = false))
        assertTrue(shouldShowHomeCardImage("path", hasCustomBackground = false, showWithoutBackground = true))
        assertFalse(shouldShowHomeCardImage("path", hasCustomBackground = false, showWithoutBackground = false))
        assertFalse(shouldShowHomeCardImage("", hasCustomBackground = true, showWithoutBackground = true))
    }
}
