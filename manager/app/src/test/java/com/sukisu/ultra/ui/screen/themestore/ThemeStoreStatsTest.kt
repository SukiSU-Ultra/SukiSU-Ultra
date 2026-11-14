package com.sukisu.ultra.ui.screen.themestore

import org.junit.Assert.assertEquals
import org.junit.Test

class ThemeStoreStatsTest {
    @Test
    fun formatsCompactCounters() {
        assertEquals("0", formatStoreCount(0))
        assertEquals("999", formatStoreCount(999))
        assertEquals("1.0k", formatStoreCount(1_000))
        assertEquals("1.2k", formatStoreCount(1_240))
        assertEquals("12k", formatStoreCount(12_345))
        assertEquals("1.0M", formatStoreCount(999_500))
        assertEquals("1.5M", formatStoreCount(1_500_000))
    }
}
