package com.sukisu.ultra.ui.util

import org.junit.Assert.assertEquals
import org.junit.Test

class ModuleTimeTest {

    @Test
    fun `utc timestamp maps to epoch millis`() {
        assertEquals(1768465391000L, isoToEpochMillis("2026-01-15T08:23:11Z"))
    }

    @Test
    fun `fractional seconds are kept`() {
        assertEquals(1768465391500L, isoToEpochMillis("2026-01-15T08:23:11.500Z"))
    }

    @Test
    fun `offset timestamps resolve to the same instant`() {
        assertEquals(
            isoToEpochMillis("2026-01-15T08:23:11Z"),
            isoToEpochMillis("2026-01-15T16:23:11+08:00")
        )
    }

    @Test
    fun `missing or malformed timestamps become zero`() {
        assertEquals(0L, isoToEpochMillis(""))
        assertEquals(0L, isoToEpochMillis("   "))
        assertEquals(0L, isoToEpochMillis("2026-01-15"))
        assertEquals(0L, isoToEpochMillis("not a date"))
    }

    @Test
    fun `formatting passes unparseable values through untouched`() {
        assertEquals("", formatRepoTime(""))
        assertEquals("not a date", formatRepoTime("not a date"))
    }
}
