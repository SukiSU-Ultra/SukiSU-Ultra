package com.sukisu.ultra.data.repository

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ThemeStoreResumeTest {
    @Test
    fun parsesPartialContentRangeStart() {
        assertEquals(0L, ThemeStoreRepository.parseContentRangeStart("bytes 0-99/100"))
        assertEquals(100L, ThemeStoreRepository.parseContentRangeStart("bytes 100-199/200"))
        assertEquals(100L, ThemeStoreRepository.parseContentRangeStart("bytes 100-199/*"))
        assertEquals(42L, ThemeStoreRepository.parseContentRangeStart("Bytes 42-"))
    }

    @Test
    fun rejectsMissingOrInvalidContentRange() {
        assertNull(ThemeStoreRepository.parseContentRangeStart(null))
        assertNull(ThemeStoreRepository.parseContentRangeStart(""))
        assertNull(ThemeStoreRepository.parseContentRangeStart("items 10-20/30"))
        assertNull(ThemeStoreRepository.parseContentRangeStart("bytes */100"))
    }
}
