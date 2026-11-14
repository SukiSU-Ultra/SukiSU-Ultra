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

    @Test
    fun parsesPartialContentRangeTotal() {
        assertEquals(100L, ThemeStoreRepository.parseContentRangeTotal("bytes 0-99/100"))
        assertEquals(100L, ThemeStoreRepository.parseContentRangeTotal("bytes */100"))
        assertEquals(2048L, ThemeStoreRepository.parseContentRangeTotal("Bytes 0-0/2048"))
        assertNull(ThemeStoreRepository.parseContentRangeTotal("bytes 100-199/*"))
        assertNull(ThemeStoreRepository.parseContentRangeTotal(null))
        assertNull(ThemeStoreRepository.parseContentRangeTotal(""))
    }

    @Test
    fun plansFixedSizeChunksWithShortTail() {
        val chunk = 2L * 1024 * 1024
        val total = 23L * 1024 * 1024 + 123
        assertEquals(chunk, ThemeStoreRepository.chunkLength(total, chunk, 0))
        assertEquals(chunk, ThemeStoreRepository.chunkLength(total, chunk, 10))
        assertEquals(1024L * 1024L + 123L, ThemeStoreRepository.chunkLength(total, chunk, 11))
        assertEquals(0L, ThemeStoreRepository.chunkLength(total, chunk, 12))
        assertEquals(0L, ThemeStoreRepository.chunkLength(total, chunk, 99))
    }
}
