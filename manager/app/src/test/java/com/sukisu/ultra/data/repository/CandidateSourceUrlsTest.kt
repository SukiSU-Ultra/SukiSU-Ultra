package com.sukisu.ultra.data.repository

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CandidateSourceUrlsTest {

    @Test
    fun `bare domain tries mmrl convention first then kernelsu`() {
        assertEquals(
            listOf(
                "https://uonou.github.io/mmrl-repo/json/modules.json",
                "https://uonou.github.io/mmrl-repo/modules.json",
            ),
            candidateSourceUrls("https://uonou.github.io/mmrl-repo")
        )
    }

    @Test
    fun `trailing slash is normalized`() {
        assertEquals(
            listOf("https://example.com/repo/json/modules.json", "https://example.com/repo/modules.json"),
            candidateSourceUrls("https://example.com/repo/")
        )
    }

    @Test
    fun `explicit json url is used as-is`() {
        assertEquals(
            listOf("https://example.com/some/custom/index.json"),
            candidateSourceUrls("https://example.com/some/custom/index.json")
        )
    }

    @Test
    fun `non-http schemes are rejected`() {
        assertTrue(candidateSourceUrls("ftp://example.com/repo").isEmpty())
        assertTrue(candidateSourceUrls("example.com/repo").isEmpty())
        assertTrue(candidateSourceUrls("").isEmpty())
        assertTrue(candidateSourceUrls("   ").isEmpty())
    }
}
