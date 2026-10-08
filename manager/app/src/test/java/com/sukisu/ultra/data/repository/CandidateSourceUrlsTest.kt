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
    fun `github repository address also tries its github pages site`() {
        assertEquals(
            listOf(
                "https://github.com/uonou/mmrl-repo/json/modules.json",
                "https://github.com/uonou/mmrl-repo/modules.json",
                "https://uonou.github.io/mmrl-repo/json/modules.json",
                "https://uonou.github.io/mmrl-repo/modules.json",
            ),
            candidateSourceUrls("https://github.com/uonou/mmrl-repo")
        )
    }

    @Test
    fun `github clone url and deep paths are handled`() {
        assertEquals(
            listOf(
                "https://github.com/Owner/Repo.git/json/modules.json",
                "https://github.com/Owner/Repo.git/modules.json",
                "https://owner.github.io/Repo/json/modules.json",
                "https://owner.github.io/Repo/modules.json",
            ),
            candidateSourceUrls("https://github.com/Owner/Repo.git")
        )
        assertEquals(
            listOf(
                "https://github.com/uonou/mmrl-repo/tree/main/json/modules.json",
                "https://github.com/uonou/mmrl-repo/tree/main/modules.json",
            ),
            candidateSourceUrls("https://github.com/uonou/mmrl-repo/tree/main")
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
