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
    fun `github repository address tries pages then the repository itself then the mirror`() {
        assertEquals(
            listOf(
                "https://uonou.github.io/mmrl-repo/json/modules.json",
                "https://uonou.github.io/mmrl-repo/modules.json",
                "https://raw.githubusercontent.com/uonou/mmrl-repo/HEAD/json/modules.json",
                "https://raw.githubusercontent.com/uonou/mmrl-repo/HEAD/modules.json",
                "https://cdn.jsdelivr.net/gh/uonou/mmrl-repo@HEAD/json/modules.json",
                "https://cdn.jsdelivr.net/gh/uonou/mmrl-repo@HEAD/modules.json",
            ),
            candidateSourceUrls("https://github.com/uonou/mmrl-repo")
        )
    }

    @Test
    fun `a repository whose index sits at the root is found in the repository itself`() {
        // ShizuSU publishes modules.json at the repository root and its Pages site is not
        // deployed, so the raw host is what resolves it.
        val candidates = candidateSourceUrls("https://github.com/qianyumeng0228/ShizuSU-Modules")
        assertEquals(
            "https://raw.githubusercontent.com/qianyumeng0228/ShizuSU-Modules/HEAD/modules.json",
            candidates[3]
        )
    }

    @Test
    fun `github clone url is handled`() {
        assertEquals(
            listOf(
                "https://owner.github.io/Repo/json/modules.json",
                "https://owner.github.io/Repo/modules.json",
                "https://raw.githubusercontent.com/Owner/Repo/HEAD/json/modules.json",
                "https://raw.githubusercontent.com/Owner/Repo/HEAD/modules.json",
                "https://cdn.jsdelivr.net/gh/Owner/Repo@HEAD/json/modules.json",
                "https://cdn.jsdelivr.net/gh/Owner/Repo@HEAD/modules.json",
            ),
            candidateSourceUrls("https://github.com/Owner/Repo.git")
        )
    }

    @Test
    fun `a tree address keeps the branch it names and is read from the repository first`() {
        assertEquals(
            listOf(
                "https://raw.githubusercontent.com/uonou/mmrl-repo/dev/json/modules.json",
                "https://raw.githubusercontent.com/uonou/mmrl-repo/dev/modules.json",
                "https://uonou.github.io/mmrl-repo/json/modules.json",
                "https://uonou.github.io/mmrl-repo/modules.json",
                "https://cdn.jsdelivr.net/gh/uonou/mmrl-repo@dev/json/modules.json",
                "https://cdn.jsdelivr.net/gh/uonou/mmrl-repo@dev/modules.json",
            ),
            candidateSourceUrls("https://github.com/uonou/mmrl-repo/tree/dev")
        )
        assertEquals(
            "https://raw.githubusercontent.com/uonou/mmrl-repo/main/json/modules.json",
            candidateSourceUrls("https://github.com/uonou/mmrl-repo/blob/main/json/modules.json").first()
        )
    }

    @Test
    fun `github addresses that are not repositories keep the plain conventions`() {
        assertEquals(
            listOf(
                "https://github.com/uonou/json/modules.json",
                "https://github.com/uonou/modules.json",
            ),
            candidateSourceUrls("https://github.com/uonou")
        )
        // A release asset is a real file on github.com, so it is left as it was pasted.
        assertEquals(
            listOf("https://github.com/uonou/mmrl-repo/releases/download/v1/modules.json"),
            candidateSourceUrls("https://github.com/uonou/mmrl-repo/releases/download/v1/modules.json")
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
