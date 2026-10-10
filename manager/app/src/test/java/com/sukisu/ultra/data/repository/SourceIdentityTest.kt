package com.sukisu.ultra.data.repository

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SourceIdentityTest {

    private val pages = "https://uonou.github.io/mmrl-repo/json/modules.json"
    private val raw = "https://raw.githubusercontent.com/uonou/mmrl-repo/HEAD/json/modules.json"
    private val jsdelivr = "https://cdn.jsdelivr.net/gh/uonou/mmrl-repo@HEAD/json/modules.json"
    private val blob = "https://github.com/uonou/mmrl-repo/blob/main/json/modules.json"

    @Test
    fun `one index reached three ways has one identity`() {
        val expected = indexIdentity(pages)
        assertEquals("github:uonou/mmrl-repo/json/modules.json", expected)
        assertEquals(expected, indexIdentity(raw))
        assertEquals(expected, indexIdentity(jsdelivr))
        assertEquals(expected, indexIdentity(blob))
    }

    @Test
    fun `the branch and the host do not change the identity`() {
        assertEquals(
            indexIdentity("https://raw.githubusercontent.com/uonou/mmrl-repo/main/json/modules.json"),
            indexIdentity("https://raw.githubusercontent.com/uonou/mmrl-repo/HEAD/json/modules.json"),
        )
        assertEquals(
            indexIdentity("https://uonou.github.io/mmrl-repo/json/modules.json"),
            indexIdentity("https://cdn.jsdelivr.net/gh/UONOU/MMRL-REPO@main/json/modules.json"),
        )
    }

    @Test
    fun `a different file in the same repository is a different source`() {
        assertFalse(
            indexIdentity("https://uonou.github.io/mmrl-repo/json/modules.json") ==
                indexIdentity("https://uonou.github.io/mmrl-repo/json/modules-extra.json")
        )
    }

    @Test
    fun `addresses that are not github index files have no identity`() {
        assertNull(indexIdentity("https://apt.izzysoft.de/magisk/json/modules.json"))
        assertNull(indexIdentity("https://codeberg.org/fruitsnack/magisk-font-repo/raw/branch/main/json/modules.json"))
        assertNull(indexIdentity("https://github.com/uonou/mmrl-repo"))
        assertNull(indexIdentity("https://uonou.github.io/mmrl-repo"))
        assertNull(indexIdentity("not a url"))
    }

    @Test
    fun `the same repository reached two ways is one source`() {
        assertTrue(isSameSource(pages, raw))
        assertTrue(isSameSource(raw, pages))
        assertTrue(isSameSource(pages, jsdelivr))
        assertTrue(isSameSource("https://github.com/uonou/mmrl-repo", pages))
        assertTrue(isSameSource(pages, "https://github.com/uonou/mmrl-repo"))
    }

    @Test
    fun `trailing slashes and case do not make a second source`() {
        assertTrue(isSameSource(pages, "$pages/"))
        assertTrue(isSameSource(pages, pages.uppercase()))
        assertTrue(isSameSource("https://github.com/uonou/mmrl-repo/", "https://github.com/uonou/mmrl-repo"))
    }

    @Test
    fun `different repositories are different sources`() {
        assertFalse(isSameSource(pages, "https://uonou.github.io/other-repo/json/modules.json"))
        assertFalse(isSameSource(pages, "https://someone-else.github.io/mmrl-repo/json/modules.json"))
        assertFalse(
            isSameSource(
                "https://github.com/uonou/mmrl-repo",
                "https://github.com/uonou/mmrl-repo-fork",
            )
        )
    }

    @Test
    fun `a site address matches the index under it`() {
        assertTrue(
            isSameSource(
                "https://uonou.github.io/mmrl-repo",
                "https://uonou.github.io/mmrl-repo/json/modules.json",
            )
        )
        assertTrue(
            isSameSource(
                "https://apt.izzysoft.de/magisk",
                "https://apt.izzysoft.de/magisk/json/modules.json",
            )
        )
        assertFalse(
            isSameSource(
                "https://apt.izzysoft.de/magisk",
                "https://apt.izzysoft.de/something-else/json/modules.json",
            )
        )
    }

    @Test
    fun `addresses without any relation are not the same source`() {
        assertFalse(
            isSameSource(
                "https://example.com/a/json/modules.json",
                "https://example.com/b/json/modules.json",
            )
        )
        assertFalse(isSameSource("", "https://example.com/a/json/modules.json"))
    }
}
