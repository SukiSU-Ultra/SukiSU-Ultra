package com.sukisu.ultra.data.repository

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ReleaseLinksTest {

    private val asset =
        "https://github.com/LSPosed/ZygiskNext/releases/download/v1.5.0/Zygisk-Next-1.5.0-843-5217106-release.zip"

    @Test
    fun `a release asset gives its page and its repository`() {
        assertEquals("https://github.com/LSPosed/ZygiskNext/releases/tag/v1.5.0", releasePageUrl(asset))
        assertEquals("https://github.com/LSPosed/ZygiskNext", repositoryUrl(asset))
    }

    @Test
    fun `a tag with a slash keeps its encoding`() {
        val url = "https://github.com/owner/repo/releases/download/release%2Fv1.0/mod.zip"
        assertEquals("https://github.com/owner/repo/releases/tag/release%2Fv1.0", releasePageUrl(url))
        assertEquals("https://github.com/owner/repo", repositoryUrl(url))
    }

    @Test
    fun `a zip served by the repository itself has no release page`() {
        assertNull(releasePageUrl("https://uonou.github.io/mmrl-repo/modules/copg/7.3.0_730.zip"))
        assertNull(repositoryUrl("https://uonou.github.io/mmrl-repo/modules/copg/7.3.0_730.zip"))
    }

    @Test
    fun `a zip kept inside the repository still has a repository`() {
        val url = "https://github.com/qianyumeng0228/ShizuSU-Modules/raw/main/private/Eclipse.zip"
        assertEquals("https://github.com/qianyumeng0228/ShizuSU-Modules", repositoryUrl(url))
        // Nothing is published for such a file, so there is no page to send the user to.
        assertNull(releasePageUrl(url))
    }

    @Test
    fun `github addresses that are not release assets have no release page`() {
        assertNull(releasePageUrl("https://github.com/uonou/mmrl-repo"))
        assertNull(releasePageUrl("https://github.com/uonou/mmrl-repo/archive/refs/tags/v1.zip"))
        assertNull(releasePageUrl("https://github.com/owner/repo/releases/download/v1"))
        assertNull(releasePageUrl("https://raw.githubusercontent.com/uonou/mmrl-repo/HEAD/json/modules.json"))
    }

    @Test
    fun `unparseable addresses have no release page`() {
        assertNull(releasePageUrl(""))
        assertNull(releasePageUrl("not a url"))
    }
}
