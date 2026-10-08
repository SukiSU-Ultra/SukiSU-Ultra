package com.sukisu.ultra.data.repository

import org.junit.Assert.assertEquals
import org.junit.Test

class DefaultSourceNameTest {

    @Test
    fun `github pages index is named owner slash repo`() {
        assertEquals(
            "uonou/mmrl-repo",
            defaultSourceName("https://uonou.github.io/mmrl-repo/json/modules.json")
        )
        assertEquals(
            "misak10/mmrl-repo",
            defaultSourceName("https://misak10.github.io/mmrl-repo/modules.json")
        )
    }

    @Test
    fun `forge address is named owner slash repo`() {
        assertEquals("uonou/mmrl-repo", defaultSourceName("https://github.com/uonou/mmrl-repo"))
        assertEquals(
            "uonou/mmrl-repo",
            defaultSourceName("https://raw.githubusercontent.com/uonou/mmrl-repo/main/json/modules.json")
        )
        assertEquals("owner/repo", defaultSourceName("https://gitlab.com/owner/repo"))
        assertEquals("owner/repo", defaultSourceName("https://gitee.com/owner/repo"))
        assertEquals("owner/repo", defaultSourceName("https://codeberg.org/owner/repo"))
    }

    @Test
    fun `clone suffix and deep paths are stripped`() {
        // The address is reproduced as published, so a repository keeps its own capitalisation.
        assertEquals("Owner/Repo", defaultSourceName("https://github.com/Owner/Repo.git"))
        assertEquals(
            "owner/repo",
            defaultSourceName("https://gitlab.com/owner/repo/-/tree/main/json/modules.json")
        )
    }

    @Test
    fun `other hosts fall back to the bare host`() {
        assertEquals("example.com", defaultSourceName("https://example.com/json/modules.json"))
        assertEquals("example.com", defaultSourceName("https://www.example.com/json/modules.json"))
        assertEquals("modules.kernelsu.org", defaultSourceName("https://modules.kernelsu.org"))
    }

    @Test
    fun `forge address without a repository keeps the host`() {
        assertEquals("github.com", defaultSourceName("https://github.com/uonou"))
        assertEquals("github.com", defaultSourceName("https://github.com"))
    }

    @Test
    fun `unparseable url is returned unchanged`() {
        assertEquals("not a url", defaultSourceName("not a url"))
        assertEquals("", defaultSourceName(""))
    }
}
