package com.sukisu.ultra.data.repository

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AssetUrlFallbackTest {

    private val index = "https://uonou.github.io/mmrl-repo/json/modules.json"

    @Test
    fun `asset host that moved falls back to the index host`() {
        assertEquals(
            "https://uonou.github.io/mmrl-repo/modules/copg/7.3.0_730.zip",
            sameOriginAssetFallback(
                "https://misak10.github.io/mmrl-repo/modules/copg/7.3.0_730.zip",
                index,
            ),
        )
    }

    @Test
    fun `asset already on the index host needs no fallback`() {
        assertNull(
            sameOriginAssetFallback(
                "https://uonou.github.io/mmrl-repo/modules/copg/7.3.0_730.zip",
                index,
            ),
        )
    }

    @Test
    fun `asset outside the repository directory is left alone`() {
        assertNull(sameOriginAssetFallback("https://cdn.example.com/releases/copg.zip", index))
    }

    @Test
    fun `index without a directory can serve any path`() {
        assertEquals(
            "https://example.com/files/mod.zip",
            sameOriginAssetFallback(
                "https://old.example.com/files/mod.zip",
                "https://example.com/modules.json",
            ),
        )
    }

    @Test
    fun `query string survives the rewrite`() {
        assertEquals(
            "https://example.com/repo/files/mod.zip?raw=1",
            sameOriginAssetFallback(
                "https://old.example.com/repo/files/mod.zip?raw=1",
                "https://example.com/repo/json/modules.json",
            ),
        )
    }

    @Test
    fun `non default port is kept`() {
        assertEquals(
            "https://example.com:8443/repo/files/mod.zip",
            sameOriginAssetFallback(
                "https://old.example.com/repo/files/mod.zip",
                "https://example.com:8443/repo/json/modules.json",
            ),
        )
    }

    @Test
    fun `unparseable or missing urls have no fallback`() {
        assertNull(sameOriginAssetFallback("not a url", index))
        assertNull(sameOriginAssetFallback("https://old.example.com/repo/x.zip", ""))
        assertNull(sameOriginAssetFallback("", index))
    }
}
