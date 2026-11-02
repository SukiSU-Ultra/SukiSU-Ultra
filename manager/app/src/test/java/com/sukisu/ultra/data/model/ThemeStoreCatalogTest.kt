package com.sukisu.ultra.data.model

import com.sukisu.ultra.data.repository.ThemeStoreRepository
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ThemeStoreCatalogTest {

    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun `catalog parses the generator output`() {
        val catalog = json.decodeFromString(
            ThemeStoreCatalog.serializer(),
            """
            {
              "schema": 1,
              "generatedAt": "2026-11-02T10:00:00Z",
              "themes": [
                {
                  "id": "pink-bow",
                  "version": 3,
                  "name": "粉色蝴蝶结",
                  "author": "Neko",
                  "description": "Test",
                  "tags": ["light", "pink"],
                  "minManagerVersion": 41131,
                  "formatVersion": 1,
                  "size": 16,
                  "sha256": "3a7bca2e86bdcaed15b0f4bb81f7d16985d52e1db61271de26181dfff4a255ea",
                  "path": "themes/pink-bow-v3.sukisu",
                  "previewPath": "previews/pink-bow-v3.webp"
                }
              ]
            }
            """.trimIndent(),
        )
        assertEquals(1, catalog.themes.size)
        val theme = catalog.themes.single()
        assertEquals("pink-bow", theme.id)
        assertEquals(3, theme.version)
        assertEquals(listOf("light", "pink"), theme.tags)
        assertEquals(16L, theme.size)
    }

    @Test
    fun `asset urls stay on the configured mirror`() {
        val base = "https://themes.example.com:8443/"
        assertEquals(
            "https://themes.example.com:8443/themes/pink-bow-v3.sukisu",
            ThemeStoreRepository.assetUrl(base, "themes/pink-bow-v3.sukisu"),
        )
        assertEquals(
            "http://themes.example.com:8080/themes/pink-bow-v3.sukisu",
            ThemeStoreRepository.assetUrl(
                "http://themes.example.com:8080/",
                "themes/pink-bow-v3.sukisu",
            ),
        )
        assertNull(ThemeStoreRepository.assetUrl(base, "https://example.com/theme.sukisu"))
        assertNull(ThemeStoreRepository.assetUrl(base, "../theme.sukisu"))
    }

    @Test
    fun `base urls are normalized for http and https`() {
        assertEquals(
            "https://themes.example.com:8443/",
            ThemeStoreRepository.normalizeBaseUrl("themes.example.com:8443"),
        )
        assertEquals(
            "http://127.0.0.1:8080/",
            ThemeStoreRepository.normalizeBaseUrl("http://127.0.0.1:8080"),
        )
        assertEquals(
            "http://themes.example.com:8080/",
            ThemeStoreRepository.normalizeBaseUrl("http://themes.example.com:8080"),
        )
        assertNull(ThemeStoreRepository.normalizeBaseUrl("https://example.com/catalog.json"))
    }
}
