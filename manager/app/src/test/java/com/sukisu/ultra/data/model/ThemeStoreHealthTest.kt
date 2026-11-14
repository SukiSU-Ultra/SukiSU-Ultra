package com.sukisu.ultra.data.model

import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ThemeStoreHealthTest {
    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun `health parses the mirror output`() {
        val health = json.decodeFromString(
            ThemeStoreHealth.serializer(),
            """
            {
              "ok": true,
              "status": "ok",
              "version": "1.0.0",
              "time": "2026-11-03T12:00:00Z",
              "uptimeSeconds": 3600,
              "checks": {
                "database": { "ok": true, "latencyMs": 2 },
                "storage": { "ok": true, "backend": "local", "diskFree": 1024 },
                "catalog": { "ok": true, "themes": 12, "generatedAt": "2026-11-03T11:00:00Z" },
                "pending": { "count": 3, "bytes": 2048 }
              },
              "stats": { "downloads": 42, "recentDownloads": 7 }
            }
            """.trimIndent(),
        )

        assertTrue(health.ok)
        assertEquals("ok", health.status)
        assertEquals("1.0.0", health.version)
        assertEquals(3600L, health.uptimeSeconds)
        assertEquals(2L, health.checks.database.latencyMs)
        assertTrue(health.checks.storage.ok)
        assertEquals(12, health.checks.catalog.themes)
        assertEquals(3, health.checks.pending.count)
    }

    @Test
    fun `missing optional checks stay nullable`() {
        val health = json.decodeFromString(
            ThemeStoreHealth.serializer(),
            """{"ok":false,"status":"down"}""",
        )

        assertFalse(health.ok)
        assertEquals("down", health.status)
        assertNull(health.checks.database.latencyMs)
        assertNull(health.checks.catalog.themes)
        assertNull(health.checks.pending.count)
    }
}
