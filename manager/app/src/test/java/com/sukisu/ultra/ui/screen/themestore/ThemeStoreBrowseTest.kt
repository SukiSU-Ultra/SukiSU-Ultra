package com.sukisu.ultra.ui.screen.themestore

import com.sukisu.ultra.data.model.AccountPreferencesResponse
import com.sukisu.ultra.data.model.ThemeStoreCatalog
import com.sukisu.ultra.data.model.ThemeStoreEntry
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ThemeStoreBrowseTest {
    private fun item(
        id: String,
        author: String = "author",
        tags: List<String> = emptyList(),
        updatedAt: String = "2026-01-01T00:00:00Z",
        baseUrl: String = "https://example.com/",
        authorHash: String = "",
        r18: Boolean = false,
    ): ThemeStoreItem = ThemeStoreItem(
        entry = ThemeStoreEntry(
            id = id,
            name = id,
            author = author,
            authorHash = authorHash,
            r18 = r18,
            tags = tags,
            updatedAt = updatedAt,
        ),
        source = ThemeStoreSource(
            id = baseUrl,
            name = "",
            baseUrl = baseUrl,
            token = "",
        ),
    )

    @Test
    fun catalogMaintenanceFlagDefaultsToFalseAndDecodesTrue() {
        val json = Json { ignoreUnknownKeys = true }
        val normal = json.decodeFromString(ThemeStoreCatalog.serializer(), """{"schema":1}""")
        val maintenance = json.decodeFromString(
            ThemeStoreCatalog.serializer(),
            """{"schema":1,"maintenance":true}""",
        )

        assertFalse(normal.maintenance)
        assertTrue(maintenance.maintenance)
    }

    @Test
    fun accountPreferencesDecodeExplicitR18Flag() {
        val response = Json { ignoreUnknownKeys = true }.decodeFromString(
            AccountPreferencesResponse.serializer(),
            """{"ok":true,"showR18":false,"showR18Set":true}""",
        )

        assertFalse(response.showR18)
        assertTrue(response.showR18Set)
    }

    @Test
    fun popularTagsAreCaseInsensitiveAndFrequencySorted() {
        val items = listOf(
            item("one", tags = listOf("Dark", "Minimal")),
            item("two", tags = listOf("dark")),
            item("three", tags = listOf("AMOLED")),
        )

        assertEquals(listOf("adaptive", "Dark", "AMOLED", "Minimal"), items.popularThemeTags())
    }

    @Test
    fun adaptiveTagIsAlwaysOfferedFirstAndCollapsesAliases() {
        val plain = item("plain")
        assertEquals(listOf("adaptive"), listOf(plain).popularThemeTags())

        val aliased = listOf(
            item("one", tags = listOf("自适应主题")),
            item("two", tags = listOf("Adaptive")),
        )
        assertEquals(listOf("adaptive"), aliased.popularThemeTags())
    }

    @Test
    fun adaptiveFilterUsesFlagAndTagAliases() {
        val flagged = ThemeStoreItem(
            entry = ThemeStoreEntry(id = "flagged", name = "flagged", adaptive = true),
            source = ThemeStoreSource(
                id = "https://example.com/",
                name = "",
                baseUrl = "https://example.com/",
                token = "",
            ),
        )
        val tagged = item("tagged", tags = listOf("自适应"))
        val other = item("other", tags = listOf("dark"))

        assertEquals(listOf(flagged, tagged), listOf(flagged, tagged, other).filterByThemeTags(setOf(ADAPTIVE_TAG)))
        assertEquals(listOf(tagged), listOf(other, tagged).filterByThemeTags(setOf("自适应主题")))
    }

    @Test
    fun tagFiltersMatchAnySelectedTag() {
        val dark = item("dark", tags = listOf("Dark"))
        val minimal = item("minimal", tags = listOf("Minimal"))
        val both = item("both", tags = listOf("dark", "minimal"))
        val items = listOf(dark, minimal, both)

        assertEquals(items, items.filterByThemeTags(emptySet()))
        assertEquals(listOf(dark, both), items.filterByThemeTags(setOf("DARK")))
        assertEquals(items, items.filterByThemeTags(setOf("dark", "minimal")))
        assertTrue(items.filterByThemeTags(setOf("missing")).isEmpty())
    }

    @Test
    fun r18DetectionUsesCatalogFlagOrLegacyTags() {
        assertTrue(item("flag", r18 = true).isR18Theme())
        assertTrue(item("tagged", tags = listOf("R18")).isR18Theme())
        assertTrue(item("nsfw", tags = listOf("nsfw")).isR18Theme())
        assertEquals(false, item("plain", tags = listOf("dark")).isR18Theme())
    }

    @Test
    fun followKeyIncludesMirrorAndAuthorIdentity() {
        val first = item("one", baseUrl = "https://a.example.com/", authorHash = "hash-a")
        val second = item("two", baseUrl = "https://b.example.com/", authorHash = "hash-a")
        val legacy = item("three", baseUrl = "https://a.example.com/")

        assertEquals("https://a.example.com|hash-a", first.followKey())
        assertEquals("https://b.example.com|hash-a", second.followKey())
        assertEquals("", legacy.followKey())
    }

    @Test
    fun followedThemesMoveToTheFrontWithoutChangingGroupOrder() {
        val first = item("one", authorHash = "hash-1")
        val second = item("two", authorHash = "hash-2")
        val third = item("three", authorHash = "hash-3")
        val items = listOf(first, second, third)
        val followed = setOf(third.followKey())

        assertEquals(listOf(third, first, second), items.followedFirst(followed))
        assertEquals(items, items.followedFirst(emptySet()))
    }

    @Test
    fun followKeyDoesNotLeakAcrossMirrors() {
        val local = item("one", baseUrl = "https://a.example.com/", authorHash = "shared")
        val otherMirror = item("two", baseUrl = "https://b.example.com/", authorHash = "shared")
        val items = listOf(local, otherMirror)
        val followed = setOf(local.followKey())

        assertEquals(listOf(local, otherMirror), items.followedFirst(followed))
    }

    @Test
    fun authorFilterIgnoresCaseAndPaddingAcrossSources() {
        val first = item("one", author = " Alice ", baseUrl = "https://a.example.com/")
        val second = item("two", author = "alice", baseUrl = "https://b.example.com/")
        val other = item("three", author = "Bob")
        val items = listOf(first, second, other)

        assertEquals(listOf(first, second), items.forThemeAuthor("ALICE"))
        assertEquals(listOf(first, second), items.forThemeAuthor("  alice  "))
        assertTrue(items.forThemeAuthor("   ").isEmpty())
    }
}
