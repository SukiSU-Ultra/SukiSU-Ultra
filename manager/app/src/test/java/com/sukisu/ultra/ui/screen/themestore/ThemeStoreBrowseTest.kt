package com.sukisu.ultra.ui.screen.themestore

import com.sukisu.ultra.data.model.ThemeStoreEntry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ThemeStoreBrowseTest {
    private fun item(
        id: String,
        author: String = "author",
        tags: List<String> = emptyList(),
        updatedAt: String = "2026-01-01T00:00:00Z",
        baseUrl: String = "https://example.com/",
    ): ThemeStoreItem = ThemeStoreItem(
        entry = ThemeStoreEntry(
            id = id,
            name = id,
            author = author,
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
