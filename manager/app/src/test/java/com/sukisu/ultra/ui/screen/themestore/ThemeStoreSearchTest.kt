package com.sukisu.ultra.ui.screen.themestore

import com.sukisu.ultra.data.model.ThemeStoreEntry
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ThemeStoreSearchTest {
    private val item = ThemeStoreItem(
        entry = ThemeStoreEntry(
            id = "pink-bow",
            name = "Pink Bow",
            author = "Neko",
            description = "A soft pink theme",
            tags = listOf("light", "cute"),
        ),
        source = ThemeStoreSource(
            id = "default",
            name = "Official",
            baseUrl = "https://themes.example.com/",
            token = "",
            isDefault = true,
        ),
    )

    @Test
    fun blankQueryMatchesEverything() {
        assertTrue(item.matchesSearch(""))
        assertTrue(item.matchesSearch("   "))
    }

    @Test
    fun matchesNameAuthorTagsAndSource() {
        assertTrue(item.matchesSearch("pink"))
        assertTrue(item.matchesSearch("neko"))
        assertTrue(item.matchesSearch("cute"))
        assertTrue(item.matchesSearch("official"))
        assertTrue(item.matchesSearch("pink-bow"))
    }

    @Test
    fun matchesMultipleTermsCaseInsensitively() {
        assertTrue(item.matchesSearch("PINK neko"))
        assertTrue(item.matchesSearch("  soft   theme "))
    }

    @Test
    fun rejectsUnknownTerms() {
        assertFalse(item.matchesSearch("dark"))
        assertFalse(item.matchesSearch("pink missing"))
    }
}
