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

    @Test
    fun matchesAuthorHandleWrittenWithSeparatorsOrAtSign() {
        assertTrue(item.matchesSearch("@neko"))
        assertTrue(item.copy(entry = item.entry.copy(author = "ne ko")).matchesSearch("neko"))
        assertTrue(item.copy(entry = item.entry.copy(author = "ne_ko")).matchesSearch("neko"))
    }

    @Test
    fun matchesAuthorWithFullWidthOrInvisibleCharacters() {
        assertTrue(item.copy(entry = item.entry.copy(author = "\uFF4E\uFF45\uFF4B\uFF4F")).matchesSearch("neko"))
        assertTrue(item.copy(entry = item.entry.copy(author = "ne\u200Bko")).matchesSearch("neko"))
    }

    @Test
    fun matchesAuthorIgnoringDiacritics() {
        assertTrue(item.copy(entry = item.entry.copy(author = "N\u00E9ko")).matchesSearch("neko"))
    }

    @Test
    fun adaptiveFlagMatchesTheLocalizedLabelWithoutATag() {
        val adaptive = item.copy(
            entry = item.entry.copy(
                tags = emptyList(),
                adaptive = true,
            ),
        )
        assertTrue(adaptive.matchesSearch("自适应", "自适应主题"))
        assertTrue(adaptive.matchesSearch("adaptive", "自适应主题"))
    }
}
