package com.sukisu.ultra.ui.screen.themestore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

class ThemeStoreMentionTest {
    private fun encoded(value: String): String =
        URLEncoder.encode(value, StandardCharsets.UTF_8.name()).replace("+", "%20")

    @Test
    fun linksChineseUsernames() {
        assertEquals(
            "https://search.bilibili.com/all?keyword=${encoded("小明")}",
            themeMentionUrl("小明@bilibili"),
        )
        assertEquals(
            "https://weibo.com/${encoded("小明")}",
            themeMentionUrl("小明@weibo"),
        )
    }

    @Test
    fun linksOtherLanguageUsernames() {
        assertEquals(
            "https://github.com/${encoded("Пользователь")}",
            themeMentionUrl("Пользователь@github"),
        )
        assertEquals(
            "https://www.youtube.com/@${encoded("ユーザー")}",
            themeMentionUrl("ユーザー@youtube"),
        )
    }

    @Test
    fun keepsNumericBilibiliUid() {
        assertEquals(
            "https://space.bilibili.com/12345",
            themeMentionUrl("12345@bilibili"),
        )
    }

    @Test
    fun linksSiteMentionsCaseInsensitively() {
        assertEquals("https://github.com", themeMentionUrl("@github"))
        assertEquals("https://github.com", themeMentionUrl("@GitHub"))
    }

    @Test
    fun linksEverySupportedSiteMention() {
        listOf(
            "github", "gitee", "bilibili", "coolapk", "telegram",
            "weibo", "xiaohongshu", "xda", "youtube", "afdian",
        ).forEach { platform ->
            assertNotNull(themeMentionUrl("@$platform"))
        }
    }

    @Test
    fun rejectsEmailDomainsUnknownPlatformsAndLocalizedAliases() {
        assertNull(themeMentionUrl("foo@github.com"))
        assertNull(themeMentionUrl("foo@unknown"))
        assertNull(themeMentionUrl("小明@unknown"))
        assertNull(themeMentionUrl("@哔哩哔哩"))
        assertNull(themeMentionUrl("小明@哔哩哔哩"))
    }

    @Test
    fun recognizesMentionsNextToChinesePunctuation() {
        val tokens = INLINE_MARKDOWN.findAll("联系 小明@bilibili。").map { it.value }.toList()
        assertTrue(tokens.contains("小明@bilibili"))
        assertFalse(tokens.any { it.endsWith("。") })
    }

    @Test
    fun doesNotTurnEmailLikeTextIntoMention() {
        val tokens = INLINE_MARKDOWN.findAll("foo@github.com").map { it.value }.toList()
        assertFalse(tokens.any { it.contains('@') })
    }

    @Test
    fun keepsFullUrlContainingLetterS() {
        val tokens = INLINE_MARKDOWN.findAll("https://example.com/some/path").map { it.value }.toList()
        assertEquals(listOf("https://example.com/some/path"), tokens)
    }
}
