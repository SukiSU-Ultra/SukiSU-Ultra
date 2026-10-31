package com.sukisu.ultra.ai

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AiSuggestionsTest {

    @Test
    fun stripsMarkdownAndFormatting() {
        assertEquals("查看 模块 状态", sanitizeAiSuggestion("**查看** `模块` 状态"))
        assertEquals("打开设置", sanitizeAiSuggestion("1. 打开设置"))
        assertEquals("查看文档", sanitizeAiSuggestion("[查看文档](https://example.com/doc)"))
        assertEquals("检查 KPM", sanitizeAiSuggestion("- 检查 KPM"))
    }

    @Test
    fun removesControlAndReplacementCharacters() {
        assertEquals("奇怪 符号", sanitizeAiSuggestion("\u200B奇怪\uFFFD符号"))
        assertEquals("正常文本", sanitizeAiSuggestion("正常\u0000文本"))
    }

    @Test
    fun rejectsJsonFragments() {
        assertNull(sanitizeAiSuggestion("""{"suggestion":"x"}"""))
        assertNull(sanitizeAiSuggestion("""["a","b""""))
    }

    @Test
    fun truncatesLongSuggestions() {
        val result = sanitizeAiSuggestion("这是一个很长的推荐内容".repeat(20))
        assertTrue(result != null)
        assertTrue(result!!.length <= 90)
    }
}
