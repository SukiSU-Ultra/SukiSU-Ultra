package com.sukisu.ultra.ui.screen.ai

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.font.FontFamily
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AiMarkdownTest {

    private fun parse(content: String): List<AiMarkdownBlock> =
        parseAiMarkdown(content, Color.Blue, Color.LightGray)

    @Test
    fun parsesHeadingsParagraphsAndLinks() {
        val blocks = parse(
            """
            # Title

            A **bold** word, `code`, and [a link](https://example.com).
            """.trimIndent()
        )

        assertEquals(2, blocks.size)
        assertTrue(blocks[0] is AiMarkdownBlock.Heading)
        assertEquals("Title", (blocks[0] as AiMarkdownBlock.Heading).text.text)
        assertTrue(blocks[1] is AiMarkdownBlock.Paragraph)
        val paragraph = blocks[1] as AiMarkdownBlock.Paragraph
        assertTrue(paragraph.text.text.contains("bold"))
        assertTrue(paragraph.text.text.contains("a link"))
        assertTrue(
            paragraph.text.getLinkAnnotations(0, paragraph.text.length).any {
                (it.item as? LinkAnnotation.Url)?.url == "https://example.com"
            }
        )
        assertTrue(
            paragraph.text.spanStyles.any {
                it.item.fontFamily == FontFamily.Monospace
            }
        )
    }

    @Test
    fun parsesFencedCodeAndMarksShellExecutable() {
        val blocks = parse(
            """
            ```bash
            echo hello
            ```

            ```kotlin
            val x = 1
            ```
            """.trimIndent()
        )

        assertEquals(2, blocks.size)
        val shell = blocks[0] as AiMarkdownBlock.Code
        assertEquals("bash", shell.language)
        assertEquals("echo hello", shell.code)
        assertTrue(shell.executable)

        val kotlin = blocks[1] as AiMarkdownBlock.Code
        assertFalse(kotlin.executable)
    }

    @Test
    fun parsesListsQuotesAndTables() {
        val blocks = parse(
            """
            - one
            - two

            > quoted

            | Name | Value |
            | --- | --- |
            | a | 1 |
            """.trimIndent()
        )

        assertEquals(3, blocks.size)
        val list = blocks[0] as AiMarkdownBlock.ListBlock
        assertFalse(list.ordered)
        assertEquals(2, list.items.size)
        assertTrue(blocks[1] is AiMarkdownBlock.Quote)

        val table = blocks[2] as AiMarkdownBlock.Table
        assertEquals(listOf("Name", "Value"), table.header.map { it.text })
        assertEquals("a", table.rows.single()[0].text)
    }

    @Test
    fun parsesOrderedListStartNumber() {
        val blocks = parse("3. three\n4. four")
        val list = blocks.single() as AiMarkdownBlock.ListBlock
        assertTrue(list.ordered)
        assertEquals(3, list.start)
        assertEquals(2, list.items.size)
    }
}
