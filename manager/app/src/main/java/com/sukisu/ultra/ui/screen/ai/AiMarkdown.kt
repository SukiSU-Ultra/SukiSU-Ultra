package com.sukisu.ultra.ui.screen.ai

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withLink
import androidx.compose.ui.text.withStyle
import org.commonmark.ext.autolink.AutolinkExtension
import org.commonmark.ext.gfm.strikethrough.Strikethrough
import org.commonmark.ext.gfm.strikethrough.StrikethroughExtension
import org.commonmark.ext.gfm.tables.TableBlock
import org.commonmark.ext.gfm.tables.TableBody
import org.commonmark.ext.gfm.tables.TableCell
import org.commonmark.ext.gfm.tables.TableHead
import org.commonmark.ext.gfm.tables.TableRow
import org.commonmark.ext.gfm.tables.TablesExtension
import org.commonmark.node.BlockQuote
import org.commonmark.node.BulletList
import org.commonmark.node.Code
import org.commonmark.node.Emphasis
import org.commonmark.node.FencedCodeBlock
import org.commonmark.node.HardLineBreak
import org.commonmark.node.Heading
import org.commonmark.node.HtmlBlock
import org.commonmark.node.HtmlInline
import org.commonmark.node.Image
import org.commonmark.node.IndentedCodeBlock
import org.commonmark.node.Link
import org.commonmark.node.ListItem
import org.commonmark.node.Node
import org.commonmark.node.OrderedList
import org.commonmark.node.Paragraph
import org.commonmark.node.SoftLineBreak
import org.commonmark.node.StrongEmphasis
import org.commonmark.node.Text as MarkdownText
import org.commonmark.node.ThematicBreak
import org.commonmark.parser.Parser

/**
 * A small, native Compose Markdown model. Chat answers commonly contain headings,
 * lists, tables and fenced code; rendering them through a WebView per message is
 * far too heavy, so this parses the CommonMark AST once and lets each UI mode
 * draw the blocks with its own typography.
 */
sealed interface AiMarkdownBlock {
    data class Paragraph(val text: AnnotatedString) : AiMarkdownBlock

    data class Heading(val level: Int, val text: AnnotatedString) : AiMarkdownBlock

    data class Code(val language: String, val code: String) : AiMarkdownBlock {
        val executable: Boolean
            get() = language.lowercase() in EXECUTABLE_LANGUAGES
    }

    data class ListBlock(
        val ordered: Boolean,
        val start: Int,
        val items: List<AiListItem>,
    ) : AiMarkdownBlock

    data class Quote(val blocks: List<AiMarkdownBlock>) : AiMarkdownBlock

    data class Table(
        val header: List<AnnotatedString>,
        val rows: List<List<AnnotatedString>>,
    ) : AiMarkdownBlock

    data object Divider : AiMarkdownBlock
}

data class AiListItem(val blocks: List<AiMarkdownBlock>)

private val EXECUTABLE_LANGUAGES = setOf(
    "sh", "shell", "bash", "zsh", "ash", "dash", "ksh", "ksu", "su",
)

private val AI_MARKDOWN_EXTENSIONS = listOf(
    TablesExtension.create(),
    StrikethroughExtension.builder().requireTwoTildes(true).build(),
    AutolinkExtension.create(),
)

private val AI_MARKDOWN_PARSER: Parser by lazy {
    Parser.builder().extensions(AI_MARKDOWN_EXTENSIONS).build()
}

fun parseAiMarkdown(
    content: String,
    linkColor: Color,
    codeBackground: Color,
): List<AiMarkdownBlock> {
    if (content.isBlank()) return emptyList()
    val renderer = AiMarkdownRenderer(linkColor, codeBackground)
    return renderer.blocks(AI_MARKDOWN_PARSER.parse(content))
}

private class AiMarkdownRenderer(
    linkColor: Color,
    private val codeBackground: Color,
) {
    private val linkStyle = SpanStyle(
        color = linkColor,
        textDecoration = TextDecoration.Underline,
    )

    fun blocks(parent: Node): List<AiMarkdownBlock> {
        val result = mutableListOf<AiMarkdownBlock>()
        parent.forEachChild { child ->
            blockOf(child)?.let(result::add)
        }
        return result
    }

    private fun blockOf(node: Node): AiMarkdownBlock? = when (node) {
        is Heading -> {
            val text = inline(node)
            if (text.isBlank()) null else AiMarkdownBlock.Heading(node.level, text)
        }

        is Paragraph -> {
            val text = inline(node)
            if (text.isBlank()) null else AiMarkdownBlock.Paragraph(text)
        }

        is FencedCodeBlock -> {
            val info = node.info.orEmpty().trim()
            val language = info
                .substringBefore(' ')
                .substringBefore('\t')
                .removePrefix("{")
                .removePrefix(".")
                .removeSuffix("}")
            AiMarkdownBlock.Code(language, node.literal.orEmpty().trimEnd())
        }

        is IndentedCodeBlock -> AiMarkdownBlock.Code("", node.literal.orEmpty().trimEnd())

        is BulletList -> listBlock(node, ordered = false, start = 1)

        is OrderedList -> listBlock(
            node,
            ordered = true,
            start = node.markerStartNumber ?: 1,
        )

        is BlockQuote -> {
            val children = blocks(node)
            if (children.isEmpty()) null else AiMarkdownBlock.Quote(children)
        }

        is ThematicBreak -> AiMarkdownBlock.Divider

        is TableBlock -> table(node)

        is HtmlBlock -> {
            val text = node.literal.orEmpty().trim()
            if (text.isEmpty()) null else AiMarkdownBlock.Paragraph(AnnotatedString(text))
        }

        else -> null
    }

    private fun listBlock(node: Node, ordered: Boolean, start: Int): AiMarkdownBlock {
        val items = mutableListOf<AiListItem>()
        node.forEachChild { child ->
            if (child is ListItem) {
                items += AiListItem(blocks(child))
            }
        }
        return AiMarkdownBlock.ListBlock(ordered, start, items)
    }

    private fun table(node: Node): AiMarkdownBlock.Table? {
        var header = emptyList<AnnotatedString>()
        val rows = mutableListOf<List<AnnotatedString>>()
        node.forEachChild { part ->
            when (part) {
                is TableHead -> {
                    part.forEachChild { row ->
                        if (row is TableRow) header = tableCells(row)
                    }
                }

                is TableBody -> {
                    part.forEachChild { row ->
                        if (row is TableRow) rows += tableCells(row)
                    }
                }
            }
        }
        if (header.isEmpty() && rows.isEmpty()) return null
        return AiMarkdownBlock.Table(header, rows)
    }

    private fun tableCells(row: TableRow): List<AnnotatedString> {
        val cells = mutableListOf<AnnotatedString>()
        row.forEachChild { child ->
            if (child is TableCell) cells += inline(child)
        }
        return cells
    }

    private fun inline(parent: Node): AnnotatedString = buildAnnotatedString {
        appendInlineChildren(parent, SpanStyle())
    }

    private fun AnnotatedString.Builder.appendInlineChildren(
        parent: Node,
        style: SpanStyle,
    ) {
        parent.forEachChild { child ->
            appendInline(child, style)
        }
    }

    private fun AnnotatedString.Builder.appendInline(node: Node, style: SpanStyle) {
        when (node) {
            is MarkdownText -> withStyle(style) { append(node.literal.orEmpty()) }

            is Code -> withStyle(
                style.merge(
                    SpanStyle(
                        fontFamily = FontFamily.Monospace,
                        background = codeBackground,
                    )
                )
            ) {
                append(node.literal.orEmpty())
            }

            is Emphasis -> withStyle(style.merge(SpanStyle(fontStyle = FontStyle.Italic))) {
                appendInlineChildren(node, style.merge(SpanStyle(fontStyle = FontStyle.Italic)))
            }

            is StrongEmphasis -> withStyle(style.merge(SpanStyle(fontWeight = FontWeight.Bold))) {
                appendInlineChildren(node, style.merge(SpanStyle(fontWeight = FontWeight.Bold)))
            }

            is Strikethrough -> withStyle(
                style.merge(SpanStyle(textDecoration = TextDecoration.LineThrough))
            ) {
                appendInlineChildren(
                    node,
                    style.merge(SpanStyle(textDecoration = TextDecoration.LineThrough)),
                )
            }

            is Link -> {
                val destination = node.destination
                if (destination.isNullOrBlank()) {
                    appendInlineChildren(node, style)
                } else {
                    withLink(LinkAnnotation.Url(destination)) {
                        appendInlineChildren(node, style.merge(linkStyle))
                    }
                }
            }

            is Image -> {
                val destination = node.destination
                if (destination.isNullOrBlank()) {
                    appendInlineChildren(node, style)
                } else {
                    withLink(LinkAnnotation.Url(destination)) {
                        appendInlineChildren(node, style.merge(linkStyle))
                    }
                }
            }

            is SoftLineBreak -> append("\n")

            is HardLineBreak -> append("\n")

            is HtmlInline -> withStyle(style) { append(node.literal.orEmpty()) }

            else -> appendInlineChildren(node, style)
        }
    }
}

private inline fun Node.forEachChild(action: (Node) -> Unit) {
    var child = firstChild
    while (child != null) {
        action(child)
        child = child.next
    }
}
