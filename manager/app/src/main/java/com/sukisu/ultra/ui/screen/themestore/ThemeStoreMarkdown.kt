@file:Suppress("SpellCheckingInspection")

package com.sukisu.ultra.ui.screen.themestore

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLinkStyles
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withLink
import androidx.compose.ui.text.withStyle
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.Locale

private val THEME_SITE_MENTIONS = mapOf(
    "github" to "https://github.com",
    "gitee" to "https://gitee.com",
    "bilibili" to "https://www.bilibili.com",
    "coolapk" to "https://www.coolapk.com",
    "telegram" to "https://t.me",
    "weibo" to "https://weibo.com",
    "xiaohongshu" to "https://www.xiaohongshu.com",
    "xda" to "https://xdaforums.com",
    "youtube" to "https://www.youtube.com",
    "afdian" to "https://afdian.com",
    "twitter" to "https://x.com",
    "x" to "https://x.com",
    "zhihu" to "https://www.zhihu.com",
    "threads" to "https://www.threads.net",
    "douyin" to "https://www.douyin.com",
)

private val MENTION_PLATFORM = THEME_SITE_MENTIONS.keys
    .sortedByDescending(String::length)
    .joinToString("|") { Regex.escape(it) }

// Usernames may use any language and common symbols such as ~, ·, or +.
private const val MENTION_USERNAME = """[\p{L}\p{M}\p{N}._·~+-]+"""

// Allow CJK text and punctuation right after a mention, but not an email/domain suffix.
private const val MENTION_END = """(?![A-Za-z0-9._-])"""

// The platform alternation must stay grouped so the trailing boundary applies to every alias.
@Suppress("RegExpUnnecessaryNonCapturingGroup")
internal val INLINE_MARKDOWN = Regex(
    """\*\*[^*\n]+\*\*|`[^`\n]+`|\[[^]\n]+]\(https?://[^\s)]+\)|$MENTION_USERNAME@(?:$MENTION_PLATFORM)$MENTION_END|(?<![A-Za-z0-9_@.-])@(?:$MENTION_PLATFORM)$MENTION_END|(?<![A-Za-z0-9_@.-])@$MENTION_USERNAME$MENTION_END|https?://\S+|\*[^*\n]+\*""",
    RegexOption.IGNORE_CASE,
)

private fun encodeUserSegment(value: String): String =
    URLEncoder.encode(value, StandardCharsets.UTF_8.name()).replace("+", "%20")

private fun userMentionUrl(user: String, platform: String): String? = when (platform.lowercase(Locale.ROOT)) {
    "github" -> "https://github.com/${encodeUserSegment(user)}"
    "gitee" -> "https://gitee.com/${encodeUserSegment(user)}"
    "bilibili" -> if (user.all(Char::isDigit)) {
        "https://space.bilibili.com/$user"
    } else {
        "https://search.bilibili.com/all?keyword=${encodeUserSegment(user)}"
    }
    "coolapk" -> "https://www.coolapk.com/u/${encodeUserSegment(user)}"
    "telegram" -> "https://t.me/${encodeUserSegment(user)}"
    "weibo" -> "https://weibo.com/${encodeUserSegment(user)}"
    "xiaohongshu" -> "https://www.xiaohongshu.com/user/profile/${encodeUserSegment(user)}"
    "xda" -> "https://xdaforums.com/m/${encodeUserSegment(user)}/"
    "youtube" -> "https://www.youtube.com/@${encodeUserSegment(user)}"
    "afdian" -> "https://afdian.com/a/${encodeUserSegment(user)}"
    "twitter", "x" -> "https://x.com/${encodeUserSegment(user)}"
    "zhihu" -> "https://www.zhihu.com/people/${encodeUserSegment(user)}"
    "threads" -> "https://www.threads.net/@${encodeUserSegment(user)}"
    "douyin" -> "https://www.douyin.com/search/${encodeUserSegment(user)}"
    else -> null
}

/**
 * Resolves a parsed `@site` or `username@platform` token to its target URL.
 * Returns null for plain text, unknown platforms and email-like tokens.
 */
internal fun themeMentionUrl(token: String): String? {
    if (token.startsWith("@")) {
        val site = token.substring(1).lowercase(Locale.ROOT)
        return THEME_SITE_MENTIONS[site]
    }
    val split = token.lastIndexOf('@')
    if (split <= 0) return null
    val user = token.substring(0, split)
    val platform = token.substring(split + 1).lowercase(Locale.ROOT)
    if (platform !in THEME_SITE_MENTIONS) return null
    return userMentionUrl(user, platform)
}

private val FENCED_CODE = Regex("```[\\s\\S]*?```")

private fun AnnotatedString.Builder.appendInlineMarkdown(
    text: String,
    linkColor: Color,
    linkStyles: TextLinkStyles,
    codeColor: Color,
    codeBackground: Color,
) {
    var cursor = 0
    INLINE_MARKDOWN.findAll(text).forEach { match ->
        if (match.range.first > cursor) {
            append(text.substring(cursor, match.range.first))
        }
        val token = match.value
        when {
            token.startsWith("**") && token.length > 4 -> withStyle(
                SpanStyle(fontWeight = FontWeight.SemiBold),
            ) {
                append(token.substring(2, token.length - 2))
            }

            token.startsWith("`") && token.length > 2 -> withStyle(
                SpanStyle(
                    fontFamily = FontFamily.Monospace,
                    color = codeColor,
                    background = codeBackground,
                ),
            ) {
                append(token.substring(1, token.length - 1))
            }

            token.startsWith("[") -> {
                val split = token.indexOf("](")
                if (split > 1) {
                    val label = token.substring(1, split)
                    val url = token.substring(split + 2, token.length - 1)
                    withLink(LinkAnnotation.Url(url, linkStyles)) {
                        append(label)
                    }
                } else {
                    append(token)
                }
            }

            token.startsWith("http://") || token.startsWith("https://") -> {
                withLink(LinkAnnotation.Url(token, linkStyles)) {
                    append(token)
                }
            }

            token.startsWith("@") || token.contains('@') -> {
                val url = themeMentionUrl(token)
                if (url != null) {
                    withLink(LinkAnnotation.Url(url, linkStyles)) {
                        append(token)
                    }
                } else {
                    // Local account mention: highlight it so it reads as a tag.
                    withStyle(
                        SpanStyle(
                            color = linkColor,
                            fontWeight = FontWeight.SemiBold,
                        ),
                    ) {
                        append(token)
                    }
                }
            }

            token.startsWith("*") && token.length > 2 -> withStyle(
                SpanStyle(fontStyle = FontStyle.Italic),
            ) {
                append(token.substring(1, token.length - 1))
            }

            else -> append(token)
        }
        cursor = match.range.last + 1
    }
    if (cursor < text.length) {
        append(text.substring(cursor))
    }
}


@Composable
internal fun themeStoreMarkdown(text: String): AnnotatedString {
    val linkColor = MaterialTheme.colorScheme.primary
    val codeColor = MaterialTheme.colorScheme.onSurface
    val codeBackground = MaterialTheme.colorScheme.surfaceContainerHigh
    val linkStyles = remember(linkColor) {
        TextLinkStyles(
            style = SpanStyle(
                color = linkColor,
                textDecoration = TextDecoration.Underline,
            ),
        )
    }
    return remember(text, linkStyles, codeColor, codeBackground, linkColor) {
        buildAnnotatedString {
            var cursor = 0
            FENCED_CODE.findAll(text).forEach { match ->
                if (match.range.first > cursor) {
                    appendInlineMarkdown(
                        text = text.substring(cursor, match.range.first),
                        linkColor = linkColor,
                        linkStyles = linkStyles,
                        codeColor = codeColor,
                        codeBackground = codeBackground,
                    )
                }
                val body = match.value
                    .removePrefix("```")
                    .removeSuffix("```")
                    .trim('\n')
                if (length > 0) append('\n')
                withStyle(
                    SpanStyle(
                        fontFamily = FontFamily.Monospace,
                        color = codeColor,
                        background = codeBackground,
                    ),
                ) {
                    append(body)
                }
                append('\n')
                cursor = match.range.last + 1
            }
            if (cursor < text.length) {
                appendInlineMarkdown(
                    text = text.substring(cursor),
                    linkColor = linkColor,
                    linkStyles = linkStyles,
                    codeColor = codeColor,
                    codeBackground = codeBackground,
                )
            }
        }
    }
}
