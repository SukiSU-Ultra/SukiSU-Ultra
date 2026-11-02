package com.sukisu.ultra.ui.screen.themestore

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
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
)

private val INLINE_MARKDOWN = Regex(
    """\*\*[^*\n]+\*\*|`[^`\n]+`|\[[^]\n]+]\(https?://[^\s)]+\)|[A-Za-z0-9._-]+@(?:github|gitee|bilibili|coolapk|telegram|weibo|xiaohongshu|xda|youtube|afdian)(?![\w.-]*\.)|(?<![\w@])@[A-Za-z0-9_-]+|https?://[^s]+|\*[^*\n]+\*""",
    RegexOption.IGNORE_CASE,
)

private val THEME_USER_MENTIONS = setOf(
    "github", "gitee", "bilibili", "coolapk", "telegram",
    "weibo", "xiaohongshu", "xda", "youtube", "afdian",
)

private fun userMentionUrl(user: String, platform: String): String? = when (platform.lowercase()) {
    "github" -> "https://github.com/$user"
    "gitee" -> "https://gitee.com/$user"
    "bilibili" -> if (user.all(Char::isDigit)) "https://space.bilibili.com/$user"
    else "https://search.bilibili.com/all?keyword=$user"
    "coolapk" -> "https://www.coolapk.com/u/$user"
    "telegram" -> "https://t.me/$user"
    "weibo" -> "https://weibo.com/$user"
    "xiaohongshu" -> "https://www.xiaohongshu.com/user/profile/$user"
    "xda" -> "https://xdaforums.com/m/$user/"
    "youtube" -> "https://www.youtube.com/@$user"
    "afdian" -> "https://afdian.com/a/$user"
    else -> null
}

/** Small inline Markdown renderer for theme descriptions shown in cards. */
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
    return remember(text, linkStyles, codeColor, codeBackground) {
        buildAnnotatedString {
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

                    token.startsWith("@") -> {
                        val site = token.substring(1).lowercase()
                        val url = THEME_SITE_MENTIONS[site]
                        if (url != null) {
                            withLink(LinkAnnotation.Url(url, linkStyles)) {
                                append(token)
                            }
                        } else {
                            append(token)
                        }
                    }

                    token.contains('@') -> {
                        val split = token.lastIndexOf('@')
                        val user = token.substring(0, split)
                        val platform = token.substring(split + 1).lowercase()
                        val url = if (platform in THEME_USER_MENTIONS) userMentionUrl(user, platform) else null
                        if (url != null) {
                            withLink(LinkAnnotation.Url(url, linkStyles)) {
                                append(token)
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
    }
}
