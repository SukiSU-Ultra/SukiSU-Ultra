package com.sukisu.ultra.ui.screen.themestore

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.R
import java.util.Locale


internal const val ADAPTIVE_TAG = "adaptive"

/// Store cards rendered per page; preview images load lazily as pages are opened.
internal const val STORE_PAGE_SIZE = 10

private val ADAPTIVE_TAG_ALIASES = setOf(
    "adaptive",
    "auto",
    "automatic",
    "lightdark",
    "light/dark",
    "自适应",
    "自适应主题",
    "自适应主题包",
)


internal fun canonicalThemeTag(tag: String): String {
    val normalized = tag.trim().lowercase(Locale.ROOT)
    return if (normalized in ADAPTIVE_TAG_ALIASES) ADAPTIVE_TAG else normalized
}

internal fun isAdaptiveThemeTag(tag: String): Boolean = canonicalThemeTag(tag) == ADAPTIVE_TAG


internal fun ThemeStoreItem.isAdaptiveTheme(): Boolean =
    entry.adaptive || entry.tags.any(::isAdaptiveThemeTag)

internal const val R18_TAG = "r18"

private val R18_TAGS = setOf(
    R18_TAG,
    "r-18",
    "18+",
    "nsfw",
    "adult",
    "成人",
    "成人向",
    "限制级",
)

/**
 * The catalog carries an explicit `r18` flag, but older mirrors may only have the tag. Keep the
 * tag fallback so hiding adult themes works before the catalog is rebuilt.
 */
internal fun ThemeStoreItem.isR18Theme(): Boolean =
    entry.r18 || entry.tags.any { it.trim().lowercase(Locale.ROOT) in R18_TAGS }

@Composable
internal fun themeTagLabel(tag: String): String = when {
    isAdaptiveThemeTag(tag) -> stringResource(R.string.theme_adaptive_tag)
    canonicalThemeTag(tag) == R18_TAG -> stringResource(R.string.theme_store_r18)
    else -> tag
}

/**
 * Most-used tags across the aggregated catalog, preserving the first spelling seen for each
 * case-insensitive tag. Adaptive aliases collapse into the canonical "adaptive" key, which is
 * always offered as the first quick filter on the store home.
 */
internal fun List<ThemeStoreItem>.popularThemeTags(limit: Int = 18): List<String> {
    if (limit <= 0) return emptyList()
    val tags = linkedMapOf<String, Pair<String, Int>>()
    for ((entry) in this) {
        for (raw in entry.tags) {
            val display = raw.trim()
            if (display.isEmpty() || display.length > 24) continue
            val canonical = canonicalThemeTag(display)
            val key = canonical.lowercase(Locale.ROOT)
            val shown = if (canonical == ADAPTIVE_TAG) ADAPTIVE_TAG else display
            val previous = tags[key]
            tags[key] = (previous?.first ?: shown) to ((previous?.second ?: 0) + 1)
        }
    }
    val ranked = tags.values
        .sortedWith(
            compareByDescending<Pair<String, Int>> { it.second }
                .thenBy { it.first.lowercase(Locale.ROOT) },
        )
        .map { it.first }
    return (listOf(ADAPTIVE_TAG) + ranked.filterNot { isAdaptiveThemeTag(it) }).take(limit)
}

/**
 * Keeps themes matching any selected tag, so selecting several tags produces a mixed feed
 * rather than an empty intersection. The adaptive filter also matches the catalog's explicit
 * adaptive flag, since older mirrors may not have written the tag yet.
 */
internal fun List<ThemeStoreItem>.filterByThemeTags(selected: Set<String>): List<ThemeStoreItem> {
    if (selected.isEmpty()) return this
    val keys = selected.mapTo(mutableSetOf()) { canonicalThemeTag(it) }
    if (keys.isEmpty()) return this
    val wantsAdaptive = ADAPTIVE_TAG in keys
    return filter { item ->
        (wantsAdaptive && item.isAdaptiveTheme()) ||
            item.entry.tags.any { canonicalThemeTag(it) in keys }
    }
}


internal fun List<ThemeStoreItem>.forThemeAuthor(author: String): List<ThemeStoreItem> {
    val normalized = author.trim()
    if (normalized.isEmpty()) return emptyList()
    return filter { it.entry.author.trim().equals(normalized, ignoreCase = true) }
}

/**
 * Follows are stored per mirror and author identity. An empty result means the catalog entry has
 * no stable author hash (legacy packages), so the UI hides the follow action for it.
 */
internal fun themeFollowKey(baseUrl: String, authorHash: String): String =
    if (authorHash.isBlank()) "" else "${baseUrl.trimEnd('/')}|${authorHash.trim()}"

internal fun ThemeStoreItem.followKey(): String =
    themeFollowKey(source.baseUrl, entry.authorHash)

/**
 * Stable partition that keeps the active sort order inside both the followed and unfollowed
 * groups, so following an author lifts their themes without scrambling the chosen sort.
 */
internal fun List<ThemeStoreItem>.followedFirst(followedKeys: Set<String>): List<ThemeStoreItem> {
    if (followedKeys.isEmpty()) return this
    return sortedWith(
        compareByDescending { item ->
            item.followKey().isNotEmpty() && item.followKey() in followedKeys
        },
    )
}
