package com.sukisu.ultra.ui.screen.themestore

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.R
import java.util.Locale

/** Canonical tag used by the catalog and the upload form for adaptive light/dark themes. */
internal const val ADAPTIVE_TAG = "adaptive"

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

/** Maps any known spelling of a special tag to its canonical catalog key. */
internal fun canonicalThemeTag(tag: String): String {
    val normalized = tag.trim().lowercase(Locale.ROOT)
    return if (normalized in ADAPTIVE_TAG_ALIASES) ADAPTIVE_TAG else normalized
}

internal fun isAdaptiveThemeTag(tag: String): Boolean = canonicalThemeTag(tag) == ADAPTIVE_TAG

/** An entry is adaptive when the catalog says so or when any of its tags is an adaptive alias. */
internal fun ThemeStoreItem.isAdaptiveTheme(): Boolean =
    entry.adaptive || entry.tags.any(::isAdaptiveThemeTag)

@Composable
internal fun themeTagLabel(tag: String): String =
    if (isAdaptiveThemeTag(tag)) stringResource(R.string.theme_adaptive_tag) else tag

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

/** All catalog entries by one author, matched case-insensitively and ignoring padding. */
internal fun List<ThemeStoreItem>.forThemeAuthor(author: String): List<ThemeStoreItem> {
    val normalized = author.trim()
    if (normalized.isEmpty()) return emptyList()
    return filter { it.entry.author.trim().equals(normalized, ignoreCase = true) }
}
