package com.sukisu.ultra.ui.screen.themestore

import java.util.Locale

/**
 * Most-used tags across the aggregated catalog, preserving the first spelling seen for each
 * case-insensitive tag. Used for the quick tag filters on the store home.
 */
internal fun List<ThemeStoreItem>.popularThemeTags(limit: Int = 18): List<String> {
    if (limit <= 0) return emptyList()
    val tags = linkedMapOf<String, Pair<String, Int>>()
    for (item in this) {
        for (raw in item.entry.tags) {
            val display = raw.trim()
            if (display.isEmpty() || display.length > 24) continue
            val key = display.lowercase(Locale.ROOT)
            val previous = tags[key]
            tags[key] = (previous?.first ?: display) to ((previous?.second ?: 0) + 1)
        }
    }
    return tags.values
        .sortedWith(
            compareByDescending<Pair<String, Int>> { it.second }
                .thenBy { it.first.lowercase(Locale.ROOT) },
        )
        .take(limit)
        .map { it.first }
}

/**
 * Keeps themes matching any selected tag, so selecting several tags produces a mixed feed
 * rather than an empty intersection.
 */
internal fun List<ThemeStoreItem>.filterByThemeTags(selected: Set<String>): List<ThemeStoreItem> {
    if (selected.isEmpty()) return this
    val keys = selected.mapTo(mutableSetOf()) { it.trim().lowercase(Locale.ROOT) }
    if (keys.isEmpty()) return this
    return filter { item ->
        item.entry.tags.any { it.trim().lowercase(Locale.ROOT) in keys }
    }
}

/** All catalog entries by one author, matched case-insensitively and ignoring padding. */
internal fun List<ThemeStoreItem>.forThemeAuthor(author: String): List<ThemeStoreItem> {
    val normalized = author.trim()
    if (normalized.isEmpty()) return emptyList()
    return filter { it.entry.author.trim().equals(normalized, ignoreCase = true) }
}
