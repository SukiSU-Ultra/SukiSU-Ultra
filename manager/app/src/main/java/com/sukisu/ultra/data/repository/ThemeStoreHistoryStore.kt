package com.sukisu.ultra.data.repository

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

enum class ThemeStoreHistoryKind(val key: String) {
    VIEWED("viewed"),
    DOWNLOADED("downloaded"),
}

data class ThemeStoreHistoryEntry(
    val key: String,
    val themeId: String,
    val name: String,
    val author: String,
    val sourceId: String,
    val baseUrl: String,
    val previewPath: String,
    val createdAt: Long,
    val r18: Boolean = false,
    val adaptive: Boolean = false,
)

/** Local, account-independent history for the manager theme store. */
class ThemeStoreHistoryStore(context: Context) {
    private companion object {
        const val PREFS = "theme_store_history"
        const val MAX_ENTRIES = 100
    }

    private val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun read(kind: ThemeStoreHistoryKind): List<ThemeStoreHistoryEntry> {
        val raw = prefs.getString(kind.key, null) ?: return emptyList()
        return runCatching {
            val array = JSONArray(raw)
            buildList {
                for (index in 0 until array.length()) {
                    val item = array.optJSONObject(index) ?: continue
                    val entry = decode(item) ?: continue
                    add(entry)
                }
            }
        }.getOrDefault(emptyList())
    }

    fun record(kind: ThemeStoreHistoryKind, entry: ThemeStoreHistoryEntry) {
        val entries = read(kind).filterNot { it.key == entry.key }
        val next = (listOf(entry) + entries).take(MAX_ENTRIES)
        write(kind, next)
    }

    fun remove(kind: ThemeStoreHistoryKind, keys: Set<String>) {
        if (keys.isEmpty()) return
        write(kind, read(kind).filterNot { it.key in keys })
    }

    fun clear(kind: ThemeStoreHistoryKind) {
        prefs.edit().remove(kind.key).apply()
    }

    private fun write(kind: ThemeStoreHistoryKind, entries: List<ThemeStoreHistoryEntry>) {
        val array = JSONArray()
        entries.forEach { array.put(encode(it)) }
        prefs.edit().putString(kind.key, array.toString()).apply()
    }

    private fun decode(item: JSONObject): ThemeStoreHistoryEntry? {
        val key = item.optString("key")
        val themeId = item.optString("themeId")
        if (key.isBlank() || themeId.isBlank()) return null
        return ThemeStoreHistoryEntry(
            key = key,
            themeId = themeId,
            name = item.optString("name"),
            author = item.optString("author"),
            sourceId = item.optString("sourceId"),
            baseUrl = item.optString("baseUrl"),
            previewPath = item.optString("previewPath"),
            createdAt = item.optLong("createdAt", 0L),
            r18 = item.optBoolean("r18", false),
            adaptive = item.optBoolean("adaptive", false),
        )
    }

    private fun encode(entry: ThemeStoreHistoryEntry): JSONObject = JSONObject().apply {
        put("key", entry.key)
        put("themeId", entry.themeId)
        put("name", entry.name)
        put("author", entry.author)
        put("sourceId", entry.sourceId)
        put("baseUrl", entry.baseUrl)
        put("previewPath", entry.previewPath)
        put("createdAt", entry.createdAt)
        put("r18", entry.r18)
        put("adaptive", entry.adaptive)
    }
}
