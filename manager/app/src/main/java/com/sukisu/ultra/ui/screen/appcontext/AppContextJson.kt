package com.sukisu.ultra.ui.screen.appcontext

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** Versioned ksud wire format. No dependency on Android or CLI presentation text. */
internal object AppContextJson {
    private val json = Json { ignoreUnknownKeys = true }

    @Serializable
    private data class Snapshot(val version: Int, val entries: List<Record>)

    @Serializable
    private data class Record(
        val uid: Long,
        val foreground: Boolean,
        @SerialName("profile_id") val profileId: Long,
        val tags: String,
        @SerialName("last_update_ns") val lastUpdateNs: String,
    )

    fun decode(text: String): List<AppContextEntry> {
        val snapshot = json.decodeFromString<Snapshot>(text)
        require(snapshot.version == 1) { "Unsupported App Context JSON version" }
        require(snapshot.entries.size <= 512) { "Too many App Context records" }
        val seen = HashSet<Long>()
        return snapshot.entries.map { record ->
            require(record.uid in 0..0xffffffffL && seen.add(record.uid)) { "Invalid or duplicate UID" }
            require(record.profileId in 0..0xffffffffL) { "Invalid profile ID" }
            require(record.tags.matches(Regex("0x[0-9a-fA-F]{16}"))) { "Invalid tag mask" }
            val timestamp = record.lastUpdateNs.toULong()
            AppContextEntry(
                uid = record.uid,
                foreground = record.foreground,
                profileId = record.profileId,
                tags = record.tags.removePrefix("0x").toULong(16).toLong(),
                lastUpdateNs = timestamp.toString(),
            )
        }.sortedWith(compareByDescending<AppContextEntry> { it.foreground }.thenBy { it.uid })
    }
}
