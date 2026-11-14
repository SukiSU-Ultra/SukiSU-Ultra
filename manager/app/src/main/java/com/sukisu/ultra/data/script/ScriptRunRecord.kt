package com.sukisu.ultra.data.script

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json


@Serializable
data class ScriptRunRecord(
    val id: String,
    val versionCode: Int? = null,
    
    val time: Long,
    val exitCode: Int,
) {
    val outcome: ScriptOutcome get() = ScriptOutcome.of(exitCode)

    fun encode(): String = JSON.encodeToString(serializer(), this)

    companion object {
        private val JSON = Json { ignoreUnknownKeys = true }

        
        fun decode(text: String?, id: String): ScriptRunRecord? =
            text?.let { runCatching { JSON.decodeFromString(serializer(), it) }.getOrNull() }?.takeIf { it.id == id }
    }
}


interface ScriptRunStorage {
    fun read(key: String): String?
    fun write(key: String, value: String)
}

class ScriptRunHistory(private val storage: ScriptRunStorage) {
    fun last(id: String): ScriptRunRecord? = ScriptRunRecord.decode(storage.read(KEY_PREFIX + id), id)

    fun record(record: ScriptRunRecord) = storage.write(KEY_PREFIX + record.id, record.encode())

    private companion object {
        const val KEY_PREFIX = "last_run:"
    }
}
