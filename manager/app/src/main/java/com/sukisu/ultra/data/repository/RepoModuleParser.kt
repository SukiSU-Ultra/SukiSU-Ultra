package com.sukisu.ultra.data.repository

import com.sukisu.ultra.data.model.Author
import com.sukisu.ultra.data.model.MmrlModuleInfo
import com.sukisu.ultra.data.model.MmrlVersion
import com.sukisu.ultra.data.model.RepoModule
import com.sukisu.ultra.data.model.ReleaseAsset
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

enum class RepoFormat {
    KERNELSU,
    MMRL,
}

/**
 * Parses the two module repository index formats:
 *  - KERNELSU: a top-level JSON array of modules (legacy modules.kernelsu.org format)
 *  - MMRL: a top-level JSON object with a "modules" array (MMRL repository format)
 */
object RepoModuleParser {

    private val ISO_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC)

    fun sniffFormat(body: String): RepoFormat? {
        val trimmed = body.trimStart('\uFEFF', ' ', '\n', '\r', '\t')
        return when {
            trimmed.startsWith("[") -> RepoFormat.KERNELSU
            trimmed.startsWith("{") && trimmed.contains("\"modules\"") -> RepoFormat.MMRL
            else -> null
        }
    }

    fun parse(body: String, sourceId: String, sourceName: String): List<RepoModule> {
        return when (sniffFormat(body)) {
            RepoFormat.KERNELSU -> parseKsu(body, sourceId, sourceName)
            RepoFormat.MMRL -> parseMmrl(body, sourceId, sourceName)
            null -> throw IllegalArgumentException("Unrecognized repository format")
        }
    }

    fun parseKsu(body: String, sourceId: String = "", sourceName: String = ""): List<RepoModule> {
        val json = JSONArray(body)
        return (0 until json.length()).mapNotNull { idx ->
            val item = json.optJSONObject(idx) ?: return@mapNotNull null
            parseKsuModule(item, sourceId, sourceName)
        }
    }

    fun parseMmrl(body: String, sourceId: String, sourceName: String): List<RepoModule> {
        val root = JSONObject(body)
        val modules = root.optJSONArray("modules") ?: return emptyList()
        return (0 until modules.length()).mapNotNull { idx ->
            val item = modules.optJSONObject(idx) ?: return@mapNotNull null
            parseMmrlModule(item, sourceId, sourceName)
        }
    }

    private fun parseKsuModule(item: JSONObject, sourceId: String, sourceName: String): RepoModule? {
        val moduleId = item.optString("moduleId", "")
        if (moduleId.isEmpty()) return null
        val moduleName = item.optString("moduleName", "")
        val authorsArray = item.optJSONArray("authors")
        val authorList = if (authorsArray != null) {
            (0 until authorsArray.length())
                .mapNotNull { idx ->
                    val authorObj = authorsArray.optJSONObject(idx) ?: return@mapNotNull null
                    val name = authorObj.optString("name", "").trim()
                    var link = authorObj.optString("link", "").trim()
                    if (link.startsWith("`") && link.endsWith("`") && link.length >= 2) {
                        link = link.substring(1, link.length - 1)
                    }
                    if (name.isEmpty()) null else Author(name = name, link = link)
                }
        } else {
            emptyList()
        }
        val authors = if (authorList.isNotEmpty()) authorList.joinToString(", ") { it.name } else item.optString("authors", "")
        val summary = item.optString("summary", "")
        val metamodule = item.optBoolean("metamodule", false)
        val zygisk = item.optBoolean("zygisk", false)
        val stargazerCount = item.optInt("stargazerCount", 0)
        val updatedAt = item.optString("updatedAt", "")
        val createdAt = item.optString("createdAt", "")

        var latestRelease = ""
        var latestReleaseTime = ""
        var latestVersionCode = 0L
        var latestAsset: ReleaseAsset? = null
        val lr = item.optJSONObject("latestRelease")
        if (lr != null) {
            val lrName = lr.optString("name", lr.optString("version", ""))
            val lrTime = lr.optString("time", "")
            val lrUrl = stripTicks(lr.optString("downloadUrl", "")).trim()

            latestVersionCode = optLongValue(lr, "versionCode")
            latestRelease = lrName
            latestReleaseTime = lrTime
            if (lrUrl.isNotEmpty()) {
                val fileName = lrUrl.substringAfterLast('/')
                latestAsset = ReleaseAsset(name = fileName, downloadUrl = lrUrl, size = 0L)
            }
        }

        return RepoModule(
            moduleId = moduleId,
            moduleName = moduleName,
            authors = authors,
            authorList = authorList,
            summary = summary,
            metamodule = metamodule,
            zygisk = zygisk,
            stargazerCount = stargazerCount,
            updatedAt = updatedAt,
            createdAt = createdAt,
            latestRelease = latestRelease,
            latestReleaseTime = latestReleaseTime,
            latestVersionCode = latestVersionCode,
            latestAsset = latestAsset,
            sourceId = sourceId,
            sourceName = sourceName,
        )
    }

    private fun parseMmrlModule(item: JSONObject, sourceId: String, sourceName: String): RepoModule? {
        val moduleId = item.optString("id", "").trim()
        if (moduleId.isEmpty()) return null
        val moduleName = item.optString("name", "")
        val summary = item.optString("description", "")
        val author = item.optString("author", "").trim()

        val versionsJson = item.optJSONArray("versions") ?: JSONArray()
        val versions = (0 until versionsJson.length()).mapNotNull { idx ->
            val v = versionsJson.optJSONObject(idx) ?: return@mapNotNull null
            val zipUrl = stripTicks(v.optString("zipUrl", "")).trim()
            if (zipUrl.isEmpty()) return@mapNotNull null
            val timestamp = optSecondsValue(v, "timestamp")
            MmrlVersion(
                version = v.optString("version", ""),
                versionCode = optLongValue(v, "versionCode"),
                timestamp = timestamp,
                time = epochToIso(timestamp),
                zipUrl = zipUrl,
                changelogUrl = stripTicks(v.optString("changelog", "")).trim().ifEmpty { null },
                size = optLongValue(v, "size"),
            )
        }.sortedWith(compareByDescending<MmrlVersion> { it.versionCode }.thenByDescending { it.timestamp })

        val latest = versions.firstOrNull()
        val latestTime = epochToIso(latest?.timestamp ?: 0L).ifEmpty {
            epochToIso(optSecondsValue(item, "timestamp"))
        }

        return RepoModule(
            moduleId = moduleId,
            moduleName = moduleName,
            authors = author,
            authorList = if (author.isEmpty()) emptyList() else listOf(Author(name = author, link = "")),
            summary = summary,
            metamodule = false,
            zygisk = false,
            stargazerCount = 0,
            updatedAt = latestTime,
            createdAt = "",
            latestRelease = latest?.version ?: "",
            latestReleaseTime = latestTime,
            latestVersionCode = latest?.versionCode ?: 0L,
            latestAsset = latest?.let {
                ReleaseAsset(name = it.zipUrl.substringAfterLast('/'), downloadUrl = it.zipUrl, size = it.size)
            },
            sourceId = sourceId,
            sourceName = sourceName,
            mmrl = MmrlModuleInfo(
                readmeUrl = stripTicks(item.optString("readme", "")).trim().ifEmpty { null },
                supportUrl = stripTicks(item.optString("support", "")).trim().ifEmpty { null },
                versions = versions,
            ),
        )
    }

    private fun stripTicks(s: String): String {
        val t = s.trim()
        return if (t.startsWith("`") && t.endsWith("`") && t.length >= 2) t.substring(1, t.length - 1) else t
    }

    private fun optLongValue(obj: JSONObject, key: String): Long {
        val value = obj.opt(key) ?: return 0L
        return when (value) {
            is Number -> value.toLong()
            is String -> value.trim().toLongOrNull() ?: 0L
            else -> 0L
        }
    }

    private fun optSecondsValue(obj: JSONObject, key: String): Long {
        val value = obj.opt(key) ?: return 0L
        return when (value) {
            is Number -> value.toDouble().toLong()
            is String -> value.trim().toDoubleOrNull()?.toLong() ?: 0L
            else -> 0L
        }
    }

    private fun epochToIso(seconds: Long): String {
        if (seconds <= 0L) return ""
        return ISO_FORMAT.format(Instant.ofEpochSecond(seconds))
    }
}
