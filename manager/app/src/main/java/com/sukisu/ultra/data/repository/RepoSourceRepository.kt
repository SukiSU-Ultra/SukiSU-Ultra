package com.sukisu.ultra.data.repository

import android.content.Context
import android.content.SharedPreferences
import com.sukisu.ultra.ksuApp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

data class RepoSource(
    val id: String,
    val name: String,
    val url: String,
    val enabled: Boolean = true,
)

interface RepoSourceRepository {
    fun loadSources(): List<RepoSource>

    /**
     * Probes [rawUrl] candidate endpoints, persists the first reachable module
     * index and returns it. Fails with a user-displayable message otherwise.
     */
    suspend fun addSource(rawUrl: String, name: String? = null): Result<RepoSource>

    fun removeSource(id: String)
    fun setSourceEnabled(id: String, enabled: Boolean)
    fun renameSource(id: String, name: String)

    companion object {
        const val DEFAULT_SOURCE_NAME = "KernelSU"
        const val DEFAULT_SOURCE_URL = "https://modules.kernelsu.org"
    }
}

class RepoSourceRepositoryImpl(
    private val prefs: SharedPreferences = ksuApp.getSharedPreferences("settings", Context.MODE_PRIVATE),
    private val httpClient: OkHttpClient = ksuApp.okhttpClient,
) : RepoSourceRepository {

    companion object {
        private const val KEY_SOURCES = "repo_sources"
        private const val CONNECT_TIMEOUT_SECONDS = 15L
        private const val READ_TIMEOUT_SECONDS = 20L
    }

    override fun loadSources(): List<RepoSource> {
        val raw = prefs.getString(KEY_SOURCES, null) ?: return defaultSources()
        return runCatching {
            decode(raw)
        }.getOrNull() ?: defaultSources()
    }

    override suspend fun addSource(rawUrl: String, name: String?): Result<RepoSource> = withContext(Dispatchers.IO) {
        runCatching {
            val trimmed = rawUrl.trim()
            require(trimmed.isNotEmpty()) { ksuApp.getString(com.sukisu.ultra.R.string.module_repo_source_bad_url) }
            val candidates = candidateSourceUrls(trimmed)
            require(candidates.isNotEmpty()) { ksuApp.getString(com.sukisu.ultra.R.string.module_repo_source_bad_url) }

            val existing = loadSources()
            val inputCandidates = (candidateSourceUrls(trimmed) + trimmed)
                .map { it.trimEnd('/').lowercase() }.toSet()
            require(existing.none { source ->
                val candidates = (candidateSourceUrls(source.url) + source.url)
                    .map { it.trimEnd('/').lowercase() }
                candidates.any { it in inputCandidates }
            }) {
                ksuApp.getString(com.sukisu.ultra.R.string.module_repo_source_duplicate)
            }

            val client = httpClient.newBuilder()
                .connectTimeout(java.time.Duration.ofSeconds(CONNECT_TIMEOUT_SECONDS))
                .readTimeout(java.time.Duration.ofSeconds(READ_TIMEOUT_SECONDS))
                .build()

            var resolvedUrl: String? = null
            var lastError: String = ""
            for (candidate in candidates) {
                try {
                    val request = Request.Builder().url(candidate).build()
                    client.newCall(request).execute().use { response ->
                        if (response.isSuccessful) {
                            val body = response.body.string()
                            if (RepoModuleParser.sniffFormat(body) != null) {
                                resolvedUrl = candidate
                            } else {
                                lastError = "unrecognized format"
                            }
                        } else {
                            lastError = "HTTP ${response.code}"
                        }
                    }
                } catch (e: kotlin.coroutines.cancellation.CancellationException) {
                    throw e
                } catch (e: Exception) {
                    lastError = e.message ?: e.javaClass.simpleName
                }
                if (resolvedUrl != null) break
            }

            val url = resolvedUrl
            if (url == null) {
                throw IllegalStateException(
                    ksuApp.getString(com.sukisu.ultra.R.string.module_repo_source_unreachable) + if (lastError.isEmpty()) "" else " ($lastError)"
                )
            }

            val source = RepoSource(
                id = UUID.randomUUID().toString(),
                name = (name?.takeIf { it.isNotBlank() } ?: hostOf(url)),
                url = url,
            )
            save(existing + source)
            source
        }
    }

    override fun removeSource(id: String) = mutate { it.filterNot { s -> s.id == id } }

    override fun setSourceEnabled(id: String, enabled: Boolean) =
        mutate { list -> list.map { if (it.id == id) it.copy(enabled = enabled) else it } }

    override fun renameSource(id: String, name: String) =
        mutate { list -> list.map { if (it.id == id) it.copy(name = name) else it } }

    private fun mutate(transform: (List<RepoSource>) -> List<RepoSource>) {
        save(transform(loadSources()))
    }

    private fun save(sources: List<RepoSource>) {
        val array = JSONArray()
        sources.forEach { source ->
            array.put(
                JSONObject()
                    .put("id", source.id)
                    .put("name", source.name)
                    .put("url", source.url)
                    .put("enabled", source.enabled)
            )
        }
        prefs.edit().putString(KEY_SOURCES, array.toString()).apply()
    }

    private fun decode(raw: String): List<RepoSource> {
        val array = JSONArray(raw)
        return (0 until array.length()).mapNotNull { idx ->
            val item = array.optJSONObject(idx) ?: return@mapNotNull null
            val url = item.optString("url", "").trim()
            val id = item.optString("id", "").ifBlank { UUID.randomUUID().toString() }
            if (url.isEmpty()) return@mapNotNull null
            RepoSource(
                id = id,
                name = item.optString("name", "").ifBlank { hostOf(url) },
                url = url,
                enabled = item.optBoolean("enabled", true),
            )
        }
    }

    private fun defaultSources(): List<RepoSource> = listOf(
        RepoSource(
            id = "kernelsu-official",
            name = RepoSourceRepository.DEFAULT_SOURCE_NAME,
            url = RepoSourceRepository.DEFAULT_SOURCE_URL,
        )
    )
}

/**
 * Builds the candidate module index URLs for a user-provided address:
 *  - a URL already pointing at a .json file is used as-is
 *  - otherwise the MMRL convention (<base>/json/modules.json) is tried first,
 *    then the KernelSU convention (<base>/modules.json)
 *  - a GitHub repository address also gets its GitHub Pages site tried last, because
 *    <https://github.com/owner/repo> is what people paste while the index is published
 *    at <https://owner.github.io/repo>
 */
fun candidateSourceUrls(raw: String): List<String> {
    val trimmed = raw.trim().trimEnd('/')
    if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) return emptyList()
    if (trimmed.endsWith(".json")) return listOf(trimmed)
    val candidates = mutableListOf("$trimmed/json/modules.json", "$trimmed/modules.json")
    githubPagesBase(trimmed)?.let { pages ->
        candidates += "$pages/json/modules.json"
        candidates += "$pages/modules.json"
    }
    return candidates
}

/** The GitHub Pages base for a bare GitHub repository address, or null for anything else. */
private fun githubPagesBase(url: String): String? {
    val uri = runCatching { java.net.URI(url) }.getOrNull() ?: return null
    if (uri.host?.lowercase() != "github.com") return null
    if (!uri.query.isNullOrEmpty() || !uri.fragment.isNullOrEmpty()) return null

    val segments = uri.path.orEmpty().trim('/').split('/').filter { it.isNotEmpty() }
    if (segments.size != 2) return null
    val owner = segments[0]
    val repo = segments[1].removeSuffix(".git")
    if (owner.isEmpty() || repo.isEmpty()) return null

    return "https://${owner.lowercase()}.github.io/$repo"
}

private fun hostOf(url: String): String {
    return runCatching { java.net.URI(url).host }.getOrNull()
        ?.removePrefix("www.")
        ?.takeIf { it.isNotEmpty() }
        ?: url.substringAfter("://").substringBefore('/')
}
