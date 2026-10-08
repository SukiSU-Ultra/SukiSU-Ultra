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

    /**
     * No source is configured out of the box: the repository the manager used to ship with,
     * `modules.kernelsu.org`, has been gone since the organisation behind it was suspended, and
     * seeding it only made every first launch report a failed fetch. The dialog offers
     * [defaultRepoCandidates] instead.
     */
    override fun loadSources(): List<RepoSource> {
        val raw = prefs.getString(KEY_SOURCES, null) ?: return emptyList()
        return runCatching { decode(raw) }.getOrNull() ?: emptyList()
    }

    override suspend fun addSource(rawUrl: String, name: String?): Result<RepoSource> = withContext(Dispatchers.IO) {
        runCatching {
            val trimmed = rawUrl.trim()
            require(trimmed.isNotEmpty()) { ksuApp.getString(com.sukisu.ultra.R.string.module_repo_source_bad_url) }
            val candidates = candidateSourceUrls(trimmed)
            require(candidates.isNotEmpty()) { ksuApp.getString(com.sukisu.ultra.R.string.module_repo_source_bad_url) }

            val existing = loadSources()
            require(existing.none { source -> isSameSource(source.url, trimmed) }) {
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
                name = (name?.takeIf { it.isNotBlank() } ?: defaultSourceName(url)),
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
                name = item.optString("name", "").ifBlank { defaultSourceName(url) },
                url = url,
                enabled = item.optBoolean("enabled", true),
            )
        }
    }
}

/**
 * Whether [inputUrl] and [existingUrl] address the same module index, so that the same repository
 * cannot be configured twice.
 *
 * Two addresses are the same when one of them resolves to the other's candidates, and — for
 * GitHub-hosted indexes — when they are the same file of the same repository reached by a
 * different route: the Pages address, the raw address and the jsDelivr mirror of one repository
 * are one source, not three.
 */
internal fun isSameSource(existingUrl: String, inputUrl: String): Boolean {
    val existing = (candidateSourceUrls(existingUrl) + existingUrl).map { it.normalizedSourceUrl() }
    val input = (candidateSourceUrls(inputUrl) + inputUrl).map { it.normalizedSourceUrl() }.toSet()
    if (existing.any { it in input }) return true

    val inputIdentity = indexIdentity(inputUrl)
    return inputIdentity != null && inputIdentity == indexIdentity(existingUrl)
}

private fun String.normalizedSourceUrl(): String = trim().trimEnd('/').lowercase()

/**
 * The identity of a GitHub-hosted index file: `github:<owner>/<repo>/<path>`, with the host and
 * the branch left out, so that the same file reached through GitHub Pages, the raw host or
 * jsDelivr compares equal. Null when the address is not a GitHub index file, where no such
 * equivalence is known.
 */
internal fun indexIdentity(url: String): String? {
    val uri = runCatching { java.net.URI(url) }.getOrNull() ?: return null
    val host = uri.host?.lowercase() ?: return null
    val segments = uri.path.orEmpty().trim('/').split('/').filter { it.isNotEmpty() }

    val slug: String
    val path: List<String>
    when {
        host == "raw.githubusercontent.com" && segments.size >= 3 -> {
            // owner/repo/<ref>/<path>
            slug = "${segments[0]}/${segments[1]}"
            path = segments.drop(3)
        }

        host == "github.com" && segments.size >= 2 -> {
            slug = "${segments[0]}/${segments[1].removeSuffix(".git")}"
            path = if (segments.size >= 4 && segments[2] in REF_SEGMENTS) segments.drop(4) else segments.drop(2)
        }

        host.endsWith(".github.io") && segments.size >= 2 -> {
            slug = "${host.removeSuffix(".github.io")}/${segments[0]}"
            path = segments.drop(1)
        }

        host == "cdn.jsdelivr.net" && segments.size >= 3 && segments[0] == "gh" -> {
            slug = "${segments[1]}/${segments[2].substringBefore('@')}"
            path = segments.drop(3)
        }

        else -> return null
    }

    if (path.isEmpty() || !path.last().endsWith(".json")) return null
    return "github:${slug.lowercase()}/${path.joinToString("/").lowercase()}"
}

/**
 * Builds the candidate module index URLs for a user-provided address:
 *  - a GitHub repository address is tried on its GitHub Pages site first, because that is where
 *    such a repository publishes both its index and its module zips, then inside the repository
 *    itself through the raw file host, and last through the jsDelivr mirror, for networks that
 *    cannot reach raw.githubusercontent.com
 *  - a URL already pointing at a .json file is used as-is
 *  - anything else tries the MMRL convention (<base>/json/modules.json) first, then the KernelSU
 *    convention (<base>/modules.json)
 *
 * `HEAD` is GitHub's alias for the repository's default branch, so neither `main` nor `master` has
 * to be guessed.
 */
fun candidateSourceUrls(raw: String): List<String> {
    val trimmed = raw.trim().trimEnd('/')
    if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) return emptyList()

    // A repository page is recognised before the .json rule below: the address of a file on
    // github.com is an HTML page, not the file, so it has to be resolved through the raw host.
    val repo = githubRepoAddress(trimmed)
        ?: return if (trimmed.endsWith(".json")) {
            listOf(trimmed)
        } else {
            listOf("$trimmed/json/modules.json", "$trimmed/modules.json")
        }

    val ref = repo.ref ?: "HEAD"
    val slug = "${repo.owner}/${repo.repo}"
    val pages = "https://${repo.owner.lowercase()}.github.io/${repo.repo}"
    val pagesCandidates = listOf("$pages/json/modules.json", "$pages/modules.json")
    val rawCandidates = listOf(
        "https://raw.githubusercontent.com/$slug/$ref/json/modules.json",
        "https://raw.githubusercontent.com/$slug/$ref/modules.json",
    )
    val mirrorCandidates = listOf(
        "https://cdn.jsdelivr.net/gh/$slug@$ref/json/modules.json",
        "https://cdn.jsdelivr.net/gh/$slug@$ref/modules.json",
    )
    // GitHub Pages publishes the default branch only, so an address that names a branch has to be
    // read from the raw host to get the branch it asked for.
    return if (repo.ref == null) {
        pagesCandidates + rawCandidates + mirrorCandidates
    } else {
        rawCandidates + pagesCandidates + mirrorCandidates
    }
}

private data class GithubRepoAddress(val owner: String, val repo: String, val ref: String?)

/**
 * Reads a github.com address as owner/repository plus the branch it names, or null when the
 * address is not a repository page — a release asset, an issue list and the like stay untouched.
 * A clone suffix and a `tree`/`blob`/`raw` page are understood; anything deeper is ignored,
 * because the index is looked up by the repository's own layout rather than by the file the
 * address happens to point at.
 */
private fun githubRepoAddress(url: String): GithubRepoAddress? {
    val uri = runCatching { java.net.URI(url) }.getOrNull() ?: return null
    if (uri.host?.lowercase() != "github.com") return null
    if (!uri.query.isNullOrEmpty() || !uri.fragment.isNullOrEmpty()) return null

    val segments = uri.path.orEmpty().trim('/').split('/').filter { it.isNotEmpty() }
    if (segments.size < 2) return null
    val owner = segments[0]
    val repo = segments[1].removeSuffix(".git")
    if (owner.isEmpty() || repo.isEmpty()) return null

    return when {
        segments.size == 2 -> GithubRepoAddress(owner, repo, null)
        segments[2] in REF_SEGMENTS && segments.size >= 4 -> GithubRepoAddress(owner, repo, segments[3])
        else -> null
    }
}

private val REF_SEGMENTS = listOf("tree", "blob", "raw")

private val PAGES_SUFFIXES = listOf(".github.io", ".gitlab.io", ".gitee.io", ".codeberg.page")
private val FORGE_HOSTS =
    listOf("github.com", "raw.githubusercontent.com", "gitlab.com", "gitee.com", "codeberg.org", "bitbucket.org")

/**
 * A readable name for a source the user did not name. Module indexes are published out of a
 * repository, so "owner/repo" identifies the source far better than the host it happens to be
 * served from: `uonou.github.io/mmrl-repo` is really just `uonou/mmrl-repo`. Anything that is
 * not a known forge or Pages site falls back to the bare host.
 */
internal fun defaultSourceName(url: String): String {
    val uri = runCatching { java.net.URI(url) }.getOrNull() ?: return url
    val host = uri.host?.lowercase()?.removePrefix("www.")?.takeIf { it.isNotEmpty() } ?: return url
    val segments = uri.path.orEmpty().trim('/').split('/').filter { it.isNotEmpty() }

    val pages = PAGES_SUFFIXES.firstOrNull { host.endsWith(it) }
    if (pages != null && segments.isNotEmpty()) {
        return "${host.removeSuffix(pages)}/${segments.first()}"
    }
    if (host in FORGE_HOSTS && segments.size >= 2) {
        return "${segments[0]}/${segments[1].removeSuffix(".git")}"
    }
    return host
}
