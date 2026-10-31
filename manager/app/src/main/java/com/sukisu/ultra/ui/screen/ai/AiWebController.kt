package com.sukisu.ultra.ui.screen.ai

import com.sukisu.ultra.data.registry.RegistryUrls
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import okhttp3.OkHttpClient
import okhttp3.Request

data class WebSearchResult(
    val title: String,
    val url: String,
    val snippet: String,
)

data class GithubRepository(
    val fullName: String,
    val url: String,
    val description: String,
    val stars: Int,
    val updatedAt: String,
    val archived: Boolean,
    val topics: List<String>,
)

data class GithubReleaseAsset(
    val name: String,
    val size: Long,
    val url: String,
    val sha256: String?,
)

data class GithubRelease(
    val tag: String,
    val name: String,
    val prerelease: Boolean,
    val draft: Boolean,
    val publishedAt: String,
    val assets: List<GithubReleaseAsset>,
)

data class GithubModuleAsset(
    val repo: String,
    val tag: String,
    val name: String,
    val size: Long,
    val url: String,
    val sha256: String?,
)

/**
 * Web and GitHub discovery used by the assistant. Only read-only HTTP calls
 * are made here; installation is handed to [AiModuleController] after the user
 * approves the resolved release asset.
 */
object AiWebController {

    private const val MAX_BODY = 2 * 1024 * 1024
    private const val USER_AGENT =
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) " +
            "Chrome/124.0.0.0 Mobile Safari/537.36"
    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    fun isGithubReleaseUrl(url: String): Boolean = RegistryUrls.isAllowedReleaseDownloadUrl(url)

    suspend fun searchWeb(query: String, limit: Int = 8): String = withContext(Dispatchers.IO) {
        val cleaned = query.trim()
        require(cleaned.isNotEmpty()) { "query is required" }
        require(cleaned.length <= 200) { "query is too long" }
        val encoded = URLEncoder.encode(cleaned, StandardCharsets.UTF_8.toString())
        val html = fetch("https://html.duckduckgo.com/html/?q=$encoded", "text/html")
        var results = parseDuckDuckGo(html)
        if (results.isEmpty()) {
            val lite = runCatching {
                parseDuckDuckGoLite(
                    fetch("https://lite.duckduckgo.com/lite/?q=$encoded", "text/html")
                )
            }.getOrDefault(emptyList())
            results = lite
        }
        buildJsonObject {
            put("query", cleaned)
            put("results", buildJsonArray {
                results.take(limit.coerceIn(1, 10)).forEach { result ->
                    add(buildJsonObject {
                        put("title", result.title.take(200))
                        put("url", result.url)
                        put("snippet", result.snippet.take(320))
                    })
                }
            })
            if (results.isEmpty()) {
                put(
                    "note",
                    "No web results were parsed. Try github_search with repository keywords, " +
                        "or ask the user to open a browser.",
                )
            }
        }.toString()
    }

    suspend fun searchGithub(query: String, limit: Int = 8): String = withContext(Dispatchers.IO) {
        val cleaned = query.trim()
        require(cleaned.isNotEmpty()) { "query is required" }
        require(cleaned.length <= 200) { "query is too long" }
        val encoded = URLEncoder.encode(cleaned, StandardCharsets.UTF_8.toString())
        val url = "https://api.github.com/search/repositories" +
            "?q=$encoded&sort=stars&order=desc&per_page=${limit.coerceIn(1, 20)}"
        val body = fetch(url, "application/vnd.github+json")
        val root = json.parseToJsonElement(body) as? JsonObject
            ?: throw IllegalStateException("GitHub returned an unexpected response")
        root["message"]?.let { throw IllegalStateException("GitHub: ${it.text()}") }
        val items = root["items"] as? JsonArray ?: JsonArray(emptyList())
        val repos = items.mapNotNull { element ->
            val item = element as? JsonObject ?: return@mapNotNull null
            GithubRepository(
                fullName = item.str("full_name").orEmpty(),
                url = item.str("html_url").orEmpty(),
                description = stripHtml(item.str("description").orEmpty()),
                stars = item.int("stargazers_count") ?: 0,
                updatedAt = item.str("updated_at").orEmpty(),
                archived = item.bool("archived") ?: false,
                topics = (item["topics"] as? JsonArray)
                    ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
                    .orEmpty(),
            )
        }.filter { it.fullName.isNotBlank() }
        buildJsonObject {
            put("query", cleaned)
            put("results", buildJsonArray {
                repos.forEach { repo ->
                    add(buildJsonObject {
                        put("repo", repo.fullName)
                        put("url", repo.url)
                        put("description", repo.description.take(300))
                        put("stars", repo.stars)
                        put("updated_at", repo.updatedAt)
                        put("archived", repo.archived)
                        put("topics", buildJsonArray { repo.topics.take(12).forEach { add(it) } })
                    })
                }
            })
        }.toString()
    }

    suspend fun githubReleases(repo: String, limit: Int = 5): String = withContext(Dispatchers.IO) {
        val releases = fetchGithubReleases(repo)
        buildJsonObject {
            put("repo", repo)
            put("releases", buildJsonArray {
                releases.take(limit.coerceIn(1, 10)).forEach { release ->
                    add(buildJsonObject {
                        put("tag", release.tag)
                        put("name", release.name)
                        put("prerelease", release.prerelease)
                        put("draft", release.draft)
                        put("published_at", release.publishedAt)
                        put("assets", buildJsonArray {
                            release.assets.take(12).forEach { asset ->
                                add(buildJsonObject {
                                    put("name", asset.name)
                                    put("size", asset.size)
                                    put("url", asset.url)
                                    put("sha256", asset.sha256 ?: "")
                                })
                            }
                        })
                    })
                }
            })
        }.toString()
    }

    /**
     * Resolves a repository release to one installable ZIP asset. Prefers the
     * latest stable release unless [version] names a tag.
     */
    suspend fun resolveGithubModule(
        repo: String,
        version: String? = null,
        assetName: String? = null,
    ): GithubModuleAsset = withContext(Dispatchers.IO) {
        val normalizedRepo = normalizeRepo(repo)
        val releases = fetchGithubReleases(normalizedRepo)
        val requested = version?.trim().orEmpty()
        val release = if (requested.isEmpty()) {
            releases.firstOrNull { !it.draft && !it.prerelease }
        } else {
            releases.firstOrNull {
                !it.draft && (it.tag.equals(requested, true) || it.name.equals(requested, true))
            }
        } ?: throw IllegalArgumentException(
            "No stable release '${requested.ifEmpty { "latest" }}' in $normalizedRepo. " +
                "Available: ${releases.filter { !it.draft }.joinToString { it.tag }}"
        )

        val zips = release.assets.filter {
            it.name.endsWith(".zip", true) &&
                !it.name.contains(".sha256", true) &&
                !it.name.contains(".asc", true) &&
                !it.name.contains("source", true)
        }
        val requestedAsset = assetName?.trim().orEmpty()
        val asset = if (requestedAsset.isNotEmpty()) {
            zips.firstOrNull { it.name.equals(requestedAsset, true) }
                ?: zips.firstOrNull { it.name.contains(requestedAsset, true) }
                ?: throw IllegalArgumentException(
                    "No ZIP asset '$requestedAsset' in $normalizedRepo ${release.tag}. " +
                        "Assets: ${zips.joinToString { it.name }}"
                )
        } else {
            zips.firstOrNull { it.name.contains("module", true) }
                ?: zips.firstOrNull { !it.name.contains("source", true) }
                ?: zips.firstOrNull()
                ?: throw IllegalArgumentException(
                    "No ZIP asset in $normalizedRepo ${release.tag}; this release has no installable module."
                )
        }
        check(isGithubReleaseUrl(asset.url)) {
            "Release asset is not a GitHub release download URL"
        }
        GithubModuleAsset(
            repo = normalizedRepo,
            tag = release.tag,
            name = asset.name,
            size = asset.size,
            url = asset.url,
            sha256 = asset.sha256,
        )
    }

    private suspend fun fetchGithubReleases(repo: String): List<GithubRelease> = withContext(Dispatchers.IO) {
        val normalized = normalizeRepo(repo)
        val body = fetch(
            "https://api.github.com/repos/$normalized/releases?per_page=10",
            "application/vnd.github+json",
        )
        val root = runCatching { json.parseToJsonElement(body) as? JsonArray }.getOrNull()
            ?: throw IllegalStateException("GitHub returned an unexpected releases response")
        root.mapNotNull { element ->
            val release = element as? JsonObject ?: return@mapNotNull null
            val assets = (release["assets"] as? JsonArray).orEmpty().mapNotNull { assetElement ->
                val asset = assetElement as? JsonObject ?: return@mapNotNull null
                val name = asset.str("name").orEmpty()
                val url = asset.str("browser_download_url").orEmpty()
                if (name.isBlank() || url.isBlank()) return@mapNotNull null
                GithubReleaseAsset(
                    name = name,
                    size = asset.long("size") ?: 0L,
                    url = url,
                    sha256 = asset.str("digest")
                        ?.substringAfter("sha256:", "")
                        ?.takeIf { it.length == 64 && it.all { c -> c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F' } }
                        ?.lowercase(),
                )
            }
            GithubRelease(
                tag = release.str("tag_name").orEmpty(),
                name = release.str("name").orEmpty().ifBlank { release.str("tag_name").orEmpty() },
                prerelease = release.bool("prerelease") ?: false,
                draft = release.bool("draft") ?: false,
                publishedAt = release.str("published_at").orEmpty(),
                assets = assets,
            )
        }.filter { it.tag.isNotBlank() }
    }

    private fun normalizeRepo(repo: String): String {
        val cleaned = repo.trim()
            .removePrefix("https://github.com/")
            .removePrefix("http://github.com/")
            .removePrefix("github.com/")
            .removeSuffix(".git")
            .trimEnd('/')
        val parts = cleaned.split('/').filter { it.isNotBlank() }
        require(parts.size >= 2) {
            "repo must be owner/name, e.g. owner/repository"
        }
        val owner = parts[0]
        val name = parts[1]
        require(owner.length <= 100 && name.length <= 100) { "repo is too long" }
        require((owner + name).all { it.isLetterOrDigit() || it == '-' || it == '_' || it == '.' }) {
            "repo contains invalid characters"
        }
        return "$owner/$name"
    }

    private fun fetch(url: String, accept: String): String {
        val request = Request.Builder()
            .url(url)
            .header("User-Agent", USER_AGENT)
            .header("Accept", accept)
            .build()
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                val body = runCatching { response.body.string() }.getOrDefault("")
                throw IllegalStateException(
                    "HTTP ${response.code} from ${URI(url).host}" +
                        if (body.isNotBlank()) ": ${stripHtml(body).take(300)}" else ""
                )
            }
            val body = response.body.string()
            return body.take(MAX_BODY)
        }
    }

    internal fun parseDuckDuckGo(html: String): List<WebSearchResult> {
        val anchors = Regex(
            """<a\b[^>]*class="[^"]*result__a[^"]*"[^>]*>([\s\S]*?)</a>""",
            RegexOption.IGNORE_CASE,
        ).findAll(html).toList()
        val snippets = Regex(
            """<a\b[^>]*class="[^"]*result__snippet[^"]*"[^>]*>([\s\S]*?)</a>""",
            RegexOption.IGNORE_CASE,
        ).findAll(html).map { stripHtml(it.groupValues[1]) }.toList()
        return anchors.mapIndexedNotNull { index, match ->
            val href = Regex("""href="([^"]*)"""", RegexOption.IGNORE_CASE)
                .find(match.value)?.groupValues?.get(1)
                ?: return@mapIndexedNotNull null
            val url = decodeDuckDuckGoUrl(href)
            if (!url.startsWith("http", true)) return@mapIndexedNotNull null
            WebSearchResult(
                title = stripHtml(match.groupValues[1]),
                url = url,
                snippet = snippets.getOrElse(index) { "" },
            )
        }.filter { it.title.isNotBlank() }.distinctBy { it.url }
    }

    internal fun parseDuckDuckGoLite(html: String): List<WebSearchResult> {
        val anchors = Regex(
            """<a\b[^>]*class="[^"]*result-link[^"]*"[^>]*>([\s\S]*?)</a>""",
            RegexOption.IGNORE_CASE,
        ).findAll(html).toList()
        val snippets = Regex(
            """<td\b[^>]*class="[^"]*result-snippet[^"]*"[^>]*>([\s\S]*?)</td>""",
            RegexOption.IGNORE_CASE,
        ).findAll(html).map { stripHtml(it.groupValues[1]) }.toList()
        return anchors.mapIndexedNotNull { index, match ->
            val href = Regex("""href="([^"]*)"""", RegexOption.IGNORE_CASE)
                .find(match.value)?.groupValues?.get(1)
                ?: return@mapIndexedNotNull null
            val url = decodeDuckDuckGoUrl(href)
            if (!url.startsWith("http", true)) return@mapIndexedNotNull null
            WebSearchResult(
                title = stripHtml(match.groupValues[1]),
                url = url,
                snippet = snippets.getOrElse(index) { "" },
            )
        }.filter { it.title.isNotBlank() }.distinctBy { it.url }
    }

    private fun decodeDuckDuckGoUrl(href: String): String {
        val cleaned = unescapeHtml(href)
        val uddg = Regex("""[?&]uddg=([^&]+)""").find(cleaned)?.groupValues?.get(1)
        val url = uddg?.let { runCatching { URLDecoder.decode(it, "UTF-8") }.getOrNull() } ?: cleaned
        return when {
            url.startsWith("//") -> "https:$url"
            url.startsWith("/") -> "https://duckduckgo.com$url"
            else -> url
        }
    }

    private fun stripHtml(value: String): String {
        val withoutBlocks = value
            .replace(Regex("""<(script|style)[\s\S]*?</\1>""", RegexOption.IGNORE_CASE), " ")
            .replace(Regex("""<br\s*/?>""", RegexOption.IGNORE_CASE), "\n")
            .replace(Regex("""</p>""", RegexOption.IGNORE_CASE), "\n")
            .replace(Regex("""<[^>]+>"""), " ")
        return unescapeHtml(withoutBlocks)
            .replace(Regex("""\s+"""), " ")
            .trim()
    }

    private fun unescapeHtml(value: String): String = value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")

    private fun JsonObject.str(key: String): String? =
        (this[key] as? JsonPrimitive)?.contentOrNull

    private fun JsonObject.int(key: String): Int? =
        (this[key] as? JsonPrimitive)?.intOrNull

    private fun JsonObject.long(key: String): Long? =
        (this[key] as? JsonPrimitive)?.longOrNull

    private fun JsonObject.bool(key: String): Boolean? =
        (this[key] as? JsonPrimitive)?.contentOrNull?.toBooleanStrictOrNull()

    private fun kotlinx.serialization.json.JsonElement.text(): String =
        (this as? JsonPrimitive)?.contentOrNull ?: toString()
}
