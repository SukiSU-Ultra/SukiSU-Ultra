package com.sukisu.ultra.ai.host

import com.sukisu.ultra.ai.api.*

import android.net.Uri
import com.sukisu.ultra.Natives
import com.sukisu.ultra.data.registry.ExpectedFile
import com.sukisu.ultra.data.repository.ModuleRepoRepositoryImpl
import com.sukisu.ultra.data.repository.ModuleRepositoryImpl
import com.sukisu.ultra.data.repository.isAutoDeleteModuleZipEnabled
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.util.DownloadManager
import com.sukisu.ultra.ui.util.flashModule
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.Request
import java.io.File
import kotlin.time.Duration.Companion.milliseconds

/**
 * Read the module registry and install a verified release. This mirrors the
 * module repository detail screen: the ZIP is downloaded with its size and
 * SHA-256 check, then handed to ksud through the normal install path.
 */
object AiModuleController {

    private val registry = ModuleRepoRepositoryImpl()

    suspend fun search(query: String?, limit: Int = 8): String = withContext(Dispatchers.IO) {
        val list = registry.fetchModules().getOrThrow()
        val installed = runCatching {
            ModuleRepositoryImpl().getModules().getOrNull().orEmpty()
                .associate { it.id to it.versionCode }
        }.getOrDefault(emptyMap())
        val needle = query?.trim().orEmpty()
        val matches = list.modules.asSequence()
            .filter { module ->
                needle.isEmpty() ||
                    module.moduleId.contains(needle, true) ||
                    module.moduleName.contains(needle, true) ||
                    module.summary.contains(needle, true) ||
                    module.authors.contains(needle, true) ||
                    module.tags.any { it.contains(needle, true) }
            }
            .take(limit.coerceIn(1, 20))
            .toList()
        buildJsonObject {
            put("count", matches.size)
            put("stale", list.stale)
            put("modules", buildJsonArray {
                matches.forEach { module ->
                    add(buildJsonObject {
                        put("id", module.moduleId)
                        put("name", module.moduleName)
                        put("version", module.latestVersion)
                        put("version_code", module.latestVersionCode)
                        put("authors", module.authors)
                        put("summary", module.summary.take(240))
                        put("metamodule", module.metamodule)
                        put("script", module.isScript)
                        put("installed_version_code", installed[module.moduleId]?.toString() ?: "")
                    })
                }
            })
        }.toString()
    }

    /**
     * @param moduleId registry id (preferred) or an exact module name.
     * @param version optional release tag/version; the latest stable release is used otherwise.
     */
    suspend fun install(
        moduleId: String,
        version: String? = null,
        onProgress: (String) -> Unit = {},
    ): String =
        withContext(Dispatchers.IO) {
            check(!Natives.isSafeMode) { "Module installation is disabled in safe mode." }
            onProgress("Resolving ${moduleId.trim()}…")
            val detail = registry.fetchDetail(moduleId.trim()).getOrThrow()
            check(!detail.module.isScript) {
                "'${detail.module.moduleName}' is a one-shot script, not an installable module."
            }
            val requested = version?.trim().orEmpty()
            val release = if (requested.isEmpty()) {
                detail.releases.firstOrNull()
            } else {
                detail.releases.firstOrNull {
                    it.tag.equals(requested, true) ||
                        it.version.equals(requested, true) ||
                        it.name.equals(requested, true)
                }
            } ?: throw IllegalArgumentException(
                "No stable release '${requested.ifEmpty { "latest" }}' for ${detail.module.moduleId}. " +
                    "Available: ${detail.releases.joinToString { it.tag }}"
            )

            val downloadId = DownloadManager.enqueue(
                context = ksuApp,
                url = release.zipUrl,
                fileName = release.zipName,
                expected = ExpectedFile(release.zipSize, release.sha256),
            )
            onProgress("Downloading ${release.zipName}…")
            val finalState = withTimeoutOrNull((10 * 60 * 1000L).milliseconds) {
                DownloadManager.downloads.first { map ->
                    val status = map[downloadId]?.status
                    status == DownloadManager.Status.COMPLETED ||
                        status == DownloadManager.Status.FAILED
                }[downloadId]
            } ?: throw IllegalStateException("Download timed out: ${release.zipName}")
            val uri: Uri = finalState.resultUri ?: throw IllegalStateException(
                "Download failed or failed size/SHA-256 verification: ${release.zipName}" +
                    (finalState.error?.let { "\n$it" } ?: "")
            )

            onProgress("Installing ${detail.module.moduleName} ${release.version}…")
            val stdout = StringBuilder()
            val stderr = StringBuilder()
            val result = flashModule(
                uri = uri,
                onStdout = { line -> if (stdout.length < 12_000) stdout.appendLine(line) },
                onStderr = { line -> if (stderr.length < 6_000) stderr.appendLine(line) },
                deleteSourceOnSuccess = isAutoDeleteModuleZipEnabled(),
            )
            if (result.code != 0) {
                throw IllegalStateException(
                    "Install failed (exit ${result.code}): " +
                        (stderr.toString().ifBlank { stdout.toString() }).take(1200)
                )
            }
            buildString {
                append("Installed ${detail.module.moduleName} ${release.version} (${detail.module.moduleId}).")
                if (result.showReboot) append(" Reboot to activate it.")
                val output = stdout.toString().trim()
                if (output.isNotEmpty()) append("\n").append(output.take(1200))
            }
        }

    /**
     * Installs a GitHub release ZIP. Verified when GitHub published a SHA-256
     * digest for the asset; otherwise the URL is still restricted to a GitHub
     * release download path and the result says verification was unavailable.
     */
    suspend fun installGithubAsset(
        asset: GithubModuleAsset,
        onProgress: (String) -> Unit = {},
    ): String = withContext(Dispatchers.IO) {
        check(!Natives.isSafeMode) { "Module installation is disabled in safe mode." }
        check(AiGithubUrls.isReleaseDownloadUrl(asset.url)) {
            "Not a GitHub release download URL: ${asset.url}"
        }
        val expected = asset.sha256
            ?.takeIf { it.length == 64 && asset.size > 0 }
            ?.let { ExpectedFile(asset.size, it) }
        var temporaryFile: File? = null
        try {
            val uri: Uri = if (expected != null) {
                onProgress("Downloading ${asset.name}…")
                val downloadId = DownloadManager.enqueue(
                    context = ksuApp,
                    url = asset.url,
                    fileName = asset.name,
                    expected = expected,
                )
                val finalState = withTimeoutOrNull((10 * 60 * 1000L).milliseconds) {
                    DownloadManager.downloads.first { map ->
                        val status = map[downloadId]?.status
                        status == DownloadManager.Status.COMPLETED ||
                            status == DownloadManager.Status.FAILED
                    }[downloadId]
                } ?: throw IllegalStateException("Download timed out: ${asset.name}")
                finalState.resultUri ?: throw IllegalStateException(
                    "Download failed: ${asset.name}" +
                        (finalState.error?.let { "\n$it" } ?: "")
                )
            } else {
                val file = downloadUnverifiedGithubZip(asset, onProgress)
                temporaryFile = file
                Uri.fromFile(file)
            }

            onProgress("Installing ${asset.name}…")
            val stdout = StringBuilder()
            val stderr = StringBuilder()
            val result = flashModule(
                uri = uri,
                onStdout = { line -> if (stdout.length < 12_000) stdout.appendLine(line) },
                onStderr = { line -> if (stderr.length < 6_000) stderr.appendLine(line) },
                deleteSourceOnSuccess = expected != null && isAutoDeleteModuleZipEnabled(),
            )
            if (result.code != 0) {
                throw IllegalStateException(
                    "Install failed (exit ${result.code}): " +
                        (stderr.toString().ifBlank { stdout.toString() }).take(1200)
                )
            }
            buildString {
                append("Installed ${asset.repo}@${asset.tag} (${asset.name}).")
                if (expected != null) {
                    append(" SHA-256 verified.")
                } else {
                    append(" GitHub did not publish a SHA-256 for this asset; the ZIP was downloaded without hash verification and removed after installing.")
                }
                if (result.showReboot) append(" Reboot to activate it.")
                val output = stdout.toString().trim()
                if (output.isNotEmpty()) append("\n").append(output.take(1200))
            }
        } finally {
            temporaryFile?.delete()
        }
    }

    /**
     * Fallback for assets without a GitHub digest. Older Android releases
     * cannot publish into MediaStore.Downloads, so stream into the app cache
     * instead and let [flashModule] read the file URI.
     */
    private suspend fun downloadUnverifiedGithubZip(
        asset: GithubModuleAsset,
        onProgress: (String) -> Unit,
    ): File = withContext(Dispatchers.IO) {
        val safeName = asset.name
            .substringAfterLast('/')
            .replace(Regex("[^A-Za-z0-9._-]"), "_")
            .take(80)
            .ifBlank { "module.zip" }
        val file = File(ksuApp.cacheDir, "ai-module-${System.currentTimeMillis()}-$safeName")
        try {
            val request = Request.Builder()
                .url(asset.url)
                .header("User-Agent", "SukiSU-Manager-AI/1.0")
                .build()
            ksuApp.okhttpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) throw IllegalStateException("HTTP ${response.code}")
                val body = response.body
                val total = if (asset.size > 0) asset.size else body.contentLength()
                var copied = 0L
                var lastPercent = -1
                body.byteStream().use { input ->
                    file.outputStream().use { output ->
                        val buffer = ByteArray(64 * 1024)
                        while (true) {
                            currentCoroutineContext().ensureActive()
                            val read = input.read(buffer)
                            if (read == -1) break
                            copied += read
                            check(copied <= MAX_MODULE_BYTES) { "Module ZIP exceeds 256 MB" }
                            output.write(buffer, 0, read)
                            if (total > 0) {
                                val percent = ((copied * 100) / total).toInt().coerceIn(0, 100)
                                if (percent >= lastPercent + 2 || copied == total) {
                                    onProgress("Downloading ${asset.name}… $percent%")
                                    lastPercent = percent
                                }
                            }
                        }
                    }
                }
                if (asset.size > 0 && copied != asset.size) {
                    throw IllegalStateException("Size mismatch: expected ${asset.size}, got $copied")
                }
            }
            file
        } catch (error: Throwable) {
            file.delete()
            throw error
        }
    }

    private const val MAX_MODULE_BYTES = 256L * 1024 * 1024
}
