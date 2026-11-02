package com.sukisu.ultra.data.repository

import android.content.Context
import com.sukisu.ultra.data.model.ThemeStoreCatalog
import com.sukisu.ultra.data.model.ThemeStoreEntry
import com.sukisu.ultra.data.model.ThemeStoreSubmitResponse
import com.sukisu.ultra.ksuApp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.CacheControl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.asRequestBody
import okio.Buffer
import okio.BufferedSink
import okio.ForwardingSink
import okio.buffer
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

data class ThemeCatalogLoad(
    val catalog: ThemeStoreCatalog,
    val fromCache: Boolean,
)

/** A validated theme package prepared for upload to a store source. */
data class ThemeStoreSubmission(
    val id: String,
    val version: Int,
    val formatVersion: Int,
    val name: String,
    val author: String,
    val authorId: String,
    val description: String,
    val tags: String,
    val license: String,
    val minManagerVersion: Long,
    val changelog: String,
    val packageFile: File,
    val previewFile: File,
    val avatarFile: File? = null,
    val screenshotFiles: List<File> = emptyList(),
)

class ThemeStoreUnauthorizedException : IOException("Theme store token rejected")

private class ProgressRequestBody(
    private val delegate: RequestBody,
    private val onProgress: (Float) -> Unit,
) : RequestBody() {
    override fun contentType(): MediaType? = delegate.contentType()

    override fun contentLength(): Long = delegate.contentLength()

    override fun writeTo(sink: BufferedSink) {
        val total = contentLength()
        val forwarding = object : ForwardingSink(sink) {
            private var written = 0L

            override fun write(source: Buffer, byteCount: Long) {
                super.write(source, byteCount)
                written += byteCount
                if (total > 0L) {
                    onProgress((written.toFloat() / total).coerceIn(0f, 1f))
                }
            }
        }
        val buffered = forwarding.buffer()
        delegate.writeTo(buffered)
        buffered.flush()
    }
}

/**
 * Downloads the public theme catalog and theme packages.
 *
 * The base URL and access token come from the manager's settings; nothing is
 * hardcoded here. The catalog is cached per base URL so switching stores does
 * not show another store's entries. Packages are written to a temporary file,
 * checked against the size and SHA-256 from the catalog, and only then renamed
 * to their final name.
 */
class ThemeStoreRepository(
    private val context: Context,
    private val client: OkHttpClient = ksuApp.okhttpClient,
) {
    companion object {
        const val TOKEN_HEADER = "X-Sukisu-Theme-Token"

        private const val MAX_CATALOG_BYTES = 1024L * 1024L
        private const val MAX_PACKAGE_BYTES = 16L * 1024L * 1024L
        private const val BUFFER_SIZE = 64 * 1024
        private val SHA256_PATTERN = Regex("^[0-9a-fA-F]{64}$")
        private val ID_PATTERN = Regex("^[a-z0-9][a-z0-9-]{0,63}$")

        private val json = Json {
            ignoreUnknownKeys = true
            isLenient = true
        }

        /**
         * Accepts `host`, `host:port`, or a full URL and returns a base URL with
         * a trailing slash. Both HTTPS and plain HTTP sources are supported;
         * when no scheme is supplied, HTTPS is assumed.
         */
        fun normalizeBaseUrl(raw: String): String? {
            val trimmed = raw.trim()
            if (trimmed.isEmpty()) return null
            val withScheme = if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
                trimmed
            } else {
                "https://$trimmed"
            }
            val url = withScheme.toHttpUrlOrNull() ?: return null
            if (url.query != null || url.fragment != null) return null
            if (url.encodedPath.endsWith(".json")) return null
            return url.toString().trimEnd('/') + "/"
        }

        fun assetUrl(baseUrl: String, path: String): String? {
            val base = normalizeBaseUrl(baseUrl) ?: return null
            if (path.isBlank() || path.contains("..") ||
                path.startsWith("http://") || path.startsWith("https://")
            ) {
                return null
            }
            return base + path.removePrefix("/")
        }
    }

    private val cacheDir = File(context.cacheDir, "theme_store")
    private val downloadDir = File(cacheDir, "downloads")

    private val downloadClient: OkHttpClient by lazy {
        client.newBuilder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build()
    }

    private val catalogClient: OkHttpClient by lazy {
        client.newBuilder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .build()
    }

    private val uploadClient: OkHttpClient by lazy {
        client.newBuilder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(120, TimeUnit.SECONDS)
            .build()
    }

    suspend fun loadCatalog(baseUrl: String, token: String): Result<ThemeCatalogLoad> =
        withContext(Dispatchers.IO) {
            val base = normalizeBaseUrl(baseUrl)
                ?: return@withContext Result.failure(IOException("Invalid theme store URL"))
            runCatching { fetchCatalog(base, token) }
                .map { ThemeCatalogLoad(it, fromCache = false) }
                .recoverCatching { error ->
                    if (error is ThemeStoreUnauthorizedException) throw error
                    readCachedCatalog(base) ?: throw error
                }
        }

    suspend fun downloadTheme(
        entry: ThemeStoreEntry,
        baseUrl: String,
        token: String,
        onProgress: (Float) -> Unit,
    ): Result<File> = withContext(Dispatchers.IO) {
        var tempFile: File? = null
        runCatching {
            val base = normalizeBaseUrl(baseUrl)
                ?: throw IOException("Invalid theme store URL")
            val expectedSha = entry.sha256.trim().lowercase()
            require(ID_PATTERN.matches(entry.id)) { "Invalid theme id" }
            require(entry.path.isNotBlank() && !entry.path.contains("..") &&
                !entry.path.startsWith("http://") && !entry.path.startsWith("https://")) {
                "Invalid theme package path"
            }
            require(SHA256_PATTERN.matches(expectedSha)) { "Invalid theme checksum" }
            require(entry.size in 1..MAX_PACKAGE_BYTES) { "Invalid theme package size" }

            downloadDir.mkdirs()
            val finalFile = File(downloadDir, "${entry.id}-v${entry.version}.sukisu")
            if (finalFile.isFile &&
                finalFile.length() == entry.size &&
                sha256Of(finalFile) == expectedSha
            ) {
                onProgress(1f)
                return@runCatching finalFile
            }

            tempFile = File(downloadDir, "${finalFile.name}.part")
            tempFile.delete()
            finalFile.delete()

            val request = Request.Builder()
                .url(base + entry.path.removePrefix("/"))
                .cacheControl(CacheControl.Builder().noCache().build())
                .withToken(token)
                .build()

            downloadClient.newCall(request).execute().use { response ->
                if (response.code == 401) throw ThemeStoreUnauthorizedException()
                if (!response.isSuccessful) {
                    throw IOException("HTTP ${response.code} for ${entry.path}")
                }
                val body = response.body
                val contentLength = body.contentLength()
                if (contentLength > MAX_PACKAGE_BYTES) {
                    throw IOException("Theme package is too large")
                }
                val digest = MessageDigest.getInstance("SHA-256")
                var written = 0L
                val buffer = ByteArray(BUFFER_SIZE)
                body.byteStream().use { input ->
                    FileOutputStream(tempFile).use { output ->
                        while (true) {
                            val read = input.read(buffer)
                            if (read < 0) break
                            written += read
                            if (written > MAX_PACKAGE_BYTES) {
                                throw IOException("Theme package is too large")
                            }
                            digest.update(buffer, 0, read)
                            output.write(buffer, 0, read)
                            if (entry.size > 0) {
                                onProgress((written.toFloat() / entry.size).coerceIn(0f, 1f))
                            }
                        }
                    }
                }
                if (written != entry.size) {
                    throw IOException("Theme package size mismatch")
                }
                val actualSha = digest.digest().joinToString("") { "%02x".format(it) }
                if (actualSha != expectedSha) {
                    throw IOException("Theme package checksum mismatch")
                }
            }

            if (!tempFile.renameTo(finalFile)) {
                tempFile.copyTo(finalFile, overwrite = true)
                tempFile.delete()
            }
            onProgress(1f)
            finalFile
        }.onFailure {
            tempFile?.delete()
        }
    }

    suspend fun submitTheme(
        submission: ThemeStoreSubmission,
        baseUrl: String,
        token: String,
        bearerToken: String? = null,
        onProgress: (Float) -> Unit = {},
    ): Result<ThemeStoreSubmitResponse> = withContext(Dispatchers.IO) {
        runCatching {
            val base = normalizeBaseUrl(baseUrl)
                ?: throw IOException("Invalid theme store URL")
            if (bearerToken.isNullOrBlank() && token.isBlank()) {
                throw IOException("Theme store token is missing")
            }
            if (submission.id.isNotBlank()) {
                require(ID_PATTERN.matches(submission.id)) { "Invalid theme id" }
            }
            require(submission.packageFile.isFile) { "Theme package is missing" }
            require(submission.previewFile.isFile) { "Preview image is missing" }

            val builder = MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("id", submission.id)
                .addFormDataPart("version", submission.version.toString())
                .addFormDataPart("formatVersion", submission.formatVersion.toString())
                .addFormDataPart("name", submission.name)
                .addFormDataPart("author", submission.author)
                .addFormDataPart("authorId", submission.authorId)
                .addFormDataPart("description", submission.description)
                .addFormDataPart("tags", submission.tags)
                .addFormDataPart("license", submission.license)
                .addFormDataPart("minManagerVersion", submission.minManagerVersion.toString())
                .addFormDataPart("changelog", submission.changelog)
                .addFormDataPart(
                    "package",
                    submission.packageFile.name,
                    submission.packageFile.asRequestBody("application/octet-stream".toMediaType()),
                )
                .addFormDataPart(
                    "preview",
                    submission.previewFile.name,
                    submission.previewFile.asRequestBody("application/octet-stream".toMediaType()),
                )
            submission.avatarFile?.let { file ->
                require(file.isFile) { "Avatar image is missing" }
                builder.addFormDataPart(
                    "avatar",
                    file.name,
                    file.asRequestBody("application/octet-stream".toMediaType()),
                )
            }
            submission.screenshotFiles.forEach { file ->
                builder.addFormDataPart(
                    "screenshots",
                    file.name,
                    file.asRequestBody("application/octet-stream".toMediaType()),
                )
            }

            val endpoint = if (!bearerToken.isNullOrBlank()) "account/api/submit" else "submit"
            val requestBuilder = Request.Builder()
                .url(base + endpoint)
                .post(ProgressRequestBody(builder.build(), onProgress))
                .withToken(token)
            if (!bearerToken.isNullOrBlank()) {
                requestBuilder.header("Authorization", "Bearer $bearerToken")
            }
            val request = requestBuilder.build()

            uploadClient.newCall(request).execute().use { response ->
                val raw = response.body.string()
                val parsed = runCatching {
                    json.decodeFromString(ThemeStoreSubmitResponse.serializer(), raw)
                }.getOrNull()
                if (response.code == 401) throw ThemeStoreUnauthorizedException()
                if (!response.isSuccessful) {
                    throw IOException(
                        parsed?.error?.takeIf { it.isNotBlank() }
                            ?: "HTTP ${response.code} while submitting theme",
                    )
                }
                parsed ?: throw IOException("Invalid theme submission response")
            }
        }
    }


    private fun fetchCatalog(base: String, token: String): ThemeStoreCatalog {
        val request = Request.Builder()
            .url(base + "catalog.json")
            .cacheControl(CacheControl.Builder().noCache().build())
            .withToken(token)
            .build()
        val raw = catalogClient.newCall(request).execute().use { response ->
            if (response.code == 401) throw ThemeStoreUnauthorizedException()
            if (!response.isSuccessful) throw IOException("HTTP ${response.code} for catalog")
            val body = response.body
            if (body.contentLength() > MAX_CATALOG_BYTES) {
                throw IOException("Theme catalog is too large")
            }
            val source = body.source()
            if (source.request(MAX_CATALOG_BYTES + 1)) {
                throw IOException("Theme catalog is too large")
            }
            source.readUtf8()
        }
        val catalog = json.decodeFromString(ThemeStoreCatalog.serializer(), raw)
        if (catalog.schema > 1) throw IOException("Unsupported theme catalog schema")
        writeCatalogCache(base, raw)
        return catalog
    }

    private fun catalogCacheFile(base: String): File =
        File(cacheDir, "catalog-${base.hashCode().toUInt().toString(16)}.json")

    private fun readCachedCatalog(base: String): ThemeCatalogLoad? {
        val file = catalogCacheFile(base)
        if (!file.isFile) return null
        return runCatching {
            val raw = file.readText()
            val catalog = json.decodeFromString(ThemeStoreCatalog.serializer(), raw)
            if (catalog.schema > 1) return null
            ThemeCatalogLoad(catalog, fromCache = true)
        }.getOrNull()
    }

    private fun writeCatalogCache(base: String, raw: String) {
        runCatching {
            cacheDir.mkdirs()
            val target = catalogCacheFile(base)
            val temp = File(cacheDir, "${target.name}.tmp")
            temp.writeText(raw)
            if (!temp.renameTo(target)) {
                temp.copyTo(target, overwrite = true)
                temp.delete()
            }
        }
    }

    private fun Request.Builder.withToken(token: String): Request.Builder = apply {
        if (token.isNotBlank()) header(TOKEN_HEADER, token)
    }

    private fun sha256Of(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(BUFFER_SIZE)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
