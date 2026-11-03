package com.sukisu.ultra.data.repository

import android.content.Context
import com.sukisu.ultra.data.model.ThemeStoreCatalog
import com.sukisu.ultra.data.model.ThemeStoreEntry
import com.sukisu.ultra.data.model.ThemeStoreSubmitResponse
import com.sukisu.ultra.data.model.ThemeStoreUploadInitRequest
import com.sukisu.ultra.data.model.ThemeStoreUploadSession
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
import okhttp3.RequestBody.Companion.toRequestBody
import okio.Buffer
import okio.BufferedSink
import okio.ForwardingSink
import okio.buffer
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.RandomAccessFile
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
        /** Shared client ceiling; the mirror's server-side limit remains authoritative. */
        const val MAX_PACKAGE_BYTES = 128L * 1024L * 1024L
        private const val BUFFER_SIZE = 64 * 1024
        private const val MAX_UPLOAD_CHUNK_BYTES = 8L * 1024L * 1024L
        private const val PACKAGE_PROGRESS_WEIGHT = 0.95f
        /** Persistent download cache ceiling; two maximum-size packages fit before eviction. */
        private const val MAX_DOWNLOAD_CACHE_BYTES = 256L * 1024L * 1024L
        /** Never trim a download that was touched recently; it may still be importing. */
        private val ACTIVE_CACHE_GRACE_MS = TimeUnit.HOURS.toMillis(1)
        private val SHA256_PATTERN = Regex("^[0-9a-fA-F]{64}$")
        private val ID_PATTERN = Regex("^[a-z0-9][a-z0-9-]{0,63}$")
        private val UPLOAD_ID_PATTERN = Regex("^[0-9a-fA-F]{8,64}$")
        private val CONTENT_RANGE_START = Regex("""bytes\s+(\d+)-""", RegexOption.IGNORE_CASE)
        private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()
        private val CHUNK_MEDIA = "application/octet-stream".toMediaType()

        internal fun parseContentRangeStart(value: String?): Long? =
            value?.let { CONTENT_RANGE_START.find(it) }
                ?.groupValues
                ?.getOrNull(1)
                ?.toLongOrNull()

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
            .readTimeout(5, TimeUnit.MINUTES)
            .writeTimeout(5, TimeUnit.MINUTES)
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
            finalFile.delete()

            val tempFile = File(downloadDir, "${finalFile.name}.part")
            if (tempFile.isFile) {
                when {
                    tempFile.length() > entry.size -> tempFile.delete()
                    tempFile.length() == entry.size && sha256Of(tempFile) == expectedSha -> {
                        moveDownloadedFile(tempFile, finalFile)
                        onProgress(1f)
                        return@runCatching finalFile
                    }

                    tempFile.length() == entry.size -> tempFile.delete()
                }
            }

            val resumeFrom = tempFile.takeIf { it.isFile }?.length() ?: 0L
            val downloaded = downloadThemePackage(
                entry = entry,
                url = base + entry.path.removePrefix("/"),
                token = token,
                tempFile = tempFile,
                resumeFrom = resumeFrom,
                expectedSha = expectedSha,
                onProgress = onProgress,
                allowRestart = resumeFrom > 0,
            )
            moveDownloadedFile(downloaded, finalFile)
            onProgress(1f)
            finalFile
        }
    }

    /**
     * Streams a package to [tempFile], resuming from [resumeFrom] when the server honors
     * `Range`. Keeps the partial file on network failures so a later attempt can continue.
     */
    private fun downloadThemePackage(
        entry: ThemeStoreEntry,
        url: String,
        token: String,
        tempFile: File,
        resumeFrom: Long,
        expectedSha: String,
        onProgress: (Float) -> Unit,
        allowRestart: Boolean,
    ): File {
        val requestBuilder = Request.Builder()
            .url(url)
            .cacheControl(CacheControl.Builder().noCache().build())
            .header("Accept-Encoding", "identity")
            .withToken(token)
        if (resumeFrom > 0) {
            requestBuilder.header("Range", "bytes=$resumeFrom-")
            onProgress((resumeFrom.toFloat() / entry.size).coerceIn(0f, 1f))
        }

        downloadClient.newCall(requestBuilder.build()).execute().use { response ->
            if (response.code == 401) throw ThemeStoreUnauthorizedException()
            if (response.code == 416) {
                tempFile.delete()
                if (allowRestart) {
                    return downloadThemePackage(
                        entry, url, token, tempFile, 0, expectedSha, onProgress, false,
                    )
                }
                throw IOException("HTTP 416 for ${entry.path}")
            }
            if (!response.isSuccessful) {
                throw IOException("HTTP ${response.code} for ${entry.path}")
            }

            val body = response.body
            val contentLength = body.contentLength()
            var offset = resumeFrom
            if (response.code == 206) {
                val start = parseContentRangeStart(response.header("Content-Range"))
                if (start != offset) {
                    if (allowRestart) {
                        tempFile.delete()
                        return downloadThemePackage(
                            entry, url, token, tempFile, 0, expectedSha, onProgress, false,
                        )
                    }
                    throw IOException("Invalid Content-Range for ${entry.path}")
                }
                if (contentLength > 0 && offset + contentLength > entry.size) {
                    tempFile.delete()
                    throw IOException("Theme package is too large")
                }
            } else {
                // The server ignored Range (or this was a fresh request): rewrite from zero.
                offset = 0
                onProgress(0f)
                if (contentLength > entry.size) {
                    tempFile.delete()
                    throw IOException("Theme package is too large")
                }
            }

            var written = offset
            val buffer = ByteArray(BUFFER_SIZE)
            body.byteStream().use { input ->
                FileOutputStream(tempFile, offset > 0).use { output ->
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        written += read
                        if (written > entry.size) {
                            tempFile.delete()
                            throw IOException("Theme package is too large")
                        }
                        output.write(buffer, 0, read)
                        onProgress((written.toFloat() / entry.size).coerceIn(0f, 1f))
                    }
                }
            }

            if (written != entry.size) {
                if (allowRestart && offset > 0) {
                    tempFile.delete()
                    return downloadThemePackage(
                        entry, url, token, tempFile, 0, expectedSha, onProgress, false,
                    )
                }
                tempFile.delete()
                throw IOException("Theme package size mismatch")
            }
            if (sha256Of(tempFile) != expectedSha) {
                if (allowRestart && offset > 0) {
                    tempFile.delete()
                    return downloadThemePackage(
                        entry, url, token, tempFile, 0, expectedSha, onProgress, false,
                    )
                }
                tempFile.delete()
                throw IOException("Theme package checksum mismatch")
            }
            return tempFile
        }
    }

    private fun moveDownloadedFile(tempFile: File, finalFile: File) {
        if (!tempFile.renameTo(finalFile)) {
            tempFile.copyTo(finalFile, overwrite = true)
            tempFile.delete()
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

            // Account uploads use the mirror's chunked session so a network drop can resume
            // instead of restarting a package that may be up to 128 MB.
            val resumableUploadId = bearerToken?.takeIf { it.isNotBlank() }?.let { bearer ->
                uploadPackageResumable(
                    base = base,
                    bearerToken = bearer,
                    packageFile = submission.packageFile,
                    onProgress = { progress ->
                        onProgress(progress * PACKAGE_PROGRESS_WEIGHT)
                    },
                )
            }
            if (resumableUploadId != null) {
                builder.addFormDataPart("uploadId", resumableUploadId)
            } else {
                builder.addFormDataPart(
                    "package",
                    submission.packageFile.name,
                    submission.packageFile.asRequestBody("application/octet-stream".toMediaType()),
                )
            }
            builder.addFormDataPart(
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
            val progressBody = ProgressRequestBody(builder.build()) { progress ->
                if (resumableUploadId != null) {
                    onProgress(
                        PACKAGE_PROGRESS_WEIGHT + progress * (1f - PACKAGE_PROGRESS_WEIGHT),
                    )
                } else {
                    onProgress(progress)
                }
            }
            val requestBuilder = Request.Builder()
                .url(base + endpoint)
                .post(progressBody)
                .withToken(token)
            if (!bearerToken.isNullOrBlank()) {
                requestBuilder
                    .header("Authorization", "Bearer $bearerToken")
                    .header("X-Requested-With", "SukiSUThemeAdmin")
                    .header("X-Client", "android")
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

    /**
     * Uploads the package through the mirror's resumable session API. `init` returns chunks
     * that already reached the server, so a retry after an interrupted upload continues from
     * there. The session is removed by the server after the final submit succeeds.
     */
    private fun uploadPackageResumable(
        base: String,
        bearerToken: String,
        packageFile: File,
        onProgress: (Float) -> Unit,
    ): String {
        val totalSize = packageFile.length()
        if (totalSize <= 0L || totalSize > MAX_PACKAGE_BYTES) {
            throw IOException("Invalid theme package size")
        }
        val session = initResumableUpload(base, bearerToken, packageFile, totalSize)
        if (!UPLOAD_ID_PATTERN.matches(session.uploadId)) {
            throw IOException("Invalid upload session id")
        }
        val chunkSize = session.chunkSize
        if (chunkSize <= 0L || chunkSize > MAX_UPLOAD_CHUNK_BYTES) {
            throw IOException("Invalid upload chunk size")
        }
        val expectedChunks = (totalSize + chunkSize - 1L) / chunkSize
        if (session.size != totalSize || session.totalChunks != expectedChunks) {
            throw IOException("Upload session does not match the selected package")
        }

        val received = session.received
            .filter { it in 0 until session.totalChunks }
            .toSet()
        var uploadedBytes = received.sumOf { index ->
            uploadChunkLength(totalSize, chunkSize, index)
        }
        onProgress((uploadedBytes.toFloat() / totalSize).coerceIn(0f, 1f))

        RandomAccessFile(packageFile, "r").use { file ->
            var index = 0L
            while (index < session.totalChunks) {
                if (index !in received) {
                    val offset = index * chunkSize
                    val length = uploadChunkLength(totalSize, chunkSize, index)
                    if (length > 0L) {
                        file.seek(offset)
                        val data = ByteArray(length.toInt())
                        file.readFully(data)
                        uploadPackageChunk(
                            base = base,
                            bearerToken = bearerToken,
                            uploadId = session.uploadId,
                            index = index,
                            data = data,
                        )
                        uploadedBytes += length
                        onProgress((uploadedBytes.toFloat() / totalSize).coerceIn(0f, 1f))
                    }
                }
                index++
            }
        }
        return session.uploadId
    }

    private fun initResumableUpload(
        base: String,
        bearerToken: String,
        packageFile: File,
        totalSize: Long,
    ): ThemeStoreUploadSession {
        val requestBody = json.encodeToString(
            ThemeStoreUploadInitRequest.serializer(),
            ThemeStoreUploadInitRequest(
                filename = packageFile.name,
                size = totalSize,
                fingerprint = sha256Of(packageFile),
            ),
        ).toRequestBody(JSON_MEDIA)
        val request = Request.Builder()
            .url(base + "account/api/uploads/init")
            .post(requestBody)
            .header("Authorization", "Bearer $bearerToken")
            .header("X-Requested-With", "SukiSUThemeAdmin")
            .header("X-Client", "android")
            .build()
        uploadClient.newCall(request).execute().use { response ->
            val raw = response.body.string()
            if (response.code == 401) throw ThemeStoreUnauthorizedException()
            val parsed = runCatching {
                json.decodeFromString(ThemeStoreUploadSession.serializer(), raw)
            }.getOrNull()
            if (!response.isSuccessful) {
                throw IOException(
                    parsed?.error?.takeIf { it.isNotBlank() }
                        ?: "HTTP ${response.code} while starting the upload",
                )
            }
            val session = parsed ?: throw IOException("Invalid upload session response")
            if (!session.ok || session.uploadId.isBlank()) {
                throw IOException(session.error?.takeIf { it.isNotBlank() } ?: "Upload session was rejected")
            }
            return session
        }
    }

    private fun uploadPackageChunk(
        base: String,
        bearerToken: String,
        uploadId: String,
        index: Long,
        data: ByteArray,
    ) {
        val request = Request.Builder()
            .url(base + "account/api/uploads/$uploadId/$index")
            .post(data.toRequestBody(CHUNK_MEDIA))
            .header("Authorization", "Bearer $bearerToken")
            .header("X-Requested-With", "SukiSUThemeAdmin")
            .header("X-Client", "android")
            .build()
        uploadClient.newCall(request).execute().use { response ->
            val raw = response.body.string()
            if (response.code == 401) throw ThemeStoreUnauthorizedException()
            val parsed = runCatching {
                json.decodeFromString(ThemeStoreUploadSession.serializer(), raw)
            }.getOrNull()
            if (!response.isSuccessful) {
                throw IOException(
                    parsed?.error?.takeIf { it.isNotBlank() }
                        ?: "HTTP ${response.code} while uploading a chunk",
                )
            }
            if (parsed != null && !parsed.ok) {
                throw IOException(parsed.error?.takeIf { it.isNotBlank() } ?: "Chunk upload was rejected")
            }
        }
    }

    private fun uploadChunkLength(totalSize: Long, chunkSize: Long, index: Long): Long {
        val offset = index * chunkSize
        if (offset >= totalSize) return 0L
        return minOf(chunkSize, totalSize - offset)
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

    /**
     * Bounded cache housekeeping. Partial downloads are kept long enough for resume, while
     * abandoned upload/import temporaries and orphaned completed downloads are removed.
     */
    fun cleanupStaleCache(now: Long = System.currentTimeMillis()) {
        val day = TimeUnit.DAYS.toMillis(1)
        val week = TimeUnit.DAYS.toMillis(7)

        downloadDir.listFiles()?.forEach { file ->
            if (!file.isFile) return@forEach
            val maxAge = if (file.name.endsWith(".part")) week else day
            if (file.isOlderThan(maxAge, now)) runCatching { file.delete() }
        }
        trimDownloadCache(now)
        cacheDir.listFiles()?.forEach { file ->
            if (!file.isFile) return@forEach
            when {
                file.name.startsWith("catalog-") &&
                    file.name.endsWith(".json") &&
                    file.isOlderThan(30L * day, now) -> runCatching { file.delete() }

                // The upload screen's "current preset" export lives directly in cacheDir and
                // is not covered by the theme_import_* temporary-file rule above.
                file.name == "theme_upload_preset.sukisu" &&
                    file.isOlderThan(day, now) -> runCatching { file.delete() }
            }
        }
        cacheDir.parentFile?.listFiles()?.forEach { file ->
            when {
                file.isDirectory &&
                    file.name.startsWith("theme_upload_") &&
                    file.isOlderThan(day, now) -> runCatching { file.deleteRecursively() }

                file.isFile &&
                    file.name.startsWith("theme_import_") &&
                    file.isOlderThan(day, now) -> runCatching { file.delete() }
            }
        }
    }

    /**
     * Keeps the persistent download cache under [MAX_DOWNLOAD_CACHE_BYTES]. Completed
     * packages are evicted before resumable partials, always oldest first, and recently
     * touched files are left alone because they may still be imported or downloaded.
     */
    private fun trimDownloadCache(now: Long) {
        val files = downloadDir.listFiles()?.filter { it.isFile } ?: return
        var total = files.sumOf { it.length() }
        if (total <= MAX_DOWNLOAD_CACHE_BYTES) return
        val candidates = files
            .filter { it.isOlderThan(ACTIVE_CACHE_GRACE_MS, now) }
            .sortedWith(
                compareBy<File> { it.name.endsWith(".part") }
                    .thenBy { it.lastModified() },
            )
        for (file in candidates) {
            if (total <= MAX_DOWNLOAD_CACHE_BYTES) break
            val size = file.length()
            if (runCatching { file.delete() }.getOrDefault(false)) {
                total -= size
            }
        }
    }

    private fun File.isOlderThan(maxAgeMillis: Long, now: Long): Boolean {
        val modified = lastModified()
        return modified > 0L && now - modified > maxAgeMillis
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
