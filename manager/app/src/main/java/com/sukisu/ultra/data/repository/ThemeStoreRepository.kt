package com.sukisu.ultra.data.repository

import android.content.Context
import com.sukisu.ultra.data.model.ThemeStoreCatalog
import com.sukisu.ultra.data.model.ThemeStoreEntry
import com.sukisu.ultra.data.model.ThemeStoreHealth
import com.sukisu.ultra.data.model.ThemeStoreSubmitResponse
import com.sukisu.ultra.ksuApp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.CacheControl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Protocol
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
import java.io.RandomAccessFile
import java.security.MessageDigest
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

data class ThemeCatalogLoad(
    val catalog: ThemeStoreCatalog,
    val fromCache: Boolean,
    
    val notModified: Boolean = false,
)

private data class CatalogFetch(
    val catalog: ThemeStoreCatalog,
    val notModified: Boolean,
)


data class ThemeStoreHealthResult(
    val health: ThemeStoreHealth,
    val latencyMs: Long,
)

enum class ThemeStoreHealthError {
    INVALID_URL,
    NON_JSON,
    EMPTY_RESPONSE,
    INVALID_RESPONSE,
    HTTP,
}


class ThemeStoreHealthException(
    val error: ThemeStoreHealthError,
    val httpStatus: Int? = null,
) : IOException("theme health check failed: $error")


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


private class RangeUnsupportedException : IOException("Server does not support ranged downloads")

/**
 * Resume marker for a partially downloaded package. [completed] lists the chunks that
 * were fully written, so a retry only fetches the missing ranges instead of the whole
 * package.
 */
@Serializable
private data class ParallelDownloadMeta(
    val sha256: String,
    val size: Long,
    val chunkSize: Long,
    val completed: List<Long> = emptyList(),
)

private class ProgressRequestBody(
    private val delegate: RequestBody,
    private val onProgress: (Float, Long, Long) -> Unit,
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
                    onProgress((written.toFloat() / total).coerceIn(0f, 1f), written, total)
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

        
        private const val MAX_CATALOG_BYTES = 8L * 1024L * 1024L
        
        const val MAX_PACKAGE_BYTES = 128L * 1024L * 1024L
        private const val BUFFER_SIZE = 64 * 1024
        /**
         * Theme mirrors commonly throttle a single connection. Fetching several ranges
         * at once keeps large packages from taking a minute on those hosts while
         * remaining gentle enough for small mirrors.
         */
        private const val DOWNLOAD_WORKERS = 4
        private const val DOWNLOAD_CHUNK_BYTES = 2L * 1024L * 1024L
        private const val DOWNLOAD_RETRIES = 3
        private const val MIN_PARALLEL_DOWNLOAD_BYTES = 1L * 1024L * 1024L
        private const val DOWNLOAD_PROGRESS_INTERVAL_NANOS = 100_000_000L
        private const val STREAM_BUFFER_SIZE = 128 * 1024
        
        private const val STREAM_FLUSH_BYTES = 256 * 1024
        
        private const val MAX_DOWNLOAD_CACHE_BYTES = 256L * 1024L * 1024L
        
        private val ACTIVE_CACHE_GRACE_MS = TimeUnit.HOURS.toMillis(1)
        private val SHA256_PATTERN = Regex("^[0-9a-fA-F]{64}$")
        private val ID_PATTERN = Regex("^[a-z0-9][a-z0-9-]{0,63}$")
        private val CONTENT_RANGE_START = Regex("""bytes\s+(\d+)-""", RegexOption.IGNORE_CASE)
        private val CONTENT_RANGE_TOTAL = Regex("""/(\d+)\s*$""", RegexOption.IGNORE_CASE)

        internal fun parseContentRangeStart(value: String?): Long? =
            value?.let { CONTENT_RANGE_START.find(it) }
                ?.groupValues
                ?.getOrNull(1)
                ?.toLongOrNull()

        internal fun parseContentRangeTotal(value: String?): Long? =
            value?.let { CONTENT_RANGE_TOTAL.find(it) }
                ?.groupValues
                ?.getOrNull(1)
                ?.toLongOrNull()

        
        internal fun chunkLength(totalSize: Long, chunkSize: Long, index: Long): Long =
            (totalSize - index * chunkSize).coerceIn(0L, chunkSize)

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

    private val access = ThemeStoreAccessRepository(context)

    suspend fun accessToken(baseUrl: String, configured: String): Result<String> = withContext(Dispatchers.IO) {
        runCatching { access.resolve(baseUrl, configured) }
    }

    suspend fun resetAccess(baseUrl: String): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching { access.reset(baseUrl) }
    }

    private val cacheDir = File(context.cacheDir, "theme_store")
    private val downloadDir = File(cacheDir, "downloads")

    // Theme data has its own verified file cache; bypass OkHttp's shared cache
    // so ETag/304 handling and download counting stay deterministic.
    private val downloadClient: OkHttpClient by lazy {
        client.newBuilder()
            .cache(null)
            // Parallel chunks need separate connections. Under HTTP/2 OkHttp would
            // multiplex every range onto one TCP stream, which inherits the mirror's
            // per-connection throttle and removes the benefit.
            .protocols(listOf(Protocol.HTTP_1_1))
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build()
    }

    private val catalogClient: OkHttpClient by lazy {
        client.newBuilder()
            .cache(null)
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .build()
    }

    private val healthClient: OkHttpClient by lazy {
        client.newBuilder()
            .cache(null)
            .connectTimeout(6, TimeUnit.SECONDS)
            .readTimeout(8, TimeUnit.SECONDS)
            .build()
    }

    private val uploadClient: OkHttpClient by lazy {
        client.newBuilder()
            .cache(null)
            .followRedirects(false)
            .followSslRedirects(false)
            // Chunk workers must not be multiplexed onto one connection under HTTP/2,
            // otherwise a per-connection mirror throttle caps the whole upload.
            .protocols(listOf(Protocol.HTTP_1_1))
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.MINUTES)
            .writeTimeout(5, TimeUnit.MINUTES)
            .build()
    }

    suspend fun loadCatalog(baseUrl: String, token: String): Result<ThemeCatalogLoad> =
        withContext(Dispatchers.IO) {
            val base = normalizeBaseUrl(baseUrl)
                ?: return@withContext Result.failure(IOException("Invalid theme store URL"))
            runCatching { fetchCatalog(base, access.resolve(base, token)) }
                .map {
                    ThemeCatalogLoad(
                        catalog = it.catalog,
                        fromCache = false,
                        notModified = it.notModified,
                    )
                }
                .recoverCatching { error ->
                    if (error is ThemeStoreUnauthorizedException) throw error
                    readCachedCatalog(base) ?: throw error
                }
        }

    
    suspend fun checkHealth(baseUrl: String, token: String): Result<ThemeStoreHealthResult> =
        withContext(Dispatchers.IO) {
            runCatching {
                val base = normalizeBaseUrl(baseUrl)
                    ?: throw ThemeStoreHealthException(ThemeStoreHealthError.INVALID_URL)
                val request = Request.Builder()
                    .url(base + "health")
                    .cacheControl(CacheControl.Builder().noCache().build())
                    .withToken(token)
                    .build()
                val started = System.nanoTime()
                healthClient.newCall(request).execute().use { response ->
                    val latencyMs = ((System.nanoTime() - started) / 1_000_000L).coerceAtLeast(0L)
                    val raw = response.body.string().trim()
                    val health = runCatching {
                        json.decodeFromString(ThemeStoreHealth.serializer(), raw)
                    }.getOrNull()?.takeIf { it.status.isNotBlank() || it.ok }
                    when {
                        health != null -> ThemeStoreHealthResult(health, latencyMs)
                        !response.isSuccessful -> throw ThemeStoreHealthException(
                            ThemeStoreHealthError.HTTP,
                            response.code,
                        )
                        raw.isEmpty() -> throw ThemeStoreHealthException(
                            ThemeStoreHealthError.EMPTY_RESPONSE,
                        )
                        !raw.startsWith("{") -> throw ThemeStoreHealthException(
                            ThemeStoreHealthError.NON_JSON,
                        )
                        else -> throw ThemeStoreHealthException(
                            ThemeStoreHealthError.INVALID_RESPONSE,
                        )
                    }
                }
            }
        }

    suspend fun downloadTheme(
        entry: ThemeStoreEntry,
        baseUrl: String,
        token: String,
        onProgress: (Float) -> Unit,
        onTransferred: (Long, Long) -> Unit = { _, _ -> },
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
                onTransferred(entry.size, entry.size)
                return@runCatching finalFile
            }
            finalFile.delete()

            val tempFile = File(downloadDir, "${finalFile.name}.part")
            val metaFile = File(downloadDir, "${finalFile.name}.part.meta")
            if (tempFile.isFile) {
                when {
                    tempFile.length() > entry.size -> {
                        tempFile.delete()
                        metaFile.delete()
                    }

                    tempFile.length() == entry.size && sha256Of(tempFile) == expectedSha -> {
                        metaFile.delete()
                        moveDownloadedFile(tempFile, finalFile)
                        onProgress(1f)
                        onTransferred(entry.size, entry.size)
                        return@runCatching finalFile
                    }

                    tempFile.length() == entry.size -> {
                        // A parallel attempt can leave the file at full length while
                        // still owning holes; only a legacy sequential file is corrupt
                        // when the checksum does not match.
                        if (!metaFile.isFile) {
                            tempFile.delete()
                            metaFile.delete()
                        }
                    }
                }
            }

            val resumeFrom = tempFile.takeIf { it.isFile }?.length() ?: 0L
            val downloaded = downloadThemePackage(
                entry = entry,
                url = base + entry.path.removePrefix("/"),
                token = token,
                tempFile = tempFile,
                metaFile = metaFile,
                resumeFrom = resumeFrom,
                expectedSha = expectedSha,
                onProgress = onProgress,
                onTransferred = onTransferred,
                allowRestart = resumeFrom > 0,
            )
            moveDownloadedFile(downloaded, finalFile)
            onProgress(1f)
            onTransferred(entry.size, entry.size)
            finalFile
        }
    }

    /**
     * Downloads a package using parallel ranged requests when the server supports them.
     * Mirrors often throttle a single connection, so a large package can take far longer
     * than its size suggests; ranged workers fetch independent chunks at the same time.
     * Servers that ignore `Range` transparently fall back to the single-stream download.
     */
    private fun downloadThemePackage(
        entry: ThemeStoreEntry,
        url: String,
        token: String,
        tempFile: File,
        metaFile: File,
        resumeFrom: Long,
        expectedSha: String,
        onProgress: (Float) -> Unit,
        onTransferred: (Long, Long) -> Unit,
        allowRestart: Boolean,
    ): File {
        val probe = probePackageRange(entry, url, token)
        if (probe.totalSize > 0L && probe.totalSize != entry.size) {
            tempFile.delete()
            metaFile.delete()
            throw IOException("Theme package size mismatch")
        }
        if (probe.rangesSupported &&
            entry.size >= MIN_PARALLEL_DOWNLOAD_BYTES &&
            (metaFile.isFile || resumeFrom == 0L)
        ) {
            return try {
                downloadThemePackageParallel(
                    entry = entry,
                    url = url,
                    token = token,
                    tempFile = tempFile,
                    metaFile = metaFile,
                    expectedSha = expectedSha,
                    onProgress = onProgress,
                    onTransferred = onTransferred,
                )
            } catch (_: RangeUnsupportedException) {
                // Some servers advertise ranges yet answer 200 on a chunk request.
                tempFile.delete()
                metaFile.delete()
                downloadThemePackageSequential(
                    entry, url, token, tempFile, 0, expectedSha,
                    onProgress, onTransferred, false,
                )
            }
        }
        // A parallel workspace stores chunks, not a prefix, so the sequential writer
        // cannot resume it. Start over rather than appending to the wrong offset.
        val sequentialResume = if (metaFile.isFile) {
            tempFile.delete()
            metaFile.delete()
            0L
        } else {
            resumeFrom
        }
        return downloadThemePackageSequential(
            entry = entry,
            url = url,
            token = token,
            tempFile = tempFile,
            resumeFrom = sequentialResume,
            expectedSha = expectedSha,
            onProgress = onProgress,
            onTransferred = onTransferred,
            allowRestart = sequentialResume > 0L || allowRestart,
        )
    }

    
    private fun probePackageRange(
        entry: ThemeStoreEntry,
        url: String,
        token: String,
    ): PackageRangeProbe {
        val request = Request.Builder()
            .url(url)
            .cacheControl(CacheControl.Builder().noCache().build())
            .header("Accept-Encoding", "identity")
            .header("Range", "bytes=0-0")
            .withToken(token)
            .build()
        downloadClient.newCall(request).execute().use { response ->
            if (response.code == 401) throw ThemeStoreUnauthorizedException()
            if (!response.isSuccessful) {
                throw IOException("HTTP ${response.code} for ${entry.path}")
            }
            if (response.code == 206) {
                return PackageRangeProbe(
                    totalSize = parseContentRangeTotal(response.header("Content-Range"))
                        ?: entry.size,
                    rangesSupported = true,
                )
            }
            // The server ignored Range and is sending the whole file; do not read it here.
            val total = response.body.contentLength()
            return PackageRangeProbe(
                totalSize = if (total > 0L) total else entry.size,
                rangesSupported = false,
            )
        }
    }

    private fun downloadThemePackageParallel(
        entry: ThemeStoreEntry,
        url: String,
        token: String,
        tempFile: File,
        metaFile: File,
        expectedSha: String,
        onProgress: (Float) -> Unit,
        onTransferred: (Long, Long) -> Unit,
    ): File {
        val totalSize = entry.size
        val chunkSize = DOWNLOAD_CHUNK_BYTES
        val chunkCount = (totalSize + chunkSize - 1L) / chunkSize
        if (chunkCount <= 0L) throw IOException("Invalid theme package size")

        val metaLock = Any()
        val completed = mutableSetOf<Long>()
        readDownloadMeta(metaFile)?.let { meta ->
            if (meta.sha256.equals(expectedSha, ignoreCase = true) &&
                meta.size == totalSize &&
                meta.chunkSize == chunkSize
            ) {
                val claimed = meta.completed.filter { it in 0L until chunkCount }
                // A missing or truncated data file cannot back any claimed chunk; drop
                // the marker instead of looping on a verification failure forever.
                val coverage = claimed.maxOfOrNull { index ->
                    index * chunkSize + chunkLength(totalSize, chunkSize, index)
                } ?: 0L
                if (tempFile.isFile && tempFile.length() >= coverage) {
                    completed.addAll(claimed)
                }
            }
        }

        val completedBytes = AtomicLong(
            completed.sumOf { chunkLength(totalSize, chunkSize, it) },
        )
        val chunkProgress = HashMap<Long, Long>()
        val reportLock = Any()
        var lastReportAt = 0L
        var lastTransferred = -1L

        fun report(force: Boolean) {
            synchronized(reportLock) {
                val now = System.nanoTime()
                if (!force && now - lastReportAt < DOWNLOAD_PROGRESS_INTERVAL_NANOS) return
                val inFlight = synchronized(chunkProgress) { chunkProgress.values.sum() }
                val transferred = (completedBytes.get() + inFlight).coerceIn(0L, totalSize)
                if (!force && transferred == lastTransferred) return
                lastReportAt = now
                lastTransferred = transferred
                onTransferred(transferred, totalSize)
                onProgress((transferred.toFloat() / totalSize).coerceIn(0f, 1f))
            }
        }

        synchronized(metaLock) {
            persistDownloadMeta(metaFile, expectedSha, totalSize, chunkSize, completed)
        }
        report(force = true)

        val pending = ConcurrentLinkedQueue<Long>()
        for (index in 0L until chunkCount) {
            if (index !in completed) pending.add(index)
        }
        if (pending.isEmpty()) {
            verifyDownloadedPackage(tempFile, metaFile, totalSize, expectedSha)
            metaFile.delete()
            return tempFile
        }

        val workers = minOf(DOWNLOAD_WORKERS, pending.size.coerceAtLeast(1))
        val pool = Executors.newFixedThreadPool(workers)
        try {
            val futures = (0 until workers).map {
                pool.submit {
                    RandomAccessFile(tempFile, "rw").use { file ->
                        while (!Thread.currentThread().isInterrupted) {
                            val index = pending.poll() ?: break
                            val start = index * chunkSize
                            val length = chunkLength(totalSize, chunkSize, index)
                            if (length <= 0L) continue
                            var attempt = 0
                            while (true) {
                                synchronized(chunkProgress) { chunkProgress[index] = 0L }
                                try {
                                    downloadPackageChunk(
                                        entry = entry,
                                        url = url,
                                        token = token,
                                        start = start,
                                        length = length,
                                        file = file,
                                        onBytes = { delta ->
                                            synchronized(chunkProgress) {
                                                chunkProgress.merge(index, delta, Long::plus)
                                            }
                                            report(force = false)
                                        },
                                    )
                                    synchronized(chunkProgress) { chunkProgress.remove(index) }
                                    synchronized(metaLock) {
                                        completed.add(index)
                                        completedBytes.addAndGet(length)
                                        persistDownloadMeta(
                                            metaFile,
                                            expectedSha,
                                            totalSize,
                                            chunkSize,
                                            completed,
                                        )
                                    }
                                    report(force = true)
                                    break
                                } catch (error: Exception) {
                                    synchronized(chunkProgress) { chunkProgress.remove(index) }
                                    report(force = true)
                                    if (error is ThemeStoreUnauthorizedException) throw error
                                    if (error is RangeUnsupportedException) throw error
                                    attempt++
                                    if (attempt >= DOWNLOAD_RETRIES) throw error
                                }
                            }
                        }
                    }
                }
            }
            for (future in futures) {
                try {
                    future.get()
                } catch (error: ExecutionException) {
                    val cause = error.cause
                    if (cause != null) throw cause
                    throw IOException(error)
                } catch (error: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw IOException("Download interrupted", error)
                }
            }
        } finally {
            pool.shutdownNow()
            runCatching { pool.awaitTermination(5, TimeUnit.SECONDS) }
        }

        report(force = true)
        verifyDownloadedPackage(tempFile, metaFile, totalSize, expectedSha)
        metaFile.delete()
        return tempFile
    }

    private fun downloadPackageChunk(
        entry: ThemeStoreEntry,
        url: String,
        token: String,
        start: Long,
        length: Long,
        file: RandomAccessFile,
        onBytes: (Long) -> Unit,
    ) {
        val end = start + length - 1L
        val request = Request.Builder()
            .url(url)
            .cacheControl(CacheControl.Builder().noCache().build())
            .header("Accept-Encoding", "identity")
            .header("Range", "bytes=$start-$end")
            .withToken(token)
            .build()
        downloadClient.newCall(request).execute().use { response ->
            if (response.code == 401) throw ThemeStoreUnauthorizedException()
            if (response.code == 416) {
                throw IOException("HTTP 416 for ${entry.path}")
            }
            if (response.code != 206) {
                if (response.isSuccessful) throw RangeUnsupportedException()
                throw IOException("HTTP ${response.code} for ${entry.path}")
            }
            if (parseContentRangeStart(response.header("Content-Range")) != start) {
                throw IOException("Invalid Content-Range for ${entry.path}")
            }
            val body = response.body
            val declared = body.contentLength()
            if (declared > 0L && declared > length) {
                throw IOException("Theme package is too large")
            }
            file.seek(start)
            var written = 0L
            body.byteStream().use { input ->
                val buffer = ByteArray(BUFFER_SIZE)
                while (true) {
                    if (Thread.currentThread().isInterrupted) {
                        throw IOException("Download cancelled")
                    }
                    val read = input.read(buffer)
                    if (read < 0) break
                    if (written + read > length) {
                        throw IOException("Theme package chunk is too large")
                    }
                    file.write(buffer, 0, read)
                    written += read
                    onBytes(read.toLong())
                }
            }
            if (written != length) {
                throw IOException("Theme package chunk is incomplete")
            }
        }
    }

    private fun verifyDownloadedPackage(
        tempFile: File,
        metaFile: File,
        size: Long,
        expectedSha: String,
    ) {
        if (tempFile.length() != size) {
            tempFile.delete()
            metaFile.delete()
            throw IOException("Theme package size mismatch")
        }
        if (sha256Of(tempFile) != expectedSha) {
            tempFile.delete()
            metaFile.delete()
            throw IOException("Theme package checksum mismatch")
        }
    }

    private fun chunkLength(totalSize: Long, chunkSize: Long, index: Long): Long =
        ThemeStoreRepository.chunkLength(totalSize, chunkSize, index)

    private fun readDownloadMeta(metaFile: File): ParallelDownloadMeta? =
        runCatching {
            if (!metaFile.isFile) return null
            json.decodeFromString(ParallelDownloadMeta.serializer(), metaFile.readText())
        }.getOrNull()

    private fun persistDownloadMeta(
        metaFile: File,
        sha256: String,
        size: Long,
        chunkSize: Long,
        completed: Set<Long>,
    ) {
        val meta = ParallelDownloadMeta(
            sha256 = sha256,
            size = size,
            chunkSize = chunkSize,
            completed = completed.sorted(),
        )
        val temp = File(metaFile.parentFile, metaFile.name + ".tmp")
        temp.writeText(json.encodeToString(meta))
        metaFile.delete()
        if (!temp.renameTo(metaFile)) {
            temp.copyTo(metaFile, overwrite = true)
            temp.delete()
        }
    }

    private class PackageRangeProbe(
        val totalSize: Long,
        val rangesSupported: Boolean,
    )

    /**
     * Streams a package to [tempFile], resuming from [resumeFrom] when the server honors
     * `Range`. Keeps the partial file on network failures so a later attempt can continue.
     */
    private fun downloadThemePackageSequential(
        entry: ThemeStoreEntry,
        url: String,
        token: String,
        tempFile: File,
        resumeFrom: Long,
        expectedSha: String,
        onProgress: (Float) -> Unit,
        onTransferred: (Long, Long) -> Unit,
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
            onTransferred(resumeFrom, entry.size)
        }

        downloadClient.newCall(requestBuilder.build()).execute().use { response ->
            if (response.code == 401) throw ThemeStoreUnauthorizedException()
            if (response.code == 416) {
                tempFile.delete()
                if (allowRestart) {
                    return downloadThemePackageSequential(
                        entry, url, token, tempFile, 0, expectedSha, onProgress, onTransferred, false,
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
                        return downloadThemePackageSequential(
                            entry, url, token, tempFile, 0, expectedSha, onProgress, onTransferred, false,
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
                onTransferred(0L, entry.size)
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
                        onTransferred(written, entry.size)
                    }
                }
            }

            if (written != entry.size) {
                if (allowRestart && offset > 0) {
                    tempFile.delete()
                    return downloadThemePackageSequential(
                        entry, url, token, tempFile, 0, expectedSha, onProgress, onTransferred, false,
                    )
                }
                tempFile.delete()
                throw IOException("Theme package size mismatch")
            }
            if (sha256Of(tempFile) != expectedSha) {
                if (allowRestart && offset > 0) {
                    tempFile.delete()
                    return downloadThemePackageSequential(
                        entry, url, token, tempFile, 0, expectedSha, onProgress, onTransferred, false,
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
        onTransferred: (Long, Long) -> Unit = { _, _ -> },
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

            val packageSize = submission.packageFile.length()
            val attachments = buildList {
                add("preview" to submission.previewFile)
                submission.avatarFile?.let { add("avatar" to it) }
                submission.screenshotFiles.forEach { add("screenshots" to it) }
            }
            require(submission.screenshotFiles.size <= 6) { "Too many screenshots" }
            require(attachments.all { it.second.isFile }) { "Upload image is missing" }
            val attachmentBytes = attachments.sumOf { it.second.length() }
            val overallSize = (packageSize + attachmentBytes).coerceAtLeast(1L)
            val uploader = bearerToken?.takeIf { it.isNotBlank() }?.let {
                ThemeStoreResumableUploader(uploadClient, base, it)
            }
            var completedBytes = 0L
            fun reportFile(bytes: Long) {
                val transferred = (completedBytes + bytes).coerceIn(0L, overallSize)
                onTransferred(transferred, overallSize)
                // The final multipart request starts the existing verification phase.
                onProgress((transferred.toFloat() / overallSize).coerceIn(0f, 0.99f))
            }
            val packageUpload = uploader?.upload(submission.packageFile) { bytes, _ -> reportFile(bytes) }
            val resumableUploadId = packageUpload?.uploadId
            if (resumableUploadId != null) {
                completedBytes = packageSize
                builder.addFormDataPart("uploadId", resumableUploadId)
            } else {
                builder.addFormDataPart(
                    "package", submission.packageFile.name,
                    submission.packageFile.asRequestBody("application/octet-stream".toMediaType()),
                )
            }
            val referencedAttachments = packageUpload?.supportsAttachments == true
            for ((field, file) in attachments) {
                if (referencedAttachments) {
                    val uploaded = requireNotNull(uploader).upload(file) { bytes, _ -> reportFile(bytes) }
                    builder.addFormDataPart(
                        if (field == "screenshots") "screenshotUploadId" else field + "UploadId",
                        uploaded.uploadId,
                    )
                    completedBytes += file.length()
                } else {
                    builder.addFormDataPart(
                        field, file.name, file.asRequestBody("application/octet-stream".toMediaType()),
                    )
                }
            }

            val endpoint = if (!bearerToken.isNullOrBlank()) "account/api/submit" else "submit"
            val progressBody = ProgressRequestBody(builder.build()) { progress, written, total ->
                if (referencedAttachments) {
                    onTransferred(overallSize, overallSize)
                    onProgress(if (progress >= 1f) 1f else 0.99f)
                } else if (resumableUploadId != null) {
                    // Keep one stable total (package + attachments) instead of
                    // jumping at the 95% boundary; the multipart progress maps to
                    // the attachment bytes.
                    val transferred = packageSize + (attachmentBytes * progress).toLong()
                    onTransferred(transferred, overallSize)
                    onProgress((transferred.toFloat() / overallSize).coerceIn(0f, 1f))
                } else {
                    if (total > 0L) onTransferred(written, total)
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

            executeThemeUpload(uploadClient, request) { response ->
                if (response.code == 401) throw ThemeStoreUnauthorizedException()
                val raw = response.uploadJson()
                val parsed = runCatching {
                    json.decodeFromString(ThemeStoreSubmitResponse.serializer(), raw)
                }.getOrNull()
                if (!response.isSuccessful) {
                    throw IOException(
                        parsed?.error?.takeIf { it.isNotBlank() }
                            ?: "HTTP ${response.code} while submitting theme",
                    )
                }
                parsed ?: throw IOException("Invalid theme submission response")
            }
        }.onFailure { if (it is CancellationException) throw it }
    }


    private fun fetchCatalog(base: String, token: String): CatalogFetch {
        val cacheFile = catalogCacheFile(base)
        val cachedEtag = catalogCacheEtagFile(base)
            .takeIf { it.isFile }
            ?.let { runCatching { it.readText().trim() }.getOrNull() }
            ?.takeIf { it.isNotEmpty() }
        val cachedCatalog = if (cacheFile.isFile && cachedEtag != null) {
            runCatching {
                val catalog = json.decodeFromString(
                    ThemeStoreCatalog.serializer(),
                    cacheFile.readText(),
                )
                catalog.takeIf { it.schema <= 1 }
            }.getOrNull()
        } else {
            null
        }
        val requestBuilder = Request.Builder()
            .url(base + "catalog.json")
            .cacheControl(CacheControl.Builder().noCache().build())
            .withToken(token)
        if (cachedCatalog != null && cachedEtag != null) {
            requestBuilder.header("If-None-Match", cachedEtag)
        }
        val response = catalogClient.newCall(requestBuilder.build()).execute()
        response.use { response ->
            if (response.code == 304) {
                return CatalogFetch(
                    catalog = cachedCatalog
                        ?: throw IOException("HTTP 304 without cached catalog"),
                    notModified = true,
                )
            }
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
            val raw = source.readUtf8()
            val catalog = json.decodeFromString(ThemeStoreCatalog.serializer(), raw)
            if (catalog.schema > 1) throw IOException("Unsupported theme catalog schema")
            writeCatalogCache(base, raw)
            writeCatalogEtag(base, response.header("ETag"))
            return CatalogFetch(catalog, notModified = false)
        }
    }

    private fun catalogCacheFile(base: String): File =
        File(cacheDir, "catalog-${base.hashCode().toUInt().toString(16)}.json")

    private fun catalogCacheEtagFile(base: String): File =
        File(cacheDir, "catalog-${base.hashCode().toUInt().toString(16)}.etag")

    private fun writeCatalogEtag(base: String, etag: String?) {
        runCatching {
            val file = catalogCacheEtagFile(base)
            val value = etag?.trim().orEmpty()
            if (value.isEmpty()) {
                file.delete()
            } else {
                cacheDir.mkdirs()
                file.writeText(value)
            }
        }
    }

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
            // A resumable download owns both the data file and its chunk marker.
            val maxAge = if (file.isPartialDownload()) week else day
            if (file.isOlderThan(maxAge, now)) runCatching { file.delete() }
        }
        trimDownloadCache(now)
        cacheDir.listFiles()?.forEach { file ->
            if (!file.isFile) return@forEach
            when {
                file.name.startsWith("catalog-") &&
                    (file.name.endsWith(".json") || file.name.endsWith(".etag")) &&
                    file.isOlderThan(30L * day, now) -> runCatching { file.delete() }

                // The upload screen's "current preset" export lives directly in cacheDir and
                // is not covered by the theme_import_* temporary-file rule above.
                file.name == "theme_upload_preset.sukisu" &&
                    file.isOlderThan(day, now) -> runCatching { file.delete() }

                file.name.startsWith("theme_upload_adaptive_") &&
                    file.name.endsWith(".sukisu") &&
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
            // The marker is deleted together with its data file.
            .filter { !it.name.endsWith(".part.meta") }
            .filter { it.isOlderThan(ACTIVE_CACHE_GRACE_MS, now) }
            .sortedWith(
                compareBy<File> { it.isPartialDownload() }
                    .thenBy { it.lastModified() },
            )
        for (file in candidates) {
            if (total <= MAX_DOWNLOAD_CACHE_BYTES) break
            val size = file.length()
            if (runCatching { file.delete() }.getOrDefault(false)) {
                total -= size
                if (file.name.endsWith(".part")) {
                    val meta = File(file.parentFile, file.name + ".meta")
                    if (meta.isFile) {
                        val metaSize = meta.length()
                        if (runCatching { meta.delete() }.getOrDefault(false)) {
                            total -= metaSize
                        }
                    }
                }
            }
        }
    }

    private fun File.isPartialDownload(): Boolean =
        name.endsWith(".part") || name.endsWith(".part.meta")

    private fun File.isOlderThan(maxAgeMillis: Long, now: Long): Boolean {
        val modified = lastModified()
        return modified > 0L && now - modified > maxAgeMillis
    }

    private fun Request.Builder.withToken(token: String): Request.Builder = apply {
        val resolved=access.forRequest(build().url.toString(), token)
        if (resolved.isNotBlank()) header(TOKEN_HEADER, resolved)
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
