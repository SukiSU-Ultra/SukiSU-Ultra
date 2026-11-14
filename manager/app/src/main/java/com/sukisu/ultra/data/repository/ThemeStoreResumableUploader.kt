package com.sukisu.ultra.data.repository

import com.sukisu.ultra.data.model.ThemeStoreUploadAck
import com.sukisu.ultra.data.model.ThemeStoreUploadComplete
import com.sukisu.ultra.data.model.ThemeStoreUploadInitRequest
import com.sukisu.ultra.data.model.ThemeStoreUploadSession
import com.sukisu.ultra.data.model.ThemeStoreUploadTarget
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.Callback
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okio.BufferedSink
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Each call belongs to the coroutine, including while receiving its response body. */
internal suspend fun <T> executeThemeUpload(
    client: OkHttpClient,
    request: Request,
    decode: (Response) -> T,
): T = suspendCancellableCoroutine { continuation ->
    val call = client.newCall(request)
    continuation.invokeOnCancellation { call.cancel() }
    call.enqueue(object : Callback {
        override fun onFailure(call: Call, e: IOException) {
            continuation.resumeWithException(e)
        }

        override fun onResponse(call: Call, response: Response) {
            try {
                val value = response.use(decode)
                continuation.resume(value)
            } catch (error: Exception) {
                continuation.resumeWithException(error)
            }
        }
    })
}

internal fun Response.uploadJson(): String {
    val source = body.source()
    if (source.request(64L * 1024L + 1L)) throw IOException("Upload response is too large")
    return source.readUtf8()
}

internal data class ThemeStoreUploadedFile(val uploadId: String, val supportsAttachments: Boolean)

/**
 * A rejected chunk request. A 4xx is the server saying "this request is wrong",
 * so switching ingress only repeats the same failure and poisons the route
 * statistics. Only timeouts and 5xx/429 are worth another route.
 */
internal class ThemeUploadHttpException(val status: Int, message: String) : IOException(message) {
    val retryable: Boolean
        get() = status == 408 || status == 425 || status == 429 || status >= 500
}

/** Account-only, bounded multi-ingress upload. Publication and all database writes stay primary. */
internal class ThemeStoreResumableUploader(
    primaryClient: OkHttpClient,
    private val base: String,
    private val bearerToken: String,
) {
    companion object {
        private const val MIB = 1024L * 1024L
        private const val MAX_WORKERS = 4
        private val ID = Regex("^[0-9a-fA-F]{8,64}$")
        private val HASH = Regex("^[0-9a-fA-F]{64}$")
        private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()
        private val CHUNK_MEDIA = "application/octet-stream".toMediaType()
        private val json = Json { ignoreUnknownKeys = true }

        // Do not clone the account client: cookies, interceptors and authenticators
        // must never cross this boundary. Redirects cannot forward a capability either.
        private fun edgeClient(): OkHttpClient = OkHttpClient.Builder()
            .protocols(listOf(Protocol.HTTP_1_1))
            .followRedirects(false)
            .followSslRedirects(false)
            .connectTimeout(15, TimeUnit.SECONDS)
            // Waiting for the edge to fsync and acknowledge a large chunk is not a
            // dead connection; 30 s was short enough to make bursts look like failures.
            .readTimeout(120, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .callTimeout(10, TimeUnit.MINUTES)
            .retryOnConnectionFailure(false)
            .build()

        private val sharedEdgeClient by lazy { edgeClient() }

        internal fun targetUrl(target: ThemeStoreUploadTarget, uploadId: String): HttpUrl? {
            val url = target.baseUrl.toHttpUrlOrNull() ?: return null
            if (url.scheme != "https" && !(url.scheme == "http" && url.host in
                    setOf("localhost", "127.0.0.1", "::1"))) return null
            if (url.username.isNotEmpty() || url.password.isNotEmpty() ||
                url.query != null || url.fragment != null) return null
            if (!ID.matches(uploadId) || !url.encodedPath.endsWith("/_edge/uploads/$uploadId")) return null
            if (target.id.isBlank() || target.ticket.isBlank() || target.ticket.length > 8192 ||
                target.ticket.any { it.code !in 33..126 }) return null
            return url
        }
    }

    private val primary = primaryClient.newBuilder()
        .cache(null)
        .followRedirects(false)
        .followSslRedirects(false)
        .retryOnConnectionFailure(false)
        .callTimeout(10, TimeUnit.MINUTES)
        .build()
    private val edge = sharedEdgeClient
    private val scheduler = Routes()

    private class RouteHealth {
        var active = 0
        var speed = 0.0
        var cooldownUntil = 0L
    }

    private class Route(val url: HttpUrl, val ticket: String?, val health: RouteHealth)

    private class Routes {
        private var cursor = 0
        private val history = HashMap<String, RouteHealth>()

        @Synchronized fun route(url: HttpUrl, ticket: String? = null): Route {
            // Preserve measurements across the package and its small images, while
            // using each new session's scoped URL and ticket. Small files can then
            // use a faster edge instead of always starting at the primary again.
            val key = url.newBuilder().removePathSegment(url.pathSegments.lastIndex).build().toString()
            return Route(url, ticket, history.getOrPut(key) { RouteHealth() })
        }

        @Synchronized fun acquire(all: List<Route>, attempted: Set<Route>, onlyPrimary: Boolean): Route {
            val candidates = if (onlyPrimary) emptyList() else all.filter {
                it !in attempted && it.health.cooldownUntil <= System.nanoTime()
            }
            val bestSpeed = all.maxOf { it.health.speed }.coerceAtLeast(256.0 * 1024)
            val start = if (candidates.isEmpty()) 0 else cursor++ % candidates.size
            val route = if (candidates.isEmpty()) all.first() else
                (candidates.drop(start) + candidates.take(start)).minBy {
                    (it.health.active + 1) / (it.health.speed.takeIf { speed -> speed > 0 } ?: bestSpeed)
                }
            route.health.active++
            return route
        }

        @Synchronized fun finish(route: Route, bytes: Long, elapsed: Long, success: Boolean, fault: Boolean) {
            val health = route.health
            health.active--
            if (success) {
                val speed = bytes * 1_000_000_000.0 / elapsed.coerceAtLeast(1L)
                health.speed = if (health.speed == 0.0) speed else health.speed * 0.6 + speed * 0.4
                health.cooldownUntil = 0L
            } else if (fault) {
                // Only transport/5xx faults cool a route. A rejected 4xx is the
                // request's fault and must not send every later chunk elsewhere.
                health.cooldownUntil = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
            }
        }

        @Synchronized fun fastestOther(all: List<Route>, route: Route): Double = all.filter {
            it !== route && it.health.cooldownUntil <= System.nanoTime()
        }.maxOfOrNull { it.health.speed } ?: 0.0
    }

    suspend fun upload(file: File, onTransferred: (Long, Long) -> Unit): ThemeStoreUploadedFile {
        val size = file.length()
        val limit = when (file.extension.lowercase()) {
            "sukisu" -> 128L * MIB
            "png", "jpg", "jpeg", "webp" -> 12L * MIB
            else -> throw IOException("Unsupported upload file type")
        }
        if (!file.isFile || size !in 1L..limit) throw IOException("Invalid upload file size")
        val session = init(file, size)
        val chunkSize = session.chunkSize
        if (!session.ok || !ID.matches(session.uploadId) || chunkSize !in MIB..8L * MIB ||
            session.size != size || session.totalChunks != (size + chunkSize - 1) / chunkSize) {
            throw IOException("Upload session does not match the selected file")
        }
        fun length(index: Long) = minOf(chunkSize, size - index * chunkSize)
        fun validIndices(indices: List<Long>): Set<Long> {
            if (indices.any { it !in 0 until session.totalChunks }) {
                throw IOException("Invalid upload chunk index")
            }
            return indices.toSet()
        }
        val confirmed = validIndices(session.received).toMutableSet()
        val progress = HashMap<Long, Long>()
        val lock = Any()
        var lastReportAt = 0L
        fun report(force: Boolean = false) = synchronized(lock) {
            val now = System.nanoTime()
            if (force || now - lastReportAt >= 100_000_000L) {
                val bytes = confirmed.sumOf(::length) + progress.values.sum()
                onTransferred(bytes.coerceIn(0L, size), size)
                lastReportAt = now
            }
        }
        val routes = mutableListOf(scheduler.route((base + "account/api/uploads/${session.uploadId}").toHttpUrlOrNull()
            ?: throw IOException("Invalid upload URL")))
        val seen = mutableSetOf<String>()
        for (target in session.uploadTargets.orEmpty().take(16)) {
            val url = targetUrl(target, session.uploadId) ?: continue
            if (seen.add(url.toString())) routes.add(scheduler.route(url, target.ticket))
        }
        suspend fun transfer(indices: Collection<Long>, onlyPrimary: Boolean = false) = coroutineScope {
            val pending = ConcurrentLinkedQueue(indices)
            (0 until minOf(MAX_WORKERS, indices.size)).map {
                async {
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val index = pending.poll() ?: break
                        val attempted = mutableSetOf<Route>()
                        val bytes = length(index)
                        val maxAttempts = if (onlyPrimary) 3 else maxOf(3, routes.size + 1)
                        for (attempt in 0 until maxAttempts) {
                            currentCoroutineContext().ensureActive()
                            val route = scheduler.acquire(routes, attempted, onlyPrimary)
                            val started = System.nanoTime()
                            val lastWrite = AtomicLong(started)
                            var success = false
                            var fault = false
                            try {
                                sendChunk(route, routes, session.uploadId, index, file,
                                    index * chunkSize, bytes, started, lastWrite) { delta ->
                                    synchronized(lock) {
                                        progress[index] = ((progress[index] ?: 0L) + delta).coerceAtMost(bytes)
                                        report()
                                    }
                                }
                                success = true
                                synchronized(lock) {
                                    progress.remove(index)
                                    confirmed.add(index)
                                    report(true)
                                }
                                break
                            } catch (error: Exception) {
                                synchronized(lock) { progress.remove(index); report(true) }
                                val rejected = error is ThemeUploadHttpException && !error.retryable
                                val abort = error is CancellationException ||
                                    error is ThemeStoreUnauthorizedException
                                fault = !(rejected || abort)
                                if (abort || rejected || attempt == maxAttempts - 1) throw error
                                attempted.add(route)
                                // Give a transient network or edge hiccup a moment before
                                // it is retried, instead of hammering the same queue.
                                delay(300L * (attempt + 1))
                            } finally {
                                scheduler.finish(route, bytes, System.nanoTime() - started, success, fault)
                            }
                        }
                    }
                }
            }.awaitAll()
        }
        report(true)
        transfer((0 until session.totalChunks).filter { it !in confirmed })
        // Even an entirely resumed session may contain receipts for an offline edge.
        // A receipt is not a merged file; repair only the missing chunks at the primary.
        if (session.uploadTargets != null) {
            var result = complete(session.uploadId)
            if (!result.complete) {
                val missing = validIndices(result.missing)
                if (missing.isEmpty()) throw IOException("Upload merge did not report missing chunks")
                synchronized(lock) { confirmed.removeAll(missing); report(true) }
                transfer(missing, onlyPrimary = true)
                result = complete(session.uploadId)
            }
            if (!result.complete || result.missing.isNotEmpty()) throw IOException("Upload merge is incomplete")
        }
        report(true)
        return ThemeStoreUploadedFile(session.uploadId, session.uploadTargets != null)
    }

    private fun accountRequest(path: String) = Request.Builder()
        .url(base + "account/api/uploads/" + path)
        .header("Authorization", "Bearer $bearerToken")
        .header("X-Requested-With", "SukiSUThemeAdmin")
        .header("X-Client", "android")

    private suspend fun init(file: File, size: Long): ThemeStoreUploadSession {
        // Larger packages use 8 MB chunks: the per-request overhead (authorization,
        // receipt check, fsync, ack) otherwise dominates on slow links and makes the
        // displayed speed oscillate. Images stay on 2 MB so their tail is short.
        val chunkSize = when {
            size < 16L * MIB -> 2L * MIB
            size >= 64L * MIB -> 8L * MIB
            else -> 4L * MIB
        }
        val body = json.encodeToString(ThemeStoreUploadInitRequest.serializer(), ThemeStoreUploadInitRequest(
            filename = file.name,
            size = size,
            fingerprint = "${file.name}:$size:${file.lastModified()}",
            chunkSize = chunkSize,
        )).toRequestBody(JSON_MEDIA)
        return executeThemeUpload(primary, accountRequest("init").post(body).build()) { response ->
            if (response.code == 401) throw ThemeStoreUnauthorizedException()
            val value = json.decodeFromString(ThemeStoreUploadSession.serializer(), response.uploadJson())
            if (!response.isSuccessful || !value.ok) throw IOException(value.error ?: "Upload initialization rejected (${response.code})")
            value
        }
    }

    private suspend fun complete(id: String): ThemeStoreUploadComplete =
        executeThemeUpload(primary, accountRequest("$id/complete").post("{}".toRequestBody(JSON_MEDIA)).build()) { response ->
            if (response.code == 401) throw ThemeStoreUnauthorizedException()
            val value = json.decodeFromString(ThemeStoreUploadComplete.serializer(), response.uploadJson())
            if (!response.isSuccessful || !value.ok) throw IOException(value.error ?: "Upload merge rejected (${response.code})")
            value
        }

    private suspend fun sendChunk(
        route: Route, routes: List<Route>, uploadId: String, index: Long, file: File,
        offset: Long, length: Long, started: Long, lastWrite: AtomicLong, onBytes: (Long) -> Unit,
    ) = coroutineScope {
        val sent = java.util.concurrent.atomic.AtomicBoolean(false)
        val body = object : RequestBody() {
            override fun contentType() = CHUNK_MEDIA
            override fun contentLength() = length
            override fun writeTo(sink: BufferedSink) {
                RandomAccessFile(file, "r").use { source ->
                    source.seek(offset)
                    val buffer = ByteArray(128 * 1024)
                    var remaining = length
                    var sinceFlush = 0L
                    while (remaining > 0L) {
                        if (Thread.currentThread().isInterrupted) throw IOException("Upload interrupted")
                        val read = source.read(buffer, 0, minOf(remaining, buffer.size.toLong()).toInt())
                        if (read <= 0) throw IOException("Unexpected end of upload file")
                        sink.write(buffer, 0, read)
                        onBytes(read.toLong())
                        lastWrite.set(System.nanoTime())
                        remaining -= read
                        sinceFlush += read
                        if (sinceFlush >= 256 * 1024) { sink.flush(); sinceFlush = 0 }
                    }
                    sink.flush()
                    sent.set(true)
                }
            }
        }
        val builder = if (route.ticket == null) accountRequest("$uploadId/$index") else
            Request.Builder().url(route.url.newBuilder().addPathSegment(index.toString()).build())
                .header("X-Sukisu-Upload-Ticket", route.ticket)
        val request = builder.post(body).build()
        val sending = async {
            executeThemeUpload(if (route.ticket == null) primary else edge, request) { response ->
                if (route.ticket == null && response.code == 401) throw ThemeStoreUnauthorizedException()
                if (!response.isSuccessful) {
                    throw ThemeUploadHttpException(
                        response.code,
                        "Chunk upload rejected (${response.code})",
                    )
                }
                val ack = json.decodeFromString(ThemeStoreUploadAck.serializer(), response.uploadJson())
                if (!ack.ok || (route.ticket != null && (ack.index != index || !HASH.matches(ack.sha256)))) {
                    throw IOException("Invalid chunk acknowledgement")
                }
            }
        }
        val watchdog = launch {
            while (isActive) {
                delay(1000)
                val now = System.nanoTime()
                val fastest = scheduler.fastestOther(routes, route)
                val elapsed = (now - started) / 1_000_000_000.0
                // Compare against a generous multiple of the best other route and
                // require at least 25 s, so a noisy speed sample cannot abort a
                // healthy worker and restart the chunk on yet another ingress.
                val tooSlow = fastest > 0 && elapsed > maxOf(25.0, length / fastest * 3)
                // Waiting for the acknowledgement is not a dead transfer; the
                // request body has already been written and the read timeout applies.
                val stalled = !sent.get() && now - lastWrite.get() > TimeUnit.SECONDS.toNanos(45)
                if (stalled || tooSlow) {
                    throw IOException("Upload route stalled; retrying another ingress")
                }
            }
        }
        try { sending.await() } finally { watchdog.cancel() }
    }
}
