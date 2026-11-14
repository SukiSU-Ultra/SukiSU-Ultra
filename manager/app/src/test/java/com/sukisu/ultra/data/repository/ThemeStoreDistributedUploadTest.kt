package com.sukisu.ultra.data.repository

import com.sukisu.ultra.data.model.ThemeStoreUploadSession
import com.sukisu.ultra.data.model.ThemeStoreUploadTarget
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class ThemeStoreDistributedUploadTest {
    @get:Rule val temporary = TemporaryFolder()
    private val id = "ab".repeat(16)
    private val chunk = 1024 * 1024
    private val json = Json { ignoreUnknownKeys = true }

    private class Server(handler: (HttpExchange) -> Unit) : Closeable {
        private val executor = Executors.newCachedThreadPool()
        private val http = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
            this.executor = this@Server.executor
            createContext("/") { exchange ->
                try { handler(exchange) } finally { exchange.close() }
            }
            start()
        }
        val url get() = "http://127.0.0.1:${http.address.port}"
        override fun close() { http.stop(0); executor.shutdownNow() }
    }

    private fun HttpExchange.reply(value: String, code: Int = 200) {
        val bytes = value.toByteArray()
        responseHeaders.set("Content-Type", "application/json")
        sendResponseHeaders(code, bytes.size.toLong())
        responseBody.use { it.write(bytes) }
    }

    private fun file(bytes: Int = chunk * 6 + 37, name: String = "theme.sukisu"): File =
        temporary.newFile(name).apply { writeBytes(ByteArray(bytes) { (it * 31).toByte() }) }

    private fun session(file: File, edge: String? = null, received: List<Int> = emptyList(), legacy: Boolean = false): String =
        buildJsonObject {
            put("ok", true); put("uploadId", id); put("size", file.length())
            put("chunkSize", chunk); put("totalChunks", (file.length() + chunk - 1) / chunk)
            putJsonArray("received") { received.forEach { add(kotlinx.serialization.json.JsonPrimitive(it)) } }
            if (!legacy) putJsonArray("uploadTargets") {
                if (edge != null) add(buildJsonObject {
                    put("id", "edge"); put("baseUrl", "$edge/_edge/uploads/$id"); put("ticket", "scoped-ticket")
                })
            }
        }.toString()

    private fun ack(bytes: ByteArray, index: Int) = buildJsonObject {
        put("ok", true); put("nodeId", "edge"); put("index", index)
        put("sha256", MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) })
    }.toString()

    @Test fun newAndLegacyCapabilitiesRemainDistinct() {
        assertNull(json.decodeFromString<ThemeStoreUploadSession>("{\"ok\":true}").uploadTargets)
        assertEquals(emptyList<ThemeStoreUploadTarget>(),
            json.decodeFromString<ThemeStoreUploadSession>("{\"ok\":true,\"uploadTargets\":[]}").uploadTargets)
    }

    @Test fun rejectsUnsafeTargetsAndPreservesProxyPrefix() {
        fun valid(url: String, ticket: String = "scoped-ticket") = ThemeStoreResumableUploader.targetUrl(
            ThemeStoreUploadTarget(id = "edge", baseUrl = url, ticket = ticket), id,
        )
        val path = "/_edge/uploads/$id"
        for (url in listOf("http://edge.example$path", "https://user:pass@edge.example$path",
            "https://edge.example$path?ticket=x", "https://edge.example$path#fragment",
            "https://edge.example/_edge/uploads/other", "https://edge.example$path/0")) {
            assertNull(url, valid(url))
        }
        assertNull(valid("https://edge.example$path", "bad\r\nheader"))
        assertNotNull(valid("https://edge.example/cache$path"))
        assertNotNull(valid("http://127.0.0.1:8080$path"))
        assertNotNull(valid("http://[::1]:8080$path"))
    }

    @Test fun sendsDistinctChunksConcurrentlyAndIsolatesEdgeCredentials() = runBlocking {
        val file = file()
        val original = file.readBytes()
        val local = ConcurrentHashMap<Int, ByteArray>()
        val remote = ConcurrentHashMap<Int, ByteArray>()
        val active = AtomicInteger()
        val peak = AtomicInteger()
        val complete = AtomicInteger()
        val leaked = Collections.synchronizedList(mutableListOf<String>())
        fun receive(exchange: HttpExchange, target: MutableMap<Int, ByteArray>, isEdge: Boolean) {
            val n = active.incrementAndGet(); peak.accumulateAndGet(n, ::maxOf)
            try {
                val bytes = exchange.requestBody.readBytes()
                val index = exchange.requestURI.path.substringAfterLast('/').toInt()
                if (isEdge) {
                    for (header in listOf("Authorization", "Cookie", "X-Sukisu-Theme-Token", "X-Primary-Secret")) {
                        exchange.requestHeaders.getFirst(header)?.let { leaked.add(header) }
                    }
                    if (exchange.requestHeaders.getFirst("X-Sukisu-Upload-Ticket") != "scoped-ticket") leaked.add("ticket missing")
                } else if (exchange.requestHeaders.getFirst("Authorization") != "Bearer account-secret") leaked.add("primary auth missing")
                Thread.sleep(if (isEdge) 10 else 100)
                target[index] = bytes
                exchange.reply(ack(bytes, index))
            } finally { active.decrementAndGet() }
        }
        Server { receive(it, remote, true) }.use { edge ->
            Server { exchange ->
                when {
                    exchange.requestURI.path.endsWith("/init") -> exchange.reply(session(file, edge.url))
                    exchange.requestURI.path.endsWith("/complete") -> { complete.incrementAndGet(); exchange.reply("{\"ok\":true,\"complete\":true}") }
                    else -> receive(exchange, local, false)
                }
            }.use { primary ->
                val client = OkHttpClient.Builder().cookieJar(object : CookieJar {
                    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) = Unit
                    override fun loadForRequest(url: HttpUrl) = listOf(Cookie.Builder()
                        .name("session").value("account-secret").hostOnlyDomain(url.host).build())
                }).addInterceptor { it.proceed(it.request().newBuilder()
                    .header("X-Primary-Secret", "secret").header("X-Sukisu-Theme-Token", "master").build()) }.build()
                val reports = Collections.synchronizedList(mutableListOf<Long>())
                val result = withTimeout(10_000) {
                    ThemeStoreResumableUploader(client, primary.url + "/", "account-secret").upload(file) { bytes, total ->
                        assertEquals(file.length(), total); reports.add(bytes)
                    }
                }
                assertEquals(id, result.uploadId); assertTrue(result.supportsAttachments)
                assertTrue("primary used", local.isNotEmpty()); assertTrue("edge used", remote.isNotEmpty())
                assertTrue("concurrency bounded", peak.get() in 2..4)
                assertTrue("no account secrets at edge: $leaked", leaked.isEmpty())
                val combined = local.toMutableMap().apply { putAll(remote) }
                assertEquals(7, combined.size)
                combined.forEach { (index, bytes) ->
                    assertArrayEquals(original.copyOfRange(index * chunk, minOf(original.size, (index + 1) * chunk)), bytes)
                }
                assertEquals(1, complete.get()); assertEquals(file.length(), reports.last())
                assertTrue(reports.all { it in 0..file.length() })
            }
        }
    }

    @Test fun edge401403429AndFailuresFallBackWithoutInvalidatingAccount() = runBlocking {
        val file = file(chunk + 7)
        for (status in listOf(401, 403, 404, 409, 429, 503)) {
            val local = ConcurrentHashMap.newKeySet<Int>()
            val edgeCalls = AtomicInteger()
            Server { exchange ->
                edgeCalls.incrementAndGet(); exchange.requestBody.readBytes(); exchange.reply("{}", status)
            }.use { edge ->
                Server { exchange ->
                    when {
                        exchange.requestURI.path.endsWith("/init") -> exchange.reply(session(file, edge.url))
                        exchange.requestURI.path.endsWith("/complete") -> exchange.reply("{\"ok\":true,\"complete\":true}")
                        else -> {
                            exchange.requestBody.readBytes(); local.add(exchange.requestURI.path.substringAfterLast('/').toInt())
                            exchange.reply("{\"ok\":true}")
                        }
                    }
                }.use { primary ->
                    withTimeout(10_000) { ThemeStoreResumableUploader(OkHttpClient(), primary.url + "/", "account")
                        .upload(file) { _, _ -> } }
                    assertTrue("edge was tried ($status)", edgeCalls.get() > 0)
                    assertEquals(setOf(0, 1), local)
                }
            }
        }
    }

    @Test fun primary401IsNotRetriedAsAnEdgeFailure() = runBlocking {
        val file = file(7)
        for (phase in listOf("init", "0", "complete")) {
            Server { exchange ->
                exchange.requestBody.readBytes()
                when (exchange.requestURI.path.substringAfterLast('/')) {
                    phase -> exchange.reply("{}", 401)
                    "init" -> exchange.reply(session(file))
                    else -> exchange.reply("{\"ok\":true}")
                }
            }.use { primary ->
                try {
                    ThemeStoreResumableUploader(OkHttpClient(), primary.url + "/", "expired").upload(file) { _, _ -> }
                    fail("expected authentication failure at $phase")
                } catch (_: ThemeStoreUnauthorizedException) { }
            }
        }
    }

    @Test fun resumedReceiptsStillCompleteAndRepairOnlyMissingAtPrimary() = runBlocking {
        val file = file(chunk * 2 + 7)
        val uploads = Collections.synchronizedList(mutableListOf<Int>())
        val completes = AtomicInteger()
        Server { exchange ->
            when {
                exchange.requestURI.path.endsWith("/init") -> exchange.reply(session(file, received = listOf(0, 1, 2)))
                exchange.requestURI.path.endsWith("/complete") -> exchange.reply(
                    if (completes.incrementAndGet() == 1) "{\"ok\":true,\"complete\":false,\"missing\":[1,1]}"
                    else "{\"ok\":true,\"complete\":true,\"missing\":[]}")
                else -> { exchange.requestBody.readBytes(); uploads.add(exchange.requestURI.path.substringAfterLast('/').toInt()); exchange.reply("{\"ok\":true}") }
            }
        }.use { primary ->
            val reports = mutableListOf<Long>()
            val result = ThemeStoreResumableUploader(OkHttpClient(), primary.url + "/", "account").upload(file) { b, _ -> reports.add(b) }
            assertTrue(result.supportsAttachments)
            assertEquals(listOf(1), uploads); assertEquals(2, completes.get())
            assertEquals(file.length(), reports.last()); assertTrue(reports.contains(file.length() - chunk))
        }
    }

    @Test fun legacySessionSkipsUnsupportedCompletionAndAttachmentReferences() = runBlocking {
        val file = file(37)
        val paths = Collections.synchronizedList(mutableListOf<String>())
        Server { exchange ->
            paths.add(exchange.requestURI.path)
            if (exchange.requestURI.path.endsWith("/init")) exchange.reply(session(file, legacy = true)) else {
                exchange.requestBody.readBytes(); exchange.reply("{\"ok\":true}")
            }
        }.use { primary ->
            val result = ThemeStoreResumableUploader(OkHttpClient(), primary.url + "/", "account").upload(file) { _, _ -> }
            assertFalse(result.supportsAttachments); assertEquals(2, paths.size)
            assertTrue(paths.none { it.endsWith("/complete") })
        }
    }

    @Test fun allImageKindsUseTheSameCompletionProtocol() = runBlocking {
        val files = listOf(file(37), file(19, "preview.png"), file(23, "avatar.webp"), file(29, "screenshot.jpg"))
        val initNames = mutableListOf<String>()
        val completes = AtomicInteger()
        Server { exchange ->
            when {
                exchange.requestURI.path.endsWith("/init") -> {
                    val request = json.parseToJsonElement(exchange.requestBody.readBytes().decodeToString()).toString()
                    val file = files.first { request.contains(it.name) }
                    initNames.add(file.name); exchange.reply(session(file))
                }
                exchange.requestURI.path.endsWith("/complete") -> { completes.incrementAndGet(); exchange.reply("{\"ok\":true,\"complete\":true}") }
                else -> { exchange.requestBody.readBytes(); exchange.reply("{\"ok\":true}") }
            }
        }.use { primary ->
            val uploader = ThemeStoreResumableUploader(OkHttpClient(), primary.url + "/", "account")
            files.forEach { assertTrue(uploader.upload(it) { _, _ -> }.supportsAttachments) }
            assertEquals(files.map { it.name }, initNames); assertEquals(4, completes.get())
        }
    }

    @Test fun cancellationStopsRequestsAndNeverCompletesTheSession() = runBlocking {
        val file = file(chunk * 3)
        val started = CompletableDeferred<Unit>()
        val completes = AtomicInteger()
        val activeClient = OkHttpClient()
        Server { exchange ->
            when {
                exchange.requestURI.path.endsWith("/init") -> exchange.reply(session(file))
                exchange.requestURI.path.endsWith("/complete") -> { completes.incrementAndGet(); exchange.reply("{}") }
                else -> { started.complete(Unit); Thread.sleep(10_000); exchange.reply("{\"ok\":true}") }
            }
        }.use { primary ->
            val job = async { ThemeStoreResumableUploader(activeClient, primary.url + "/", "account").upload(file) { _, _ -> } }
            withTimeout(5000) { started.await() }
            withTimeout(2000) { job.cancelAndJoin() }
            withTimeout(3000) { while (activeClient.dispatcher.runningCallsCount() > 0) delay(20) }
            assertEquals(0, completes.get())
        }
    }

    @Test fun edgeRedirectDoesNotForwardTicket() = runBlocking {
        val file = file(chunk + 7)
        val redirected = AtomicInteger()
        Server { redirected.incrementAndGet(); it.reply("{}") }.use { capture ->
            Server { exchange ->
                exchange.requestBody.readBytes(); exchange.responseHeaders.set("Location", capture.url + "/leak")
                exchange.reply("{}", 307)
            }.use { edge ->
                Server { exchange ->
                    when {
                        exchange.requestURI.path.endsWith("/init") -> exchange.reply(session(file, edge.url))
                        exchange.requestURI.path.endsWith("/complete") -> exchange.reply("{\"ok\":true,\"complete\":true}")
                        else -> { exchange.requestBody.readBytes(); exchange.reply("{\"ok\":true}") }
                    }
                }.use { primary -> ThemeStoreResumableUploader(OkHttpClient(), primary.url + "/", "account").upload(file) { _, _ -> } }
            }
            assertEquals(0, redirected.get())
        }
    }

    @Test fun smallAttachmentsReuseMeasuredRoutesInsteadOfAlwaysUsingPrimary() = runBlocking {
        val files = listOf(file(37), file(41, "preview.png"), file(43, "avatar.webp"))
        val remote = AtomicInteger()
        Server { exchange ->
            val bytes = exchange.requestBody.readBytes()
            remote.incrementAndGet(); exchange.reply(ack(bytes, 0))
        }.use { edge ->
            Server { exchange ->
                when {
                    exchange.requestURI.path.endsWith("/init") -> {
                        val request = exchange.requestBody.readBytes().decodeToString()
                        exchange.reply(session(files.first { request.contains(it.name) }, edge.url))
                    }
                    exchange.requestURI.path.endsWith("/complete") -> exchange.reply("{\"ok\":true,\"complete\":true}")
                    else -> { exchange.requestBody.readBytes(); exchange.reply("{\"ok\":true}") }
                }
            }.use { primary ->
                val uploader = ThemeStoreResumableUploader(OkHttpClient(), primary.url + "/", "account")
                files.forEach { uploader.upload(it) { _, _ -> } }
                assertTrue("small files must also try an available edge", remote.get() > 0)
            }
        }
    }

    @Test fun slowRouteIsCancelledAndRetriedThroughTheWorkingIngress() = runBlocking {
        val file = file(chunk * 4 + 7)
        val repaired = ConcurrentHashMap.newKeySet<Int>()
        Server { exchange ->
            val bytes = exchange.requestBody.readBytes()
            val index = exchange.requestURI.path.substringAfterLast('/').toInt()
            Thread.sleep(50); repaired.add(index); exchange.reply(ack(bytes, index))
        }.use { edge ->
            Server { exchange ->
                when {
                    exchange.requestURI.path.endsWith("/init") -> exchange.reply(session(file, edge.url))
                    exchange.requestURI.path.endsWith("/complete") -> exchange.reply("{\"ok\":true,\"complete\":true}")
                    else -> { exchange.requestBody.readBytes(); Thread.sleep(35_000); exchange.reply("{\"ok\":true}") }
                }
            }.use { primary ->
                withTimeout(25_000) {
                    // Longer than the watchdog, so this exercises adaptive route
                    // cancellation rather than OkHttp's default 10-second timeout.
                    val client = OkHttpClient.Builder().readTimeout(60, TimeUnit.SECONDS).build()
                    ThemeStoreResumableUploader(client, primary.url + "/", "account").upload(file) { _, _ -> }
                }
                assertEquals(setOf(0, 1, 2, 3, 4), repaired)
            }
        }
    }

    @Test fun incompleteMergeAfterRepairFailsWithoutReturningAnUploadReference() = runBlocking {
        val file = file(37)
        val completes = AtomicInteger()
        val chunks = AtomicInteger()
        Server { exchange ->
            when {
                exchange.requestURI.path.endsWith("/init") -> exchange.reply(session(file, received = listOf(0)))
                exchange.requestURI.path.endsWith("/complete") -> {
                    completes.incrementAndGet()
                    exchange.reply("{\"ok\":true,\"complete\":false,\"missing\":[0]}")
                }
                else -> { exchange.requestBody.readBytes(); chunks.incrementAndGet(); exchange.reply("{\"ok\":true}") }
            }
        }.use { primary ->
            try {
                ThemeStoreResumableUploader(OkHttpClient(), primary.url + "/", "account").upload(file) { _, _ -> }
                fail("An incomplete merge must not return a file reference")
            } catch (_: IOException) { }
            assertEquals(2, completes.get()); assertEquals(1, chunks.get())
        }
    }

    @Test fun rejectsInvalidSessionOrMergeIndicesWithoutPublishing() = runBlocking {
        val file = file(37)
        for (invalid in listOf("size", "chunkSize", "received", "missing")) {
            val chunks = AtomicInteger()
            Server { exchange ->
                when {
                    exchange.requestURI.path.endsWith("/init") -> exchange.reply(
                        if (invalid == "missing") session(file, received = listOf(0)) else {
                            val value = json.parseToJsonElement(session(file)).toString()
                            when (invalid) {
                                "size" -> value.replace("\"size\":37", "\"size\":38")
                                "chunkSize" -> value.replace("\"chunkSize\":1048576", "\"chunkSize\":0")
                                else -> value.replace("\"received\":[]", "\"received\":[999]")
                            }
                        })
                    exchange.requestURI.path.endsWith("/complete") -> exchange.reply("{\"ok\":true,\"complete\":false,\"missing\":[999]}")
                    else -> { chunks.incrementAndGet(); exchange.reply("{\"ok\":true}") }
                }
            }.use { primary ->
                try {
                    ThemeStoreResumableUploader(OkHttpClient(), primary.url + "/", "account").upload(file) { _, _ -> }
                    fail("invalid $invalid must be rejected")
                } catch (_: IOException) { }
                assertEquals(0, chunks.get())
            }
        }
    }
}
