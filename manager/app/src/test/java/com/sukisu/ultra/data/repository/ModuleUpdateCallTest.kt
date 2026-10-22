package com.sukisu.ultra.data.repository

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okio.Buffer
import okio.BufferedSource
import okio.Source
import okio.Timeout
import okio.buffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.reflect.KClass

class ModuleUpdateCallTest {
    private class FakeCall : Call {
        private val request = Request.Builder().url("https://example.com/update.json").build()
        lateinit var callback: Callback
        var cancelled = false
        var onCancel: () -> Unit = {}
        override fun request() = request
        override fun execute(): Response = error("Must enqueue, not execute")
        override fun enqueue(responseCallback: Callback) { callback = responseCallback }
        override fun cancel() { cancelled = true; onCancel() }
        override fun isExecuted() = ::callback.isInitialized
        override fun isCanceled() = cancelled
        override fun timeout() = Timeout.NONE
        override fun <T : Any> tag(type: KClass<T>): T? = null
        override fun <T> tag(type: Class<out T>): T? = null
        override fun <T : Any> tag(type: KClass<T>, computeIfAbsent: () -> T): T = computeIfAbsent()
        override fun <T : Any> tag(type: Class<T>, computeIfAbsent: () -> T): T = computeIfAbsent()
        override fun clone(): Call = FakeCall()
        fun respond(body: ResponseBody, code: Int = 200) {
            callback.onResponse(this, Response.Builder().request(request).protocol(Protocol.HTTP_1_1)
                .code(code).message("test").body(body).build())
        }
    }

    private class TrackingBody(private val readBytes: (Buffer, Long) -> Long) : ResponseBody() {
        var closed = false
        private val source = object : Source {
            override fun read(sink: Buffer, byteCount: Long) = readBytes(sink, byteCount)
            override fun close() { closed = true }
            override fun timeout() = Timeout.NONE
        }.buffer()
        override fun contentType(): MediaType? = null
        override fun contentLength() = -1L
        override fun source(): BufferedSource = source
    }

    @Test
    fun shouldCloseBody_whenSuccessfulOrHttpError() = runBlocking {
        for (code in listOf(200, 404, 503)) {
            val call = FakeCall()
            val data = Buffer().writeUtf8("payload")
            val body = TrackingBody { sink, count -> data.read(sink, count) }
            val result = async(start = CoroutineStart.UNDISPATCHED) { call.awaitModuleUpdateBody() }
            call.respond(body, code)
            assertEquals(if (code == 200) "payload" else "", result.await())
            assertTrue(body.closed)
        }
    }

    @Test
    fun shouldCloseBody_whenReadingFails() = runBlocking {
        val call = FakeCall()
        val failure = IOException("body read failed")
        val body = TrackingBody { _, _ -> throw failure }
        val result = async(start = CoroutineStart.UNDISPATCHED) { runCatching { call.awaitModuleUpdateBody() } }
        call.respond(body)
        assertEquals(failure, result.await().exceptionOrNull())
        assertTrue(body.closed)
    }

    @Test
    fun shouldCancelCallAndCloseLateResponse_whenCancelledBeforeHeaders() = runBlocking {
        val call = FakeCall()
        var returned = false
        val job = launch(start = CoroutineStart.UNDISPATCHED) { call.awaitModuleUpdateBody(); returned = true }
        job.cancelAndJoin()
        assertTrue(call.cancelled)
        val body = TrackingBody { _, _ -> error("Cancelled responses must not be read") }
        call.respond(body)
        assertTrue(body.closed)
        assertFalse(returned)
    }

    @Test
    fun shouldCancelCallDuringBodyRead_withoutReturningEmpty() = runBlocking {
        val call = FakeCall()
        val reading = CompletableDeferred<Unit>()
        val cancelled = CountDownLatch(1)
        call.onCancel = { cancelled.countDown() }
        val body = TrackingBody { _, _ ->
            reading.complete(Unit)
            check(cancelled.await(2, TimeUnit.SECONDS))
            throw IOException("cancelled")
        }
        var returned = false
        val job = launch(start = CoroutineStart.UNDISPATCHED) { call.awaitModuleUpdateBody(); returned = true }
        val callbackJob = launch(Dispatchers.Default) { call.respond(body) }
        try {
            withTimeout(2_000) { reading.await() }
            job.cancelAndJoin()
            callbackJob.join()
            assertTrue(call.cancelled)
            assertTrue(body.closed)
            assertFalse(returned)
        } finally {
            job.cancelAndJoin()
            cancelled.countDown()
            callbackJob.join()
        }
    }

    @Test
    fun shouldPropagateNetworkFailure() = runBlocking {
        val call = FakeCall()
        val failure = IOException("offline")
        val result = async(start = CoroutineStart.UNDISPATCHED) { runCatching { call.awaitModuleUpdateBody() } }
        call.callback.onFailure(call, failure)
        assertEquals(failure, result.await().exceptionOrNull())
    }
}
