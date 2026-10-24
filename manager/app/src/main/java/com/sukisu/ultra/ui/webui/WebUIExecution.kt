package com.sukisu.ultra.ui.webui

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.trySendBlocking
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import java.io.Closeable
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

internal suspend fun <T : Closeable, R> withWebUIResource(
    create: () -> T,
    onCancel: () -> Unit = {},
    block: (T) -> R,
): R = coroutineScope {
    val resource = WebUIResource<T>()
    suspendCancellableCoroutine { continuation ->
        // Cancellation must close a blocking shell independently of its exec worker. Merely
        // cancelling that worker (or its Future) leaves libsu's process and readers alive.
        continuation.invokeOnCancellation {
            try {
                onCancel()
            } finally {
                resource.close()
            }
        }
        launch(Dispatchers.IO) {
            try {
                val value = create()
                if (resource.attach(value)) continuation.resume(block(value))
            } catch (error: Throwable) {
                continuation.resumeWithException(error)
            } finally {
                resource.close()
            }
        }
    }
}

/** Covers cancellation both during shell creation and while its blocking job is running. */
internal class WebUIResource<T : Closeable> : Closeable {
    private var closed = false
    private var resource: T? = null

    fun attach(value: T): Boolean {
        val accepted = synchronized(this) {
            if (closed) false else {
                resource = value
                true
            }
        }
        if (!accepted) runCatching { value.close() }
        return accepted
    }

    override fun close() {
        val value = synchronized(this) {
            closed = true
            resource.also { resource = null }
        }
        runCatching { value?.close() }
    }
}

/** Owns command tasks for one page; they run concurrently, as each used its own shell before. */
internal class WebUIExecution(
    dispatcher: CoroutineDispatcher = Dispatchers.Default,
    private val onFailure: (Exception) -> Unit,
) {
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)

    fun exec(block: suspend () -> Unit) {
        launch(block)
    }

    fun launch(block: suspend () -> Unit): Job = scope.launch {
        try {
            block()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            onFailure(error)
        }
    }

    fun dispose() {
        scope.cancel()
    }
}

internal data class WebUIOutputLine(val stream: String, val data: String)

/** Backpressure reaches libsu's reader threads rather than accumulating Main/renderer tasks. */
internal class WebUIOutput(
    capacity: Int = 128,
    private val maxBatchLines: Int = 64,
    private val maxBatchChars: Int = 32 * 1024,
) {
    private val lines = Channel<WebUIOutputLine>(capacity)

    init {
        require(capacity > 0)
        require(maxBatchLines > 0)
        require(maxBatchChars > 0)
    }

    // Called directly on libsu's stdout/stderr readers, never Main or the JS bridge thread.
    fun add(stream: String, data: String) {
        lines.trySendBlocking(WebUIOutputLine(stream, data))
    }

    suspend fun drain(deliver: suspend (List<WebUIOutputLine>) -> Unit) {
        var pending: WebUIOutputLine? = null
        while (true) {
            val first = pending ?: lines.receiveCatching().getOrNull() ?: break
            pending = null
            val batch = arrayListOf(first)
            var chars = first.data.length
            while (batch.size < maxBatchLines && chars < maxBatchChars) {
                val next = lines.tryReceive().getOrNull() ?: break
                if (next.data.length > maxBatchChars - chars) {
                    pending = next
                    break
                }
                batch.add(next)
                chars += next.data.length
            }
            // A single long line is indivisible: preserve it as one data event, without truncation.
            // Await JS execution before taking another batch, bounding the renderer backlog too.
            deliver(batch)
        }
    }

    fun finish() {
        lines.close()
    }

    fun cancel() {
        // Also releases reader threads blocked in trySendBlocking during teardown or delivery failure.
        lines.cancel()
    }
}
