package com.sukisu.ultra.ui.webui

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.Closeable
import java.util.ArrayDeque
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.CoroutineContext

class WebUIExecutionTest {
    private class ManualDispatcher : CoroutineDispatcher() {
        private val tasks = ArrayDeque<Runnable>()
        override fun dispatch(context: CoroutineContext, block: Runnable) {
            tasks.add(block)
        }

        fun drain() {
            while (tasks.isNotEmpty()) {
                tasks.removeFirst().run()
            }
        }
    }

    @Test(timeout = 5_000)
    fun shouldOrderExecFifoAndKeepSpawnIndependent_whenTasksFailOrDispose() = runBlocking {
        val dispatcher = ManualDispatcher()
        val failures = mutableListOf<Exception>()
        val execution = WebUIExecution(dispatcher, failures::add)
        val gate = CompletableDeferred<Unit>()
        val order = mutableListOf<String>()

        execution.exec { order.add("first-start"); gate.await(); order.add("first-end") }
        execution.exec { order.add("second"); error("expected") }
        execution.exec { order.add("third") }
        execution.launch { order.add("spawn") }

        assertTrue(order.isEmpty())
        dispatcher.drain()
        assertEquals(listOf("first-start", "spawn"), order)

        gate.complete(Unit)
        dispatcher.drain()
        assertEquals(listOf("first-start", "spawn", "first-end", "second", "third"), order)
        assertEquals("expected", failures.single().message)

        execution.dispose()
        execution.exec { error("disposed exec ran") }
        execution.launch { error("disposed spawn ran") }
        dispatcher.drain()
        assertEquals(1, failures.size)
    }

    @Test(timeout = 5_000)
    fun shouldCancelActiveAndQueuedCallbacks_whenExecutionIsDisposed() = runBlocking {
        val dispatcher = ManualDispatcher()
        val execution = WebUIExecution(dispatcher) { throw it }
        val pendingGate = CompletableDeferred<Unit>()
        var callbacks = 0

        execution.exec { pendingGate.await(); callbacks++ }
        execution.exec { callbacks++ }
        dispatcher.drain()

        execution.dispose()
        pendingGate.complete(Unit)
        dispatcher.drain()
        assertEquals(0, callbacks)
    }

    @Test(timeout = 5_000)
    fun shouldCloseBlockingResourceOnce_whenCancelledDuringExecutionOrCreation() = runBlocking {
        val closed = AtomicInteger()
        val entered = CompletableDeferred<Unit>()
        val released = CountDownLatch(1)
        val worker = launch {
            withWebUIResource(create = { Closeable { closed.incrementAndGet(); released.countDown() } }) {
                entered.complete(Unit)
                check(released.await(5, TimeUnit.SECONDS)) { "blocking resource was not closed" }
            }
        }
        withTimeout(2_000) { entered.await() }
        worker.cancelAndJoin()
        assertEquals(1, closed.get())

        val creating = CompletableDeferred<Unit>()
        val finishCreation = CountDownLatch(1)
        val createdCloses = AtomicInteger()
        var ranBlock = false
        val creation = launch {
            withWebUIResource(create = {
                creating.complete(Unit)
                check(finishCreation.await(5, TimeUnit.SECONDS))
                Closeable { createdCloses.incrementAndGet() }
            }) { ranBlock = true }
        }
        withTimeout(2_000) { creating.await() }
        creation.cancel()
        finishCreation.countDown()
        creation.join()
        assertEquals(1, createdCloses.get())
        assertFalse(ranBlock)

        val exceptionCloses = AtomicInteger()
        val result = runCatching {
            withWebUIResource(create = { Closeable { exceptionCloses.incrementAndGet() } }) { error("job failure") }
        }
        assertEquals("job failure", result.exceptionOrNull()?.message)
        assertEquals(1, exceptionCloses.get())
    }

    @Test(timeout = 5_000)
    fun shouldBatchLinesWithBackpressureAndPreservePerStreamOrder() = runBlocking {
        val batches = WebUIOutput(capacity = 16, maxBatchLines = 3, maxBatchChars = 6)
        val expected = listOf(
            WebUIOutputLine("stdout", ""),
            WebUIOutputLine("stderr", "abc"),
            WebUIOutputLine("stdout", "de"),
            WebUIOutputLine("stderr", "fgh"),
            WebUIOutputLine("stdout", "01234567890123456789"),
            WebUIOutputLine("stderr", "\"\\\n\u2028\u2029"),
            WebUIOutputLine("stdout", "z"),
        )
        expected.forEach { batches.add(it.stream, it.data) }
        batches.finish()
        val received = mutableListOf<WebUIOutputLine>()
        var batchCount = 0
        batches.drain { batch ->
            assertTrue(batch.size <= 3)
            assertTrue(batch.size == 1 || batch.sumOf { it.data.length } <= 6)
            batchCount++
            received.addAll(batch)
        }
        assertEquals(expected, received)
        assertTrue(batchCount < expected.size)

        val bounded = WebUIOutput(capacity = 1, maxBatchLines = 1)
        bounded.add("stdout", "first")
        val producing = CompletableDeferred<Unit>()
        val producer = async(Dispatchers.IO) {
            producing.complete(Unit)
            bounded.add("stderr", "second")
        }
        withTimeout(2_000) { producing.await() }
        assertFalse(producer.isCompleted)
        val firstDelivery = CompletableDeferred<Unit>()
        val allowDelivery = CompletableDeferred<Unit>()
        val seen = mutableListOf<String>()
        val drainer = launch(start = CoroutineStart.UNDISPATCHED) {
            bounded.drain { batch ->
                seen.add(batch.single().data)
                if (seen.size == 1) {
                    firstDelivery.complete(Unit)
                    allowDelivery.await()
                }
            }
            seen.add("exit")
        }
        withTimeout(2_000) { firstDelivery.await() }
        producer.await()
        bounded.finish()
        assertEquals(listOf("first"), seen)
        assertFalse(drainer.isCompleted)
        allowDelivery.complete(Unit)
        drainer.join()
        assertEquals(listOf("first", "second", "exit"), seen)
    }

    @Test(timeout = 5_000)
    fun shouldReleaseBlockedProducer_whenOutputIsCancelled() = runBlocking {
        val cancelOutput = WebUIOutput(capacity = 1)
        cancelOutput.add("stdout", "first")
        val trying = CompletableDeferred<Unit>()
        val blocked = async(Dispatchers.IO) {
            trying.complete(Unit)
            cancelOutput.add("stderr", "second")
        }
        withTimeout(2_000) { trying.await() }
        assertFalse(blocked.isCompleted)
        cancelOutput.cancel()
        blocked.await()
        cancelOutput.drain { error("cancelled output delivered") }
    }
}
