package com.sukisu.ultra.ui.screen.ai

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AiApiClientTest {

    private var server: HttpServer? = null

    @After
    fun tearDown() {
        server?.stop(0)
        server = null
    }

    private fun startServer(contentType: String, body: String): Int {
        val http = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        http.createContext("/") { exchange ->
            val bytes = body.toByteArray(Charsets.UTF_8)
            exchange.responseHeaders.add("Content-Type", contentType)
            exchange.sendResponseHeaders(200, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        http.start()
        server = http
        return http.address.port
    }

    private fun config(port: Int, format: AiProviderFormat) = AiConfig(
        endpoint = "http://127.0.0.1:$port",
        model = "test-model",
        format = format,
        streaming = true,
    )

    @Test
    fun openAiNonStreamingParsesTextAndToolCalls() = runBlocking {
        val port = startServer(
            "application/json",
            """
            {"choices":[{"message":{"content":"hello","tool_calls":[{"id":"call_1",
            "function":{"name":"get_environment","arguments":"{\"a\":1}"}}]},"finish_reason":"tool_calls"}]}
            """.trimIndent(),
        )
        val delta = StringBuilder()
        val result = AiApiClient.complete(
            config = config(port, AiProviderFormat.OPENAI).copy(streaming = false),
            messages = listOf(AiApiMessage("user", "hi")),
            onDelta = { delta.append(it) },
        )
        assertEquals("hello", result.text)
        assertEquals("hello", delta.toString())
        assertEquals(1, result.toolCalls.size)
        assertEquals("get_environment", result.toolCalls.first().name)
        assertEquals("call_1", result.toolCalls.first().id)
    }

    @Test
    fun openAiStreamingParsesSseDeltas() = runBlocking {
        val port = startServer(
            "text/event-stream",
            """
            data: {"choices":[{"delta":{"content":"Hel"}}]}

            data: {"choices":[{"delta":{"content":"lo"}}]}

            data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"get_environment","arguments":"{\"x\""}}]}}]}

            data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":":1}"}}]},"finish_reason":"tool_calls"}]}

            data: [DONE]

            """.trimIndent(),
        )
        val delta = StringBuilder()
        val result = AiApiClient.complete(
            config = config(port, AiProviderFormat.OPENAI),
            messages = listOf(AiApiMessage("user", "hi")),
            onDelta = { delta.append(it) },
        )
        assertEquals("Hello", result.text)
        assertEquals("Hello", delta.toString())
        assertEquals(1, result.toolCalls.size)
        assertEquals("get_environment", result.toolCalls.first().name)
        assertEquals("{\"x\":1}", result.toolCalls.first().arguments)
    }

    @Test
    fun ollamaNdjsonParsesTextAndToolCalls() = runBlocking {
        val port = startServer(
            "application/x-ndjson",
            """
            {"message":{"content":"Hi "},"done":false}
            {"message":{"content":"there","tool_calls":[{"function":{"name":"get_environment","arguments":{"a":1}}}]},"done":false}
            {"done":true}
            """.trimIndent(),
        )
        val result = AiApiClient.complete(
            config = config(port, AiProviderFormat.OLLAMA),
            messages = listOf(AiApiMessage("user", "hi")),
        )
        assertEquals("Hi there", result.text)
        assertEquals(1, result.toolCalls.size)
        assertEquals("get_environment", result.toolCalls.first().name)
        assertTrue(result.toolCalls.first().arguments.contains("\"a\""))
    }

    @Test
    fun anthropicBodyParsesTextAndToolUse() = runBlocking {
        val port = startServer(
            "application/json",
            """
            {"content":[{"type":"text","text":"Hi"},{"type":"tool_use","id":"toolu_1",
            "name":"get_environment","input":{"a":1}}],"stop_reason":"tool_use"}
            """.trimIndent(),
        )
        val result = AiApiClient.complete(
            config = config(port, AiProviderFormat.ANTHROPIC).copy(streaming = false),
            messages = listOf(AiApiMessage("user", "hi")),
        )
        assertEquals("Hi", result.text)
        assertEquals(1, result.toolCalls.size)
        assertEquals("toolu_1", result.toolCalls.first().id)
        assertEquals("get_environment", result.toolCalls.first().name)
        assertTrue(result.toolCalls.first().arguments.contains("\"a\""))
    }

    @Test
    fun anthropicStreamingParsesTextAndPartialToolInput() = runBlocking {
        val port = startServer(
            "text/event-stream",
            """
            event: content_block_start
            data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

            event: content_block_delta
            data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}

            event: content_block_start
            data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"get_environment","input":{}}}

            event: content_block_delta
            data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"a\":"}}

            event: content_block_delta
            data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"1}"}}

            event: message_stop
            data: {"type":"message_stop"}

            """.trimIndent(),
        )
        val result = AiApiClient.complete(
            config = config(port, AiProviderFormat.ANTHROPIC),
            messages = listOf(AiApiMessage("user", "hi")),
        )
        assertEquals("Hi", result.text)
        assertEquals(1, result.toolCalls.size)
        assertEquals("get_environment", result.toolCalls.first().name)
        assertEquals("{\"a\":1}", result.toolCalls.first().arguments)
    }
}
