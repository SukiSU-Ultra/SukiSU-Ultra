package com.sukisu.ultra.ui.screen.ai

import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.util.concurrent.TimeUnit

@kotlinx.serialization.Serializable
data class AiToolCall(
    val id: String = "",
    val name: String = "",
    /** JSON object encoded as a string, provider-neutral. */
    val arguments: String = "{}",
)

/** Provider-neutral chat message used while building a request. */
data class AiApiMessage(
    val role: String,
    val content: String = "",
    val toolCalls: List<AiToolCall> = emptyList(),
    val toolCallId: String? = null,
    val toolName: String? = null,
)

data class AiToolSpec(
    val name: String,
    val description: String,
    val parameters: JsonObject,
)

data class AiCompletion(
    val text: String,
    val toolCalls: List<AiToolCall> = emptyList(),
    val finishReason: String? = null,
)

class AiApiException(message: String, val statusCode: Int? = null) : Exception(message)

/**
 * One client for the three wire formats local models commonly expose. Requests
 * are built provider-neutral and serialized into:
 *
 * - OpenAI chat completions (`/v1/chat/completions`)
 * - Ollama chat (`/api/chat`)
 * - Anthropic messages (`/v1/messages`)
 *
 * A full endpoint may be entered instead of a base address; see
 * [AiConfig.resolvedEndpoint].
 */
object AiApiClient {

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }
    private val mediaType = "application/json; charset=utf-8".toMediaType()

    private val defaultClient = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        // Local models can think for a long time before the first token. Do not
        // abort a valid generation on an arbitrary read timeout; Stop still
        // cancels the underlying OkHttp call.
        .readTimeout(0, TimeUnit.MILLISECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
        .callTimeout(0, TimeUnit.MILLISECONDS)
        .build()

    /** Expert mode timeouts produce one client per distinct combination. */
    private val clientCache = ConcurrentHashMap<String, OkHttpClient>()

    suspend fun complete(
        config: AiConfig,
        messages: List<AiApiMessage>,
        tools: List<AiToolSpec> = emptyList(),
        useTools: Boolean = tools.isNotEmpty(),
        maxTokens: Int = 4096,
        onDelta: (String) -> Unit = {},
    ): AiCompletion {
        require(config.endpoint.isNotBlank()) { "API address is empty" }
        require(config.model.isNotBlank()) { "Model name is empty" }
        val url = config.resolvedEndpoint()
        require(url.isNotBlank()) { "API address is invalid" }
        val options = config.advancedOptions()
        return when (config.effectiveFormat()) {
            AiProviderFormat.OLLAMA ->
                ollama(config, options, url, messages, tools, useTools, maxTokens, onDelta)
            AiProviderFormat.ANTHROPIC ->
                anthropic(config, options, url, messages, tools, useTools, maxTokens, onDelta)
            AiProviderFormat.OPENAI, AiProviderFormat.AUTO ->
                openAi(config, options, url, messages, tools, useTools, maxTokens, onDelta)
        }
    }

    /** Sends a tiny request so the user can validate the address/key/model. */
    suspend fun test(config: AiConfig): String {
        val probe = config.copy(
            streaming = false,
            toolCalling = false,
            thinkingMode = AiThinkingMode.AUTO,
        )
        val completion = complete(
            config = probe,
            messages = listOf(AiApiMessage("user", "Reply with the single word OK.")),
            tools = emptyList(),
            useTools = false,
            maxTokens = 64,
        )
        return completion.text.trim().take(160).ifBlank { "OK" }
    }

    /**
     * Fetches model ids from the configured endpoint. Supports OpenAI-compatible
     * `/models`, Ollama `/api/tags`, and Anthropic `/v1/models`.
     */
    suspend fun fetchModels(config: AiConfig): List<String> {
        require(config.endpoint.isNotBlank()) { "API address is empty" }
        val format = config.effectiveFormat()
        val url = when (format) {
            AiProviderFormat.OPENAI, AiProviderFormat.AUTO ->
                config.resolvedEndpoint().removeSuffix("/chat/completions") + "/models"
            AiProviderFormat.OLLAMA ->
                config.resolvedEndpoint().removeSuffix("/api/chat") + "/api/tags"
            AiProviderFormat.ANTHROPIC ->
                config.resolvedEndpoint().removeSuffix("/messages") + "/models"
        }
        val builder = Request.Builder().url(url).get()
        val key = config.apiKey.trim()
        if (key.isNotEmpty()) {
            when (format) {
                AiProviderFormat.ANTHROPIC -> builder.header("x-api-key", key)
                AiProviderFormat.OPENAI, AiProviderFormat.AUTO ->
                    if (url.contains("openai.azure.com", true)) {
                        builder.header("api-key", key)
                    } else {
                        builder.header("Authorization", "Bearer $key")
                    }
                AiProviderFormat.OLLAMA -> builder.header("Authorization", "Bearer $key")
            }
        }
        if (format == AiProviderFormat.ANTHROPIC) {
            builder.header("anthropic-version", "2023-06-01")
        }
        applyCustomHeaders(builder, config)
        return withCall(builder.build(), config) { response ->
            val root = runCatching {
                json.parseToJsonElement(response.body.string()) as? JsonObject
            }.getOrNull() ?: throw AiApiException("Unexpected model list response")
            root["error"]?.let { throw AiApiException(it.errorText()) }
            val array = when (format) {
                AiProviderFormat.OLLAMA -> root.arr("models")
                else -> root.arr("data")
            } ?: throw AiApiException("Model list has no data")
            array.mapNotNull { element ->
                val item = element as? JsonObject ?: return@mapNotNull null
                item.str("id") ?: item.str("name") ?: item.str("model")
            }.filter { it.isNotBlank() }.distinct().sorted()
        }
    }

    // ------------------------------------------------------------------ OpenAI

    private suspend fun openAi(
        config: AiConfig,
        options: AiAdvancedOptions,
        url: String,
        messages: List<AiApiMessage>,
        tools: List<AiToolSpec>,
        useTools: Boolean,
        maxTokens: Int,
        onDelta: (String) -> Unit,
    ): AiCompletion {
        val payload = buildJsonObject {
            put("model", config.model)
            put("messages", openAiMessages(messages))
            put("stream", config.streaming)
            put("temperature", if (config.advancedMode) options.temperature else config.temperature)
            put("max_tokens", maxTokens)
            when (config.thinkingMode) {
                AiThinkingMode.OFF -> put("reasoning_effort", "none")
                AiThinkingMode.LOW -> put("reasoning_effort", "low")
                AiThinkingMode.MEDIUM -> put("reasoning_effort", "medium")
                AiThinkingMode.HIGH -> put("reasoning_effort", "high")
                AiThinkingMode.AUTO -> Unit
            }
            if (config.advancedMode) {
                put("top_p", options.topP)
                put("frequency_penalty", options.frequencyPenalty)
                put("presence_penalty", options.presencePenalty)
                if (options.seed >= 0) put("seed", options.seed)
                if (options.stop.isNotEmpty()) {
                    putJsonArray("stop") { options.stop.forEach { add(it) } }
                }
            }
            if (useTools) {
                putJsonArray("tools") { tools.forEach { add(it.toOpenAiJson()) } }
                put("tool_choice", "auto")
                if (config.advancedMode) put("parallel_tool_calls", options.parallelToolCalls)
            }
        }.mergeExtraBody(config, options)
        val request = request(url, config, payload.toString())
        return withCall(request, config) { response ->
            val contentType = response.header("Content-Type").orEmpty()
            val readLine = response.readLineSupplier()
            if (config.streaming && contentType.contains("event-stream", ignoreCase = true)) {
                parseOpenAiStream(readLine, onDelta)
            } else if (config.streaming && contentType.contains("ndjson", ignoreCase = true)) {
                // Some gateways stream plain JSON objects one per line.
                parseOpenAiNdjson(readLine, onDelta)
            } else {
                val body = response.body.string()
                if (config.streaming && body.trimStart().startsWith("data:")) {
                    // Some proxies omit or mislabel the SSE content type.
                    parseOpenAiStream(body.lineSupplier(), onDelta)
                } else {
                    parseOpenAiBody(body, onDelta)
                }
            }
        }
    }

    private fun parseOpenAiStream(
        readLine: () -> String?,
        onDelta: (String) -> Unit,
    ): AiCompletion {
        val text = StringBuilder()
        val calls = sortedMapOf<Int, MutableToolCall>()
        var finishReason: String? = null
        var line = readLine()
        while (line != null) {
            val trimmed = line.trim()
            if (trimmed.startsWith("data:")) {
                val data = trimmed.removePrefix("data:").trim()
                if (data.isNotEmpty() && data != "[DONE]") {
                    parseOpenAiChunk(data, text, calls, onDelta)?.let { finishReason = it }
                }
            }
            line = readLine()
        }
        return AiCompletion(
            text = text.toString(),
            toolCalls = calls.values.map { it.toToolCall() },
            finishReason = finishReason,
        )
    }

    private fun parseOpenAiNdjson(
        readLine: () -> String?,
        onDelta: (String) -> Unit,
    ): AiCompletion {
        val text = StringBuilder()
        val calls = sortedMapOf<Int, MutableToolCall>()
        var finishReason: String? = null
        var line = readLine()
        while (line != null) {
            if (line.isNotBlank()) {
                parseOpenAiChunk(line.trim(), text, calls, onDelta)?.let { finishReason = it }
            }
            line = readLine()
        }
        return AiCompletion(
            text = text.toString(),
            toolCalls = calls.values.map { it.toToolCall() },
            finishReason = finishReason,
        )
    }

    private fun parseOpenAiChunk(
        raw: String,
        text: StringBuilder,
        calls: MutableMap<Int, MutableToolCall>,
        onDelta: (String) -> Unit,
    ): String? {
        val root = runCatching { json.parseToJsonElement(raw) as? JsonObject }.getOrNull() ?: return null
        root["error"]?.let { throw AiApiException(it.errorText()) }
        val choice = root.arr("choices")?.firstOrNull() as? JsonObject ?: return null
        val delta = (choice["delta"] as? JsonObject) ?: (choice["message"] as? JsonObject)
        if (delta != null) {
            val content = delta["content"]
            if (content != null && content !is JsonNull) {
                val chunk = content.textContent()
                if (chunk.isNotEmpty()) {
                    text.append(chunk)
                    onDelta(chunk)
                }
            }
            delta.arr("tool_calls")?.forEach { element ->
                val call = element as? JsonObject ?: return@forEach
                val index = call.int("index") ?: 0
                val acc = calls.getOrPut(index) { MutableToolCall() }
                call.str("id")?.takeIf { it.isNotBlank() }?.let { acc.id = it }
                (call["function"] as? JsonObject)?.let { fn ->
                    fn.str("name")?.takeIf { it.isNotBlank() }?.let { name ->
                        if (acc.name.isBlank()) acc.name = name
                    }
                    val argsChunk = when (val args = fn["arguments"]) {
                        null, is JsonNull -> ""
                        is JsonPrimitive -> args.contentOrNull.orEmpty()
                        else -> args.toString()
                    }
                    if (argsChunk.isNotEmpty()) acc.arguments.append(argsChunk)
                }
            }
            // Legacy single function_call shape.
            (delta["function_call"] as? JsonObject)?.let { fn ->
                val acc = calls.getOrPut(0) { MutableToolCall() }
                fn.str("name")?.takeIf { it.isNotBlank() }?.let { if (acc.name.isBlank()) acc.name = it }
                val argsChunk = when (val args = fn["arguments"]) {
                    null, is JsonNull -> ""
                    is JsonPrimitive -> args.contentOrNull.orEmpty()
                    else -> args.toString()
                }
                if (argsChunk.isNotEmpty()) acc.arguments.append(argsChunk)
            }
        }
        return choice.str("finish_reason")
    }

    private fun parseOpenAiBody(
        body: String,
        onDelta: (String) -> Unit,
    ): AiCompletion {
        if (body.isBlank()) return AiCompletion("")
        val root = runCatching { json.parseToJsonElement(body) as? JsonObject }.getOrNull()
            ?: throw AiApiException("Unexpected response: ${body.take(300)}")
        root["error"]?.let { throw AiApiException(it.errorText()) }
        val choice = root.arr("choices")?.firstOrNull() as? JsonObject
            ?: throw AiApiException("No choices in response: ${body.take(300)}")
        val message = choice["message"] as? JsonObject
        val text = message?.get("content")?.textContent().orEmpty()
        if (text.isNotEmpty()) onDelta(text)
        val calls = mutableListOf<AiToolCall>()
        message?.arr("tool_calls")?.forEachIndexed { index, element ->
            val call = element as? JsonObject ?: return@forEachIndexed
            val fn = call["function"] as? JsonObject
            calls += AiToolCall(
                id = call.str("id")?.takeIf { it.isNotBlank() } ?: "call_$index",
                name = fn?.str("name").orEmpty(),
                arguments = fn?.argumentsString() ?: "{}",
            )
        }
        message?.obj("function_call")?.let { fn ->
            calls += AiToolCall(
                id = "call_0",
                name = fn.str("name").orEmpty(),
                arguments = fn.argumentsString(),
            )
        }
        return AiCompletion(
            text = text,
            toolCalls = calls.filter { it.name.isNotBlank() },
            finishReason = choice.str("finish_reason"),
        )
    }

    private fun openAiMessages(messages: List<AiApiMessage>): JsonArray = buildJsonArray {
        messages.forEach { message ->
            addJsonObject {
                put("role", message.role)
                when {
                    message.role == "tool" -> {
                        put("tool_call_id", message.toolCallId.orEmpty())
                        put("content", message.content)
                    }

                    message.toolCalls.isNotEmpty() -> {
                        if (message.content.isBlank()) put("content", JsonNull) else put("content", message.content)
                        putJsonArray("tool_calls") {
                            message.toolCalls.forEach { call ->
                                addJsonObject {
                                    put("id", call.id)
                                    put("type", "function")
                                    putJsonObject("function") {
                                        put("name", call.name)
                                        put("arguments", call.arguments)
                                    }
                                }
                            }
                        }
                    }

                    else -> put("content", message.content)
                }
            }
        }
    }

    // ------------------------------------------------------------------ Ollama

    private suspend fun ollama(
        config: AiConfig,
        options: AiAdvancedOptions,
        url: String,
        messages: List<AiApiMessage>,
        tools: List<AiToolSpec>,
        useTools: Boolean,
        maxTokens: Int,
        onDelta: (String) -> Unit,
    ): AiCompletion {
        val payload = buildJsonObject {
            put("model", config.model)
            put("messages", buildJsonArray {
                messages.forEach { message ->
                    addJsonObject {
                        put("role", message.role)
                        put("content", message.content)
                        if (!message.toolName.isNullOrBlank()) put("tool_name", message.toolName)
                        if (message.toolCalls.isNotEmpty()) {
                            putJsonArray("tool_calls") {
                                message.toolCalls.forEach { call ->
                                    addJsonObject {
                                        putJsonObject("function") {
                                            put("name", call.name)
                                            put("arguments", parseArguments(call.arguments))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            })
            put("stream", config.streaming)
            putJsonObject("options") {
                put("temperature", if (config.advancedMode) options.temperature else config.temperature)
                put("num_predict", maxTokens)
                if (config.advancedMode) {
                    put("top_p", options.topP)
                    put("frequency_penalty", options.frequencyPenalty)
                    put("presence_penalty", options.presencePenalty)
                    if (options.seed >= 0) put("seed", options.seed)
                    if (options.stop.isNotEmpty()) {
                        putJsonArray("stop") { options.stop.forEach { add(it) } }
                    }
                }
            }
            when (config.thinkingMode) {
                AiThinkingMode.OFF -> put("think", false)
                AiThinkingMode.LOW -> put("think", "low")
                AiThinkingMode.MEDIUM -> put("think", "medium")
                AiThinkingMode.HIGH -> put("think", "high")
                AiThinkingMode.AUTO -> Unit
            }
            if (useTools) {
                putJsonArray("tools") { tools.forEach { add(it.toOllamaJson()) } }
            }
        }.mergeExtraBody(config, options)
        val request = request(url, config, payload.toString())
        return withCall(request, config) { response ->
            val readLine = response.readLineSupplier()
            if (config.streaming) {
                parseOllamaStream(readLine, onDelta)
            } else {
                parseOllamaBody(response.body.string(), onDelta)
            }
        }
    }

    private fun parseOllamaStream(
        readLine: () -> String?,
        onDelta: (String) -> Unit,
    ): AiCompletion {
        val text = StringBuilder()
        val calls = mutableListOf<AiToolCall>()
        var line = readLine()
        while (line != null) {
            if (line.isNotBlank()) {
                val root = runCatching { json.parseToJsonElement(line) as? JsonObject }.getOrNull()
                if (root != null) {
                    root["error"]?.let { throw AiApiException(it.errorText()) }
                    val message = root["message"] as? JsonObject
                    val chunk = message?.str("content").orEmpty()
                    if (chunk.isNotEmpty()) {
                        text.append(chunk)
                        onDelta(chunk)
                    }
                    message?.arr("tool_calls")?.forEach { element ->
                        val call = element as? JsonObject ?: return@forEach
                        val fn = call.obj("function") ?: return@forEach
                        val name = fn.str("name").orEmpty()
                        if (name.isNotBlank()) {
                            calls += AiToolCall(
                                id = call.str("id")?.takeIf { it.isNotBlank() }
                                    ?: "tool_${calls.size}",
                                name = name,
                                arguments = fn["arguments"]?.toString() ?: "{}",
                            )
                        }
                    }
                    if (root.bool("done") == true) break
                }
            }
            line = readLine()
        }
        return AiCompletion(
            text = text.toString(),
            toolCalls = calls.distinctBy { it.name to it.arguments },
        )
    }

    private fun parseOllamaBody(
        body: String,
        onDelta: (String) -> Unit,
    ): AiCompletion {
        val root = runCatching { json.parseToJsonElement(body) as? JsonObject }.getOrNull()
            ?: throw AiApiException("Unexpected response: ${body.take(300)}")
        root["error"]?.let { throw AiApiException(it.errorText()) }
        val message = root["message"] as? JsonObject
            ?: throw AiApiException("No message in response: ${body.take(300)}")
        val text = message.str("content").orEmpty()
        if (text.isNotEmpty()) onDelta(text)
        val calls = mutableListOf<AiToolCall>()
        message.arr("tool_calls")?.forEachIndexed { index, element ->
            val call = element as? JsonObject ?: return@forEachIndexed
            val fn = call.obj("function") ?: return@forEachIndexed
            val name = fn.str("name").orEmpty()
            if (name.isNotBlank()) {
                calls += AiToolCall(
                    id = call.str("id")?.takeIf { it.isNotBlank() } ?: "tool_$index",
                    name = name,
                    arguments = fn["arguments"]?.toString() ?: "{}",
                )
            }
        }
        return AiCompletion(text = text, toolCalls = calls)
    }

    // --------------------------------------------------------------- Anthropic

    private suspend fun anthropic(
        config: AiConfig,
        options: AiAdvancedOptions,
        url: String,
        messages: List<AiApiMessage>,
        tools: List<AiToolSpec>,
        useTools: Boolean,
        maxTokens: Int,
        onDelta: (String) -> Unit,
    ): AiCompletion {
        val system = messages.filter { it.role == "system" }
            .joinToString("\n\n") { it.content }
            .ifBlank { null }
        val payload = buildJsonObject {
            put("model", config.model)
            put("max_tokens", maxTokens)
            put("temperature", if (config.advancedMode) options.temperature else config.temperature)
            if (system != null) put("system", system)
            put("messages", anthropicMessages(messages))
            when (config.thinkingMode) {
                AiThinkingMode.LOW -> putJsonObject("thinking") {
                    put("type", "enabled")
                    put("budget_tokens", 1024)
                }

                AiThinkingMode.MEDIUM -> putJsonObject("thinking") {
                    put("type", "enabled")
                    put("budget_tokens", 2048)
                }

                AiThinkingMode.HIGH -> putJsonObject("thinking") {
                    put("type", "enabled")
                    put("budget_tokens", 3072)
                }

                else -> Unit
            }
            if (config.streaming) put("stream", true)
            if (config.advancedMode) {
                put("top_p", options.topP)
                if (options.stop.isNotEmpty()) {
                    putJsonArray("stop_sequences") { options.stop.forEach { add(it) } }
                }
            }
            if (useTools) {
                putJsonArray("tools") { tools.forEach { add(it.toAnthropicJson()) } }
            }
        }.mergeExtraBody(config, options)
        val request = request(url, config, payload.toString()).newBuilder()
            .header("anthropic-version", "2023-06-01")
            .build()
        return withCall(request, config) { response ->
            val contentType = response.header("Content-Type").orEmpty()
            if (config.streaming && contentType.contains("event-stream", ignoreCase = true)) {
                parseAnthropicStream(response.readLineSupplier(), onDelta)
            } else {
                val body = response.body.string()
                if (config.streaming && (
                        body.trimStart().startsWith("event:") ||
                            body.trimStart().startsWith("data:")
                        )
                ) {
                    parseAnthropicStream(body.lineSupplier(), onDelta)
                } else {
                    parseAnthropicBody(body, onDelta)
                }
            }
        }
    }

    private fun anthropicMessages(messages: List<AiApiMessage>): JsonArray {
        val grouped = mutableListOf<Pair<String, MutableList<JsonObject>>>()
        fun append(role: String, block: JsonObject) {
            val last = grouped.lastOrNull()
            if (last != null && last.first == role) last.second.add(block)
            else grouped.add(role to mutableListOf(block))
        }
        messages.forEach { message ->
            when (message.role) {
                "system" -> Unit
                "tool" -> append(
                    "user",
                    buildJsonObject {
                        put("type", "tool_result")
                        put("tool_use_id", message.toolCallId.orEmpty())
                        if (message.content.isNotBlank()) put("content", message.content)
                        else put("content", "(no output)")
                    },
                )

                "assistant" -> {
                    if (message.content.isNotBlank()) append("assistant", textBlock(message.content))
                    message.toolCalls.forEach { call ->
                        append(
                            "assistant",
                            buildJsonObject {
                                put("type", "tool_use")
                                put("id", call.id)
                                put("name", call.name)
                                put("input", parseArguments(call.arguments))
                            },
                        )
                    }
                }

                else -> append("user", textBlock(message.content))
            }
        }
        return buildJsonArray {
            grouped.forEach { (role, blocks) ->
                addJsonObject {
                    put("role", role)
                    put("content", buildJsonArray { blocks.forEach { add(it) } })
                }
            }
        }
    }

    private fun textBlock(text: String): JsonObject = buildJsonObject {
        put("type", "text")
        put("text", text)
    }

    private fun parseAnthropicStream(
        readLine: () -> String?,
        onDelta: (String) -> Unit,
    ): AiCompletion {
        val text = StringBuilder()
        val toolBlocks = mutableMapOf<Int, MutableToolCall>()
        var stopReason: String? = null
        var line = readLine()
        loop@ while (line != null) {
            val trimmed = line.trim()
            if (trimmed.startsWith("data:")) {
                val data = trimmed.removePrefix("data:").trim()
                if (data.isNotEmpty()) {
                    val root = runCatching { json.parseToJsonElement(data) as? JsonObject }.getOrNull()
                    if (root != null) {
                        when (root.str("type")) {
                            "error" -> throw AiApiException(root["error"].errorText())
                            "content_block_start" -> {
                                val index = root.int("index") ?: 0
                                val block = root["content_block"] as? JsonObject
                                if (block?.str("type") == "tool_use") {
                                    toolBlocks[index] = MutableToolCall(
                                        id = block.str("id").orEmpty(),
                                        name = block.str("name").orEmpty(),
                                        initialInput = block["input"]?.takeUnless { it is JsonNull }?.toString(),
                                    )
                                }
                            }

                            "content_block_delta" -> {
                                val index = root.int("index") ?: 0
                                val delta = root["delta"] as? JsonObject
                                when (delta?.str("type")) {
                                    "text_delta" -> {
                                        val chunk = delta.str("text").orEmpty()
                                        if (chunk.isNotEmpty()) {
                                            text.append(chunk)
                                            onDelta(chunk)
                                        }
                                    }

                                    "input_json_delta" -> {
                                        toolBlocks.getOrPut(index) { MutableToolCall() }.arguments
                                            .append(delta.str("partial_json").orEmpty())
                                    }
                                }
                            }

                            "message_delta" -> {
                                stopReason = (root["delta"] as? JsonObject)?.str("stop_reason") ?: stopReason
                            }

                            "message_stop" -> break@loop
                        }
                    }
                }
            }
            line = readLine()
        }
        return AiCompletion(
            text = text.toString(),
            toolCalls = toolBlocks.entries.sortedBy { it.key }.map { (_, block) -> block.toToolCall() },
            finishReason = stopReason,
        )
    }

    private fun parseAnthropicBody(
        body: String,
        onDelta: (String) -> Unit,
    ): AiCompletion {
        val root = runCatching { json.parseToJsonElement(body) as? JsonObject }.getOrNull()
            ?: throw AiApiException("Unexpected response: ${body.take(300)}")
        root["error"]?.let { throw AiApiException(it.errorText()) }
        val text = StringBuilder()
        val calls = mutableListOf<AiToolCall>()
        root.arr("content")?.forEachIndexed { index, element ->
            val block = element as? JsonObject ?: return@forEachIndexed
            when (block.str("type")) {
                "text" -> text.append(block.str("text").orEmpty())
                "tool_use" -> calls += AiToolCall(
                    id = block.str("id")?.takeIf { it.isNotBlank() } ?: "tool_$index",
                    name = block.str("name").orEmpty(),
                    arguments = block["input"]?.toString() ?: "{}",
                )
            }
        }
        val result = text.toString()
        if (result.isNotEmpty()) onDelta(result)
        return AiCompletion(result, calls.filter { it.name.isNotBlank() }, root.str("stop_reason"))
    }

    // ----------------------------------------------------------------- helpers

    private fun Response.readLineSupplier(): () -> String? {
        val source = body.source()
        return { source.readUtf8Line() }
    }

    private fun String.lineSupplier(): () -> String? {
        val lines = lineSequence().iterator()
        return { if (lines.hasNext()) lines.next() else null }
    }

    private fun request(url: String, config: AiConfig, body: String): Request {
        val builder = Request.Builder().url(url).post(body.toRequestBody(mediaType))
        val key = config.apiKey.trim()
        if (key.isNotEmpty()) {
            if (config.effectiveFormat() == AiProviderFormat.ANTHROPIC) {
                builder.header("x-api-key", key)
            } else if (url.contains("openai.azure.com", ignoreCase = true)) {
                builder.header("api-key", key)
            } else {
                builder.header("Authorization", "Bearer $key")
            }
        }
        applyCustomHeaders(builder, config)
        return builder.build()
    }

    private suspend fun <T> withCall(
        request: Request,
        config: AiConfig,
        block: (Response) -> T,
    ): T = withContext(Dispatchers.IO) {
        val options = config.advancedOptions()
        val retries = if (config.advancedMode) options.retryCount else 0
        val job = currentCoroutineContext()[Job]
        var attempt = 0
        var response: Response
        var handle: kotlinx.coroutines.DisposableHandle? = null
        while (true) {
            val call = clientFor(config).newCall(request)
            handle?.dispose()
            handle = job?.invokeOnCompletion { cause ->
                if (cause is kotlinx.coroutines.CancellationException) call.cancel()
            }
            try {
                val candidate = call.execute()
                if (!candidate.isSuccessful && candidate.code in RETRYABLE_STATUS && attempt < retries) {
                    candidate.close()
                    handle?.dispose()
                    handle = null
                    attempt++
                    delay(400L * attempt)
                    continue
                }
                response = candidate
                break
            } catch (error: IOException) {
                handle?.dispose()
                handle = null
                if (attempt < retries) {
                    attempt++
                    delay(400L * attempt)
                    continue
                }
                throw error
            }
        }
        try {
            response.use { result ->
                if (!result.isSuccessful) {
                    throw AiApiException(result.readError(), result.code)
                }
                block(result)
            }
        } finally {
            handle?.dispose()
        }
    }

    private fun clientFor(config: AiConfig): OkHttpClient {
        if (!config.advancedMode) return defaultClient
        val options = config.advancedOptions()
        val key = listOf(
            options.connectTimeoutSeconds,
            options.readTimeoutSeconds,
            options.writeTimeoutSeconds,
            options.callTimeoutSeconds,
        ).joinToString(":")
        return clientCache.getOrPut(key) {
            defaultClient.newBuilder()
                .connectTimeout(options.connectTimeoutSeconds.toLong(), TimeUnit.SECONDS)
                .readTimeout(options.readTimeoutSeconds.toLong(), TimeUnit.SECONDS)
                .writeTimeout(options.writeTimeoutSeconds.toLong(), TimeUnit.SECONDS)
                .callTimeout(options.callTimeoutSeconds.toLong(), TimeUnit.SECONDS)
                .build()
        }
    }

    private fun applyCustomHeaders(builder: Request.Builder, config: AiConfig) {
        if (!config.advancedMode) return
        config.advancedOptions().headers.forEach { (name, value) ->
            if (name.isNotBlank()) builder.header(name, value)
        }
    }

    private fun JsonObject.mergeExtraBody(
        config: AiConfig,
        options: AiAdvancedOptions,
    ): JsonObject {
        if (!config.advancedMode || options.extraBody.isEmpty()) return this
        val merged = toMutableMap()
        merged.putAll(options.extraBody)
        return JsonObject(merged)
    }

    private fun Response.readError(): String {
        val raw = runCatching { body.string() }.getOrDefault("")
        val parsed = runCatching { json.parseToJsonElement(raw) as? JsonObject }.getOrNull()
        val errorMessage = parsed?.get("error")?.errorText()
            ?: parsed?.str("message")
            ?: raw.take(500)
        return "HTTP $code ${errorMessage.ifBlank { message }}".trim()
    }

    private val RETRYABLE_STATUS = setOf(408, 425, 429, 500, 502, 503, 504)

    private fun JsonElement?.errorText(): String = when (this) {
        null, is JsonNull -> ""
        is JsonObject -> str("message") ?: str("error") ?: toString()
        is JsonArray -> toString()
        is JsonPrimitive -> contentOrNull ?: toString()
    }

    private fun JsonObject.str(key: String): String? =
        (this[key] as? JsonPrimitive)?.contentOrNull

    private fun JsonObject.int(key: String): Int? =
        (this[key] as? JsonPrimitive)?.intOrNull

    private fun JsonObject.bool(key: String): Boolean? =
        (this[key] as? JsonPrimitive)?.booleanOrNull

    private fun JsonObject.arr(key: String): JsonArray? = this[key] as? JsonArray

    private fun JsonObject.obj(key: String): JsonObject? = this[key] as? JsonObject

    private fun JsonObject.argumentsString(): String = when (val value = this["arguments"]) {
        null, is JsonNull -> "{}"
        is JsonPrimitive -> value.contentOrNull ?: value.toString()
        else -> value.toString()
    }

    private fun JsonElement.textContent(): String = when (this) {
        is JsonPrimitive -> contentOrNull.orEmpty()
        is JsonArray -> joinToString("") { element ->
            val block = element as? JsonObject
            if (block?.str("type") == "text") block.str("text").orEmpty() else ""
        }

        else -> ""
    }

    private fun parseArguments(raw: String): JsonObject =
        runCatching { json.parseToJsonElement(raw.ifBlank { "{}" }) as? JsonObject }.getOrNull()
            ?: buildJsonObject { }

    private fun AiToolSpec.toOpenAiJson(): JsonObject = buildJsonObject {
        put("type", "function")
        putJsonObject("function") {
            put("name", name)
            put("description", description)
            put("parameters", parameters)
        }
    }

    private fun AiToolSpec.toOllamaJson(): JsonObject = buildJsonObject {
        put("type", "function")
        putJsonObject("function") {
            put("name", name)
            put("description", description)
            put("parameters", parameters)
        }
    }

    private fun AiToolSpec.toAnthropicJson(): JsonObject = buildJsonObject {
        put("name", name)
        put("description", description)
        put("input_schema", parameters)
    }

    private class MutableToolCall(
        var id: String = "",
        var name: String = "",
        val arguments: StringBuilder = StringBuilder(),
        var initialInput: String? = null,
    ) {
        fun toToolCall(): AiToolCall {
            val args = arguments.toString().ifBlank { initialInput ?: "{}" }
            return AiToolCall(
                id = id.ifBlank {
                    // Anthropic ids are assigned by the server; synthesize only when absent.
                    "tool_${name.ifBlank { "call" }}_${args.hashCode()}"
                },
                name = name,
                arguments = args,
            )
        }
    }
}
