package com.sukisu.ultra.ai

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/**
 * Expert-only API request options. They are stored as JSON so new provider
 * knobs can be added without another settings screen, and they are only applied
 * while [AiConfig.advancedMode] is enabled.
 */
@Serializable
data class AiAdvancedOptions(
    /** Upper bound for one completion; providers may clamp it further. */
    val maxOutputTokens: Int = 4096,
    /** Sampling temperature; 0-2. */
    val temperature: Float = 0.7f,
    /** OpenAI/Anthropic top_p; Ollama options.top_p. */
    val topP: Float = 1.0f,
    val frequencyPenalty: Float = 0.0f,
    val presencePenalty: Float = 0.0f,
    /** -1 leaves the provider default. */
    val seed: Int = -1,
    val stop: List<String> = emptyList(),
    /** Chat loop safety limits. */
    val maxToolRounds: Int = 24,
    val maxHistoryTurns: Int = 40,
    val maxHistoryChars: Int = 24_000,
    /** OkHttp timeouts. 0 means no timeout for read/call. */
    val connectTimeoutSeconds: Int = 20,
    val readTimeoutSeconds: Int = 0,
    val writeTimeoutSeconds: Int = 60,
    val callTimeoutSeconds: Int = 0,
    /** Retries only for connection failures and retryable HTTP statuses. */
    val retryCount: Int = 0,
    val parallelToolCalls: Boolean = true,
    /** Extra HTTP headers. Header names and values are validated. */
    val headers: Map<String, String> = emptyMap(),
    /** Merged into the provider request body; advanced keys win. */
    val extraBody: Map<String, JsonElement> = emptyMap(),
) {
    fun normalized(): AiAdvancedOptions = copy(
        maxOutputTokens = maxOutputTokens.coerceIn(64, 131_072),
        temperature = temperature.coerceIn(0f, 2f),
        topP = topP.coerceIn(0f, 1f),
        frequencyPenalty = frequencyPenalty.coerceIn(-2f, 2f),
        presencePenalty = presencePenalty.coerceIn(-2f, 2f),
        seed = if (seed < 0) -1 else seed,
        stop = stop.asSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && it.length <= 256 }
            .distinct()
            .take(8)
            .toList(),
        maxToolRounds = maxToolRounds.coerceIn(1, 64),
        maxHistoryTurns = maxHistoryTurns.coerceIn(0, 200),
        maxHistoryChars = maxHistoryChars.coerceIn(1_000, 200_000),
        connectTimeoutSeconds = connectTimeoutSeconds.coerceIn(1, 300),
        readTimeoutSeconds = readTimeoutSeconds.coerceIn(0, 3_600),
        writeTimeoutSeconds = writeTimeoutSeconds.coerceIn(1, 300),
        callTimeoutSeconds = callTimeoutSeconds.coerceIn(0, 7_200),
        retryCount = retryCount.coerceIn(0, 5),
        headers = headers.entries.asSequence()
            .filter { (name, value) -> isValidHeader(name, value) }
            .take(32)
            .associate { it.key to it.value },
        extraBody = extraBody.entries.asSequence()
            .filter { (name, _) -> name.isNotBlank() && name.length <= 128 }
            .take(64)
            .associate { it.key to it.value },
    )

    fun extraBodyJson(): JsonObject = JsonObject(extraBody)

    companion object {
        val DEFAULT = AiAdvancedOptions()

        private val json = Json {
            // Unknown keys usually mean a typo in an expert option; surface it.
            ignoreUnknownKeys = false
            isLenient = false
            prettyPrint = true
            encodeDefaults = true
        }

        fun parse(raw: String): Result<AiAdvancedOptions> = runCatching {
            if (raw.isBlank()) return@runCatching DEFAULT
            json.decodeFromString<AiAdvancedOptions>(raw).normalized()
        }

        fun exampleJson(): String = json.encodeToString(serializer(), DEFAULT)

        private fun isValidHeader(name: String, value: String): Boolean {
            if (name.isEmpty() || name.length > 64) return false
            if (value.length > 4_096 || '\r' in value || '\n' in value) return false
            return name.all { char ->
                char.isLetterOrDigit() || char in "!#$%&'*+-.^_`|~"
            }
        }
    }
}
