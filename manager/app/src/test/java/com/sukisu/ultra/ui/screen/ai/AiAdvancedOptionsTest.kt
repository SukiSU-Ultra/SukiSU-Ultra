package com.sukisu.ultra.ui.screen.ai

import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AiAdvancedOptionsTest {

    @Test
    fun blankInputUsesSafeDefaults() {
        val options = AiAdvancedOptions.parse("").getOrThrow()
        assertEquals(AiAdvancedOptions.DEFAULT, options)
    }

    @Test
    fun invalidJsonFailsClosed() {
        assertTrue(AiAdvancedOptions.parse("""{"maxOutputTokens": }""").isFailure)
        assertTrue(AiAdvancedOptions.parse("not json").isFailure)
    }

    @Test
    fun valuesAreClampedToSafeRanges() {
        val options = AiAdvancedOptions.parse(
            """
            {
              "maxOutputTokens": 999999,
              "topP": 4.0,
              "frequencyPenalty": -9.0,
              "presencePenalty": 9.0,
              "maxToolRounds": 0,
              "maxHistoryTurns": -1,
              "maxHistoryChars": 1,
              "connectTimeoutSeconds": 0,
              "readTimeoutSeconds": 99999,
              "writeTimeoutSeconds": 0,
              "callTimeoutSeconds": 99999,
              "retryCount": 99,
              "stop": ["a", "a", "  ", "b"]
            }
            """.trimIndent()
        ).getOrThrow()
        assertEquals(131_072, options.maxOutputTokens)
        assertEquals(1f, options.topP)
        assertEquals(-2f, options.frequencyPenalty)
        assertEquals(2f, options.presencePenalty)
        assertEquals(1, options.maxToolRounds)
        assertEquals(0, options.maxHistoryTurns)
        assertEquals(1_000, options.maxHistoryChars)
        assertEquals(1, options.connectTimeoutSeconds)
        assertEquals(3_600, options.readTimeoutSeconds)
        assertEquals(1, options.writeTimeoutSeconds)
        assertEquals(7_200, options.callTimeoutSeconds)
        assertEquals(5, options.retryCount)
        assertEquals(listOf("a", "b"), options.stop)
    }

    @Test
    fun unsafeHeadersAreDropped() {
        val options = AiAdvancedOptions.parse(
            """
            {
              "headers": {
                "X-Good": "ok",
                "Bad Header": "value",
                "X-Injection": "a\r\nb"
              }
            }
            """.trimIndent()
        ).getOrThrow()
        assertEquals(mapOf("X-Good" to "ok"), options.headers)
    }

    @Test
    fun exampleJsonRoundTrips() {
        val parsed = AiAdvancedOptions.parse(AiAdvancedOptions.exampleJson()).getOrThrow()
        assertEquals(AiAdvancedOptions.DEFAULT, parsed)
    }

    @Test
    fun advancedOptionsAreIgnoredWhileModeIsOff() {
        val config = AiConfig(
            advancedMode = false,
            advancedOptionsJson = """{"maxOutputTokens":128,"retryCount":5}""",
        )
        assertEquals(AiAdvancedOptions.DEFAULT, config.advancedOptions())
    }

    @Test
    fun advancedOptionsApplyOnlyWhileModeIsOn() {
        val config = AiConfig(
            advancedMode = true,
            advancedOptionsJson = """{"maxOutputTokens":128,"retryCount":5}""",
        )
        assertEquals(128, config.advancedOptions().maxOutputTokens)
        assertEquals(5, config.advancedOptions().retryCount)
    }

    @Test
    fun extraBodyIsPreserved() {
        val options = AiAdvancedOptions.parse(
            """{"extraBody":{"custom_flag":true,"nested":{"value":1}}}"""
        ).getOrThrow()
        assertEquals(JsonPrimitive(true), options.extraBody["custom_flag"])
        assertEquals(2, options.extraBody.size)
    }
}
