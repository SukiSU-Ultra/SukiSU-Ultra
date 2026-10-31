package com.sukisu.ultra.ui.screen.ai

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AiConfigTest {

    @Test
    fun autoDetectsOpenAiCompatiblePort() {
        val config = AiConfig(endpoint = "http://192.168.1.20:1234", model = "local-model")
        assertEquals(AiProviderFormat.OPENAI, config.effectiveFormat())
        assertEquals("http://192.168.1.20:1234/v1/chat/completions", config.resolvedEndpoint())
    }

    @Test
    fun autoDetectsOllamaPort() {
        val config = AiConfig(endpoint = "192.168.1.20:11434", model = "llama3.2")
        assertEquals(AiProviderFormat.OLLAMA, config.effectiveFormat())
        assertEquals("http://192.168.1.20:11434/api/chat", config.resolvedEndpoint())
    }

    @Test
    fun ollamaOpenAiEndpointStaysOpenAi() {
        val config = AiConfig(endpoint = "http://192.168.1.20:11434/v1", model = "llama3.2")
        assertEquals(AiProviderFormat.OPENAI, config.effectiveFormat())
        assertEquals("http://192.168.1.20:11434/v1/chat/completions", config.resolvedEndpoint())
    }

    @Test
    fun anthropicBaseGetsMessagesPath() {
        val config = AiConfig(endpoint = "https://api.anthropic.com", model = "claude")
        assertEquals(AiProviderFormat.ANTHROPIC, config.effectiveFormat())
        assertEquals("https://api.anthropic.com/v1/messages", config.resolvedEndpoint())
    }

    @Test
    fun completeEndpointsAreNotRewritten() {
        assertEquals(
            "http://host:8080/v1/chat/completions",
            AiConfig(endpoint = "http://host:8080/v1/chat/completions", model = "m").resolvedEndpoint(),
        )
        assertEquals(
            "http://host:11434/api/chat",
            AiConfig(endpoint = "http://host:11434/api/chat", model = "m").resolvedEndpoint(),
        )
        assertEquals(
            "https://api.anthropic.com/v1/messages",
            AiConfig(endpoint = "https://api.anthropic.com/v1/messages", model = "m").resolvedEndpoint(),
        )
    }

    @Test
    fun customGatewayPathKeepsItsPrefix() {
        val config = AiConfig(endpoint = "http://host:8080/llm", model = "m")
        assertEquals("http://host:8080/llm/v1/chat/completions", config.resolvedEndpoint())
    }

    @Test
    fun derivesImageEndpointsFromChatEndpoint() {
        val config = AiConfig(
            endpoint = "http://host:1234",
            model = "chat-model",
            imageModel = "image-model",
        )
        assertTrue(config.isImageConfigured)
        assertEquals("http://host:1234/v1/images/generations", config.resolvedImageEndpoint())
        assertEquals("http://host:1234/v1/images/edits", config.resolvedImageEditEndpoint())
    }

    @Test
    fun blankImageModelDisablesImages() {
        val config = AiConfig(endpoint = "http://host:1234", model = "chat-model")
        assertFalse(config.isImageConfigured)
    }

    @Test
    fun explicitFormatWinsOverDetection() {
        val config = AiConfig(
            endpoint = "http://host:9999",
            model = "m",
            format = AiProviderFormat.OLLAMA,
        )
        assertEquals("http://host:9999/api/chat", config.resolvedEndpoint())
    }
}
