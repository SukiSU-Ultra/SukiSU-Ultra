package com.sukisu.ultra.ui.screen.ai

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AiLocalNetworkTest {

    private fun isLan(endpoint: String): Boolean =
        AiLocalNetwork.isLanEndpoint(AiConfig(endpoint = endpoint, model = "test"))

    @Test
    fun detectsPrivateIpv4Ranges() {
        assertTrue(isLan("http://192.168.11.2:31001"))
        assertTrue(isLan("192.168.1.20:1234"))
        assertTrue(isLan("http://10.0.2.2:11434"))
        assertTrue(isLan("http://172.20.0.5:8080"))
        assertTrue(isLan("http://169.254.1.1"))
        assertTrue(isLan("http://100.64.0.1"))
    }

    @Test
    fun detectsLanHostnames() {
        assertTrue(isLan("http://my-nas:8080"))
        assertTrue(isLan("http://router.local:8080"))
        assertTrue(isLan("http://host.docker.internal:1234"))
    }

    @Test
    fun doesNotTreatLoopbackAsLan() {
        assertFalse(isLan("http://localhost:11434"))
        assertFalse(isLan("http://127.0.0.1:8080"))
        assertFalse(isLan("http://[::1]:8080"))
    }

    @Test
    fun doesNotTreatPublicEndpointsAsLan() {
        assertFalse(isLan("https://api.openai.com"))
        assertFalse(isLan("http://8.8.8.8:8080"))
        assertFalse(isLan("http://[2001:db8::1]:8080"))
    }

    @Test
    fun detectsIpv6LinkLocalAndUniqueLocal() {
        assertTrue(isLan("http://[fe80::1]:8080"))
        assertTrue(isLan("http://[fd00::1]:8080"))
    }
}
