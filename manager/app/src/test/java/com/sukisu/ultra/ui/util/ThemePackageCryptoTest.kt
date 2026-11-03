package com.sukisu.ultra.ui.util

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class ThemePackageCryptoTest {
    @Test
    fun recognizesThemePackageHeader() {
        assertTrue(ThemePackageCrypto.hasValidHeader("SKTH".toByteArray()))
        assertTrue(ThemePackageCrypto.hasValidHeader("SKTH\u0000\u0000".toByteArray()))
    }

    @Test
    fun rejectsOtherOrShortHeaders() {
        assertFalse(ThemePackageCrypto.hasValidHeader(ByteArray(0)))
        assertFalse(ThemePackageCrypto.hasValidHeader("SKT".toByteArray()))
        assertFalse(ThemePackageCrypto.hasValidHeader("PK\u0003\u0004".toByteArray()))
    }

    @Test
    fun encryptDecryptRoundTrip() {
        val payload = "theme.json payload".toByteArray()
        val encrypted = ThemePackageCrypto.encrypt(payload)

        assertTrue(ThemePackageCrypto.hasValidHeader(encrypted))
        assertArrayEquals(payload, ThemePackageCrypto.decrypt(encrypted))
    }

    @Test
    fun streamingDecryptRoundTrip() {
        val payload = "streamed theme.json payload".toByteArray()
        val encrypted = ThemePackageCrypto.encrypt(payload)

        val decrypted = ThemePackageCrypto.decryptingStream(
            ByteArrayInputStream(encrypted),
        ).use { it.readBytes() }

        assertArrayEquals(payload, decrypted)
    }

    @Test
    fun streamingDecryptRejectsTamperedPayload() {
        val encrypted = ThemePackageCrypto.encrypt("theme.json payload".toByteArray())
        encrypted[encrypted.lastIndex] = (encrypted.last().toInt() xor 0x01).toByte()

        val result = runCatching {
            ThemePackageCrypto.decryptingStream(
                ByteArrayInputStream(encrypted),
            ).use { it.readBytes() }
        }

        assertTrue(result.isFailure)
    }

    @Test
    fun streamingEncryptDecryptRoundTrip() {
        val payload = "streamed export payload".toByteArray()
        val output = ByteArrayOutputStream()

        ThemePackageCrypto.encryptingStream(output).use { it.write(payload) }
        val encrypted = output.toByteArray()
        assertTrue(ThemePackageCrypto.hasValidHeader(encrypted))

        val decrypted = ThemePackageCrypto.decryptingStream(
            ByteArrayInputStream(encrypted),
        ).use { it.readBytes() }
        assertArrayEquals(payload, decrypted)
    }
}
