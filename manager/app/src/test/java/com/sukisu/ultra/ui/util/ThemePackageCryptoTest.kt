package com.sukisu.ultra.ui.util

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
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

    @Test
    fun streamingDecryptHandlesIncrementalReads() {
        val payload = ByteArray(3 * 1024 * 1024) { (it * 31 % 251).toByte() }
        val output = ByteArrayOutputStream()
        ThemePackageCrypto.encryptingStream(output).use { it.write(payload) }

        val decrypted = ByteArray(payload.size)
        ThemePackageCrypto.decryptingStream(
            ByteArrayInputStream(output.toByteArray()),
        ).use { input ->
            var offset = 0
            val buffer = ByteArray(777)
            while (offset < decrypted.size) {
                val read = input.read(buffer, 0, minOf(buffer.size, decrypted.size - offset))
                assertTrue(read > 0)
                System.arraycopy(buffer, 0, decrypted, offset, read)
                offset += read
            }
            assertEquals(-1, input.read())
        }
        assertArrayEquals(payload, decrypted)
    }

    @Test
    fun streamingDecryptVerifiesTagWhenClosedEarly() {
        val payload = ByteArray(256 * 1024)
        val output = ByteArrayOutputStream()
        ThemePackageCrypto.encryptingStream(output).use { it.write(payload) }
        val encrypted = output.toByteArray()
        encrypted[encrypted.lastIndex] = (encrypted.last().toInt() xor 0x01).toByte()

        val result = runCatching {
            ThemePackageCrypto.decryptingStream(ByteArrayInputStream(encrypted)).use { input ->
                input.read(ByteArray(16))
            }
        }

        assertTrue(result.isFailure)
    }
}
