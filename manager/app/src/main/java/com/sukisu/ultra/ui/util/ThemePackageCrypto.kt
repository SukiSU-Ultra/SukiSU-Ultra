package com.sukisu.ultra.ui.util

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object ThemePackageCrypto {
    private val MAGIC = byteArrayOf('S'.code.toByte(), 'K'.code.toByte(), 'T'.code.toByte(), 'H'.code.toByte())
    private const val IV_SIZE = 12
    private const val TAG_BIT_LENGTH = 128

    // 48-byte precomputed hash of theme key
    private val HASH_BYTES = byteArrayOf(
        0x41.toByte(), 0xdc.toByte(), 0x17.toByte(), 0x4e.toByte(), 0x50.toByte(), 0x96.toByte(), 0xb4.toByte(), 0xee.toByte(),
        0x93.toByte(), 0x31.toByte(), 0x1c.toByte(), 0xc8.toByte(), 0x92.toByte(), 0xb1.toByte(), 0x32.toByte(), 0xe2.toByte(),
        0x19.toByte(), 0x61.toByte(), 0x01.toByte(), 0x2b.toByte(), 0x14.toByte(), 0xcf.toByte(), 0x21.toByte(), 0x79.toByte(),
        0x54.toByte(), 0x0f.toByte(), 0x20.toByte(), 0x3c.toByte(), 0xa7.toByte(), 0x2a.toByte(), 0xb9.toByte(), 0xc1.toByte(),
        0xd9.toByte(), 0xcd.toByte(), 0xa5.toByte(), 0x45.toByte(), 0x2e.toByte(), 0x58.toByte(), 0xe6.toByte(), 0xdf.toByte(),
        0x56.toByte(), 0x79.toByte(), 0xa1.toByte(), 0x46.toByte(), 0x4d.toByte(), 0x44.toByte(), 0x0a.toByte(), 0x0a.toByte()
    )

    private val secretKey = SecretKeySpec(HASH_BYTES.copyOfRange(0, 32), "AES")
    private val secureRandom = SecureRandom()

    fun encrypt(plainBytes: ByteArray): ByteArray {
        val iv = ByteArray(IV_SIZE)
        secureRandom.nextBytes(iv)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(TAG_BIT_LENGTH, iv))
        val cipherText = cipher.doFinal(plainBytes)

        val result = ByteArray(MAGIC.size + IV_SIZE + cipherText.size)
        System.arraycopy(MAGIC, 0, result, 0, MAGIC.size)
        System.arraycopy(iv, 0, result, MAGIC.size, IV_SIZE)
        System.arraycopy(cipherText, 0, result, MAGIC.size + IV_SIZE, cipherText.size)
        return result
    }

    fun decrypt(encryptedBytes: ByteArray): ByteArray {
        if (encryptedBytes.size < MAGIC.size + IV_SIZE) {
            error("Invalid theme package: payload too small")
        }
        for (i in MAGIC.indices) {
            if (encryptedBytes[i] != MAGIC[i]) {
                error("Invalid theme package: header mismatch")
            }
        }
        val iv = ByteArray(IV_SIZE)
        System.arraycopy(encryptedBytes, MAGIC.size, iv, 0, IV_SIZE)

        val cipherTextOffset = MAGIC.size + IV_SIZE
        val cipherTextLength = encryptedBytes.size - cipherTextOffset

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(TAG_BIT_LENGTH, iv))
        return cipher.doFinal(encryptedBytes, cipherTextOffset, cipherTextLength)
    }
}
