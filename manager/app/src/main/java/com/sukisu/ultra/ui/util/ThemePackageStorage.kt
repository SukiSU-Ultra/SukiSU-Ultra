package com.sukisu.ultra.ui.util

import android.content.Context
import android.graphics.BitmapFactory
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

/**
 * Serializable part of a theme package. Fields are nullable so that packages written by newer
 * builds can still be applied by older ones as long as the known fields are valid.
 */
@Serializable
data class ThemePackageData(
    val version: Int = ThemePackageStorage.CURRENT_VERSION,
    val themeMode: Int? = null,
    val miuixMonet: Boolean? = null,
    val showHomeStatusIcon: Boolean? = null,
    val keyColor: Int? = null,
    val colorStyle: String? = null,
    val colorSpec: String? = null,
    val cardBackgroundAlphaPercent: Int? = null,
    val customBackgroundBlurPercent: Int? = null,
    val customBackgroundScrimPercent: Int? = null,
    val hasBackground: Boolean? = null,
    val hasCardBackground: Boolean? = null,
    val uiMode: String? = null,
    val appIconId: String? = null,
    val enableFloatingBottomBar: Boolean? = null,
    val enableFloatingBottomBarBlur: Boolean? = null,
    val enableNavigationBadge: Boolean? = null,
    val enablePredictiveBack: Boolean? = null,
    val enableSwipeDismiss: Boolean? = null,
    val moduleSortEnabledFirst: Boolean? = null,
    val moduleSortActionFirst: Boolean? = null,
    val moduleSortWebUiFirst: Boolean? = null,
    val moduleSortZygiskFirst: Boolean? = null,
    val moduleSortMetamoduleFirst: Boolean? = null,
    val moduleSortNameOrder: String? = null,
    val moduleSortManual: Boolean? = null,
    val customHomeTitle: String? = null,
    val customTexts: Map<String, String>? = null,
)

/**
 * Parsed theme package plus paths to extracted temporary image files.
 * Callers are responsible for deleting or promoting these temporary files.
 */
data class ImportedTheme(
    val data: ThemePackageData,
    val backgroundPath: String? = null,
    val cardBackgroundPath: String? = null,
)

object ThemePackageStorage {
    const val CURRENT_VERSION = 1

    private const val THEME_ENTRY = "theme.json"
    private const val BACKGROUND_ENTRY = "background"
    private const val CARD_BACKGROUND_ENTRY = "card_background"
    private const val MAX_JSON_BYTES = 64L * 1024
    private const val MAX_BACKGROUND_BYTES = 64L * 1024 * 1024

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    fun packageFileName(): String {
        val stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmm"))
        return "SukiSU-theme-$stamp.sukisu"
    }

    suspend fun export(
        context: Context,
        uri: Uri,
        data: ThemePackageData,
        backgroundFile: File?,
        cardBackgroundFile: File? = null,
    ): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val zipBytes = ByteArrayOutputStream().use { byteOut ->
                ZipOutputStream(byteOut).use { zip ->
                    zip.putNextEntry(ZipEntry(THEME_ENTRY))
                    zip.write(json.encodeToString(ThemePackageData.serializer(), data).toByteArray())
                    zip.closeEntry()
                    if (data.hasBackground == true && backgroundFile != null && backgroundFile.isFile) {
                        zip.putNextEntry(ZipEntry(BACKGROUND_ENTRY))
                        backgroundFile.inputStream().use { it.copyTo(zip) }
                        zip.closeEntry()
                    }
                    if (data.hasCardBackground == true && cardBackgroundFile != null && cardBackgroundFile.isFile) {
                        zip.putNextEntry(ZipEntry(CARD_BACKGROUND_ENTRY))
                        cardBackgroundFile.inputStream().use { it.copyTo(zip) }
                        zip.closeEntry()
                    }
                }
                byteOut.toByteArray()
            }
            val encryptedBytes = ThemePackageCrypto.encrypt(zipBytes)
            val output = context.contentResolver.openOutputStream(uri)
                ?: error("Cannot open the destination file")
            BufferedOutputStream(output).use { it.write(encryptedBytes) }
        }
    }

    suspend fun import(context: Context, uri: Uri): Result<ImportedTheme> = withContext(Dispatchers.IO) {
        runCatching {
            val rawBytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: error("Cannot open the theme package")
            val zipBytes = runCatching { ThemePackageCrypto.decrypt(rawBytes) }.getOrElse {
                error("Theme package verification or decryption failed")
            }
            var tempBackground: File? = null
            var tempCardBackground: File? = null
            try {
                var themeText: String? = null
                var backgroundExtracted = false
                var cardBackgroundExtracted = false
                ByteArrayInputStream(zipBytes).use { byteIn ->
                    ZipInputStream(byteIn).use { zip ->
                        var entry: ZipEntry? = zip.nextEntry
                        while (entry != null) {
                            when (entry.name) {
                                THEME_ENTRY -> themeText = readLimited(zip, MAX_JSON_BYTES).toString(Charsets.UTF_8)
                                BACKGROUND_ENTRY -> {
                                    val bg = File.createTempFile("theme_import_bg_", ".tmp", context.cacheDir)
                                    tempBackground = bg
                                    bg.outputStream().use { copyLimited(zip, it, MAX_BACKGROUND_BYTES) }
                                    backgroundExtracted = true
                                }
                                CARD_BACKGROUND_ENTRY -> {
                                    val cardBg = File.createTempFile("theme_import_card_", ".tmp", context.cacheDir)
                                    tempCardBackground = cardBg
                                    cardBg.outputStream().use { copyLimited(zip, it, MAX_BACKGROUND_BYTES) }
                                    cardBackgroundExtracted = true
                                }
                            }
                            zip.closeEntry()
                            entry = zip.nextEntry
                        }
                    }
                }

                val text = themeText ?: error("theme.json is missing")
                val data = json.decodeFromString(ThemePackageData.serializer(), text)
                if (data.version > CURRENT_VERSION) error("Unsupported theme package version")

                val hasBackground = data.hasBackground ?: backgroundExtracted
                if (hasBackground && !backgroundExtracted) error("Background image is missing")
                if (hasBackground && tempBackground != null) {
                    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                    BitmapFactory.decodeFile(tempBackground.absolutePath, bounds)
                    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) {
                        error("Background image is invalid")
                    }
                }

                val hasCardBackground = data.hasCardBackground ?: cardBackgroundExtracted
                if (hasCardBackground && tempCardBackground != null) {
                    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                    BitmapFactory.decodeFile(tempCardBackground.absolutePath, bounds)
                    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) {
                        error("Card background image is invalid")
                    }
                }

                ImportedTheme(
                    data = data,
                    backgroundPath = tempBackground?.takeIf { hasBackground }?.absolutePath,
                    cardBackgroundPath = tempCardBackground?.takeIf { hasCardBackground }?.absolutePath,
                )
            } catch (e: Exception) {
                tempBackground?.delete()
                tempCardBackground?.delete()
                throw e
            }
        }
    }

    private fun readLimited(input: InputStream, maxBytes: Long): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8 * 1024)
        var total = 0L
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            total += read
            if (total > maxBytes) error("Theme package entry is too large")
            output.write(buffer, 0, read)
        }
        return output.toByteArray()
    }

    private fun copyLimited(input: InputStream, output: OutputStream, maxBytes: Long) {
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            total += read
            if (total > maxBytes) error("Theme package entry is too large")
            output.write(buffer, 0, read)
        }
    }
}
