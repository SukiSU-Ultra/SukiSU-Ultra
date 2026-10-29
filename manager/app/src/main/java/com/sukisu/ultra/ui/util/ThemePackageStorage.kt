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
    val keyColor: Int? = null,
    val colorStyle: String? = null,
    val colorSpec: String? = null,
    val cardBackgroundAlphaPercent: Int? = null,
    val customBackgroundBlurPercent: Int? = null,
    val customBackgroundScrimPercent: Int? = null,
    val hasBackground: Boolean? = null,
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
)

/** Parsed theme package plus the background file path when the package contains an image. */
data class ImportedTheme(
    val data: ThemePackageData,
    val backgroundPath: String?,
)

object ThemePackageStorage {
    const val CURRENT_VERSION = 1

    private const val THEME_ENTRY = "theme.json"
    private const val BACKGROUND_ENTRY = "background"
    private const val MAX_JSON_BYTES = 64L * 1024
    private const val MAX_BACKGROUND_BYTES = 64L * 1024 * 1024

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    fun packageFileName(): String {
        val stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmm"))
        return "SukiSU-theme-$stamp.zip"
    }

    suspend fun export(
        context: Context,
        uri: Uri,
        data: ThemePackageData,
        backgroundFile: File?,
    ): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val output = context.contentResolver.openOutputStream(uri)
                ?: error("Cannot open the destination file")
            BufferedOutputStream(output).use { buffered ->
                ZipOutputStream(buffered).use { zip ->
                    zip.putNextEntry(ZipEntry(THEME_ENTRY))
                    zip.write(json.encodeToString(ThemePackageData.serializer(), data).toByteArray())
                    zip.closeEntry()
                    if (data.hasBackground == true && backgroundFile != null && backgroundFile.isFile) {
                        zip.putNextEntry(ZipEntry(BACKGROUND_ENTRY))
                        backgroundFile.inputStream().use { it.copyTo(zip) }
                        zip.closeEntry()
                    }
                }
            }
        }
    }

    suspend fun import(context: Context, uri: Uri): Result<ImportedTheme> = withContext(Dispatchers.IO) {
        runCatching {
            val tempBackground = File.createTempFile("theme_bg_", ".tmp", context.cacheDir)
            try {
                var themeText: String? = null
                var backgroundExtracted = false
                val input = context.contentResolver.openInputStream(uri)
                    ?: error("Cannot open the theme package")
                BufferedInputStream(input).use { buffered ->
                    ZipInputStream(buffered).use { zip ->
                        var entry: ZipEntry? = zip.nextEntry
                        while (entry != null) {
                            when (entry.name) {
                                THEME_ENTRY -> themeText = readLimited(zip, MAX_JSON_BYTES).toString(Charsets.UTF_8)
                                BACKGROUND_ENTRY -> {
                                    tempBackground.outputStream().use { copyLimited(zip, it, MAX_BACKGROUND_BYTES) }
                                    backgroundExtracted = true
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
                if (hasBackground) {
                    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                    BitmapFactory.decodeFile(tempBackground.absolutePath, bounds)
                    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) {
                        error("Background image is invalid")
                    }
                }

                val backgroundPath = when {
                    hasBackground -> BgStorage.replace(context, tempBackground)
                        ?: error("Cannot store the background image")

                    else -> null
                }
                ImportedTheme(data = data, backgroundPath = backgroundPath)
            } finally {
                tempBackground.delete()
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
