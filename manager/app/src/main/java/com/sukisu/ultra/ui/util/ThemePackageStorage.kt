package com.sukisu.ultra.ui.util

import android.content.Context
import android.graphics.BitmapFactory
import android.net.Uri
import com.sukisu.ultra.data.repository.ThemeStoreRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.IOException
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
    val hasCardBackground: Boolean? = null,
    val hideHomeCardStatusText: Boolean? = null,
    val hideHomeCardDecoration: Boolean? = null,
    val homeCardStickerTransforms: List<HomeCardStickerTransform>? = null,
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
    val stickerPaths: List<String> = emptyList(),
)

object ThemePackageStorage {
    /** v2 is the current package format; v1 packages remain importable. */
    const val CURRENT_VERSION = 2
    const val MIN_SUPPORTED_VERSION = 1
    const val THEME_MIME_TYPE = "application/x-sukisu-theme"

    fun isSupportedVersion(version: Int): Boolean =
        version in MIN_SUPPORTED_VERSION..CURRENT_VERSION

    private const val THEME_ENTRY = "theme.json"
    private const val BACKGROUND_ENTRY = "background"
    private const val CARD_BACKGROUND_ENTRY = "card_background"
    private const val CARD_STICKER_ENTRY_PREFIX = "card_sticker_"
    private const val MAX_JSON_BYTES = 64L * 1024
    private const val MAX_BACKGROUND_BYTES = 64L * 1024 * 1024
    /** Caps the total disk a single package can unpack to, not just each image. */
    private const val MAX_EXTRACTED_IMAGE_BYTES = 256L * 1024 * 1024

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
        cardStickerFiles: List<File> = emptyList(),
    ): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val output = context.contentResolver.openOutputStream(uri)
                ?: error("Cannot open the destination file")
            BufferedOutputStream(output).use {
                writeEncryptedZip(it, data, backgroundFile, cardBackgroundFile, cardStickerFiles)
            }
        }
    }

    /** Encrypted package written to an app-private file (used for sharing). */
    suspend fun exportToFile(
        file: File,
        data: ThemePackageData,
        backgroundFile: File?,
        cardBackgroundFile: File? = null,
        cardStickerFiles: List<File> = emptyList(),
    ): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            file.parentFile?.mkdirs()
            BufferedOutputStream(file.outputStream()).use {
                writeEncryptedZip(it, data, backgroundFile, cardBackgroundFile, cardStickerFiles)
            }
        }
    }

    private fun writeEncryptedZip(
        output: OutputStream,
        data: ThemePackageData,
        backgroundFile: File?,
        cardBackgroundFile: File?,
        cardStickerFiles: List<File>,
    ) {
        val encrypted = ThemePackageCrypto.encryptingStream(output)
        ZipOutputStream(encrypted).use { zip ->
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
            cardStickerFiles.filter { it.isFile }.forEachIndexed { index, file ->
                zip.putNextEntry(ZipEntry(CARD_STICKER_ENTRY_PREFIX + index))
                file.inputStream().use { it.copyTo(zip) }
                zip.closeEntry()
            }
        }
    }

    suspend fun import(context: Context, uri: Uri): Result<ImportedTheme> = withContext(Dispatchers.IO) {
        runCatching {
            val zipFile = File.createTempFile("theme_import_zip_", ".zip", context.cacheDir)
            try {
                writeDecryptedZip(context, uri, zipFile)
                parseThemeZip(context, zipFile)
            } finally {
                zipFile.delete()
            }
        }
    }

    /**
     * Streams and decrypts the package into a temporary zip file. This keeps peak memory at
     * the copy buffer instead of loading a package that may be up to 128 MB into a byte array.
     */
    private fun writeDecryptedZip(context: Context, uri: Uri, target: File) {
        val raw = context.contentResolver.openInputStream(uri)
            ?: error("Cannot open the theme package")
        raw.use { input ->
            val limited = LimitedInputStream(input, ThemeStoreRepository.MAX_PACKAGE_BYTES)
            ThemePackageCrypto.decryptingStream(limited).use { decrypted ->
                target.outputStream().buffered().use { output ->
                    val buffer = ByteArray(64 * 1024)
                    var total = 0L
                    while (true) {
                        val read = decrypted.read(buffer)
                        if (read < 0) break
                        total += read
                        if (total > ThemeStoreRepository.MAX_PACKAGE_BYTES) {
                            throw IOException("Theme package is too large")
                        }
                        output.write(buffer, 0, read)
                    }
                    if (total <= 0L) error("Theme package is empty")
                }
            }
        }
    }

    private fun parseThemeZip(context: Context, zipFile: File): ImportedTheme {
        var tempBackground: File? = null
        var tempCardBackground: File? = null
        val tempStickers = mutableMapOf<Int, File>()
        var extractedImageBytes = 0L
        fun copyExtractedImage(input: InputStream, output: OutputStream) {
            val remaining = MAX_EXTRACTED_IMAGE_BYTES - extractedImageBytes
            if (remaining <= 0L) error("Theme package images are too large")
            extractedImageBytes += copyLimited(
                input = input,
                output = output,
                maxBytes = minOf(MAX_BACKGROUND_BYTES, remaining),
            )
        }
        try {
            var themeText: String? = null
            var backgroundExtracted = false
            var cardBackgroundExtracted = false
            FileInputStream(zipFile).use { fileInput ->
                ZipInputStream(fileInput).use { zip ->
                    var entry: ZipEntry? = zip.nextEntry
                    while (entry != null) {
                        val name = entry.name
                        when {
                            name == THEME_ENTRY -> themeText =
                                readLimited(zip, MAX_JSON_BYTES).toString(Charsets.UTF_8)

                            name == BACKGROUND_ENTRY -> {
                                if (tempBackground != null) error("Duplicate background entry")
                                val bg = File.createTempFile("theme_import_bg_", ".tmp", context.cacheDir)
                                tempBackground = bg
                                bg.outputStream().use { copyExtractedImage(zip, it) }
                                backgroundExtracted = true
                            }

                            name == CARD_BACKGROUND_ENTRY -> {
                                if (tempCardBackground != null) {
                                    error("Duplicate card background entry")
                                }
                                val cardBg = File.createTempFile("theme_import_card_", ".tmp", context.cacheDir)
                                tempCardBackground = cardBg
                                cardBg.outputStream().use { copyExtractedImage(zip, it) }
                                cardBackgroundExtracted = true
                            }

                            name.startsWith(CARD_STICKER_ENTRY_PREFIX) -> {
                                val index = name.removePrefix(CARD_STICKER_ENTRY_PREFIX).toIntOrNull()
                                if (index != null && index in 0 until HomeCardSticker.MAX_COUNT) {
                                    if (tempStickers.containsKey(index)) {
                                        error("Duplicate card sticker entry")
                                    }
                                    val sticker = File.createTempFile(
                                        "theme_import_sticker_", ".tmp", context.cacheDir
                                    )
                                    tempStickers[index] = sticker
                                    sticker.outputStream().use { copyExtractedImage(zip, it) }
                                }
                            }
                        }
                        zip.closeEntry()
                        entry = zip.nextEntry
                    }
                }
            }

            val text = themeText ?: error("theme.json is missing")
            val data = json.decodeFromString(ThemePackageData.serializer(), text)
            if (!isSupportedVersion(data.version)) error("Unsupported theme package version")

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
            if (hasCardBackground && !cardBackgroundExtracted) {
                error("Card background image is missing")
            }
            if (hasCardBackground && tempCardBackground != null) {
                val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                BitmapFactory.decodeFile(tempCardBackground.absolutePath, bounds)
                if (bounds.outWidth <= 0 || bounds.outHeight <= 0) {
                    error("Card background image is invalid")
                }
            }

            tempStickers.forEach { (_, sticker) ->
                val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                BitmapFactory.decodeFile(sticker.absolutePath, bounds)
                if (bounds.outWidth <= 0 || bounds.outHeight <= 0) {
                    error("Card sticker image is invalid")
                }
            }

            val orderedStickerPaths = tempStickers.entries
                .sortedBy { it.key }
                .map { it.value.absolutePath }

            return ImportedTheme(
                data = data,
                backgroundPath = tempBackground?.takeIf { hasBackground }?.absolutePath,
                cardBackgroundPath = tempCardBackground?.takeIf { hasCardBackground }?.absolutePath,
                stickerPaths = orderedStickerPaths,
            )
        } catch (e: Exception) {
            tempBackground?.delete()
            tempCardBackground?.delete()
            tempStickers.forEach { (_, file) -> file.delete() }
            throw e
        }
    }

    /**
     * Prevents encrypted packages above the shared 128 MB ceiling from being streamed.
     * One extra byte may be read so an exact-limit file can still reach EOF normally.
     */
    private class LimitedInputStream(
        private val input: InputStream,
        private val maxBytes: Long,
    ) : InputStream() {
        private var readBytes = 0L

        override fun read(): Int {
            if (readBytes >= maxBytes) {
                val extra = input.read()
                if (extra >= 0) throw IOException("Theme package is too large")
                return -1
            }
            val value = input.read()
            if (value >= 0) readBytes++
            return value
        }

        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            if (length == 0) return 0
            if (readBytes == maxBytes) {
                val extra = input.read()
                if (extra >= 0) throw IOException("Theme package is too large")
                return -1
            }
            val allowed = minOf(length.toLong(), maxBytes - readBytes + 1L).toInt()
            val count = input.read(buffer, offset, allowed)
            if (count > 0) {
                readBytes += count
                if (readBytes > maxBytes) throw IOException("Theme package is too large")
            }
            return count
        }

        override fun close() = input.close()
    }

    /** Validates and parses a package without keeping its extracted image files. */
    suspend fun validate(context: Context, uri: Uri): Result<ThemePackageData> = withContext(Dispatchers.IO) {
        import(context, uri).map { imported ->
            imported.backgroundPath?.let { File(it).delete() }
            imported.cardBackgroundPath?.let { File(it).delete() }
            imported.stickerPaths.forEach { File(it).delete() }
            imported.data
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

    private fun copyLimited(input: InputStream, output: OutputStream, maxBytes: Long): Long {
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            total += read
            if (total > maxBytes) error("Theme package entry is too large")
            output.write(buffer, 0, read)
        }
        return total
    }
}
