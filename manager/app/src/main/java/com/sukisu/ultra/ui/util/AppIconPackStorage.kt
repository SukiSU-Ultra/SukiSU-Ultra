package com.sukisu.ultra.ui.util

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.provider.OpenableColumns
import android.util.Log
import androidx.core.graphics.scale
import com.sukisu.ultra.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.util.Locale
import java.util.UUID
import java.util.zip.ZipFile

@Serializable
data class AppIconEntry(
    val id: String,
    val name: String,
    val fileName: String,
)

@Serializable
data class AppIconPack(
    val id: String,
    val name: String,
    val importedAt: Long = 0L,
    val icons: List<AppIconEntry> = emptyList(),
)

@Serializable
private data class AppIconIndex(
    val version: Int = AppIconPackStorage.CURRENT_VERSION,
    val packs: List<AppIconPack> = emptyList(),
)

/**
 * Stores icon packs imported from ZIP archives. Every image is center-cropped to a square and
 * re-encoded as a 512 px PNG so previews and pinned shortcuts always get launcher-sized artwork.
 */
object AppIconPackStorage {
    const val CURRENT_VERSION = 1
    const val MAX_ICONS_PER_PACK = 64

    private const val TAG = "AppIconPackStorage"
    private const val STORAGE_DIR = "app_icons"
    private const val INDEX_FILE = "index.json"
    private const val ICON_SIZE = 512
    private const val MAX_ZIP_BYTES = 64L * 1024 * 1024
    private const val MAX_ENTRY_BYTES = 16L * 1024 * 1024
    private const val MAX_TOTAL_UNCOMPRESSED_BYTES = 128L * 1024 * 1024
    private const val MAX_SOURCE_DIMENSION = 8192
    private const val MAX_SCANNED_ENTRIES = 512
    private val imageExtensions = setOf("png", "webp", "jpg", "jpeg")

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    /** Serializes imports and deletes so concurrent index updates cannot drop packs. */
    private val writeLock = Mutex()

    suspend fun load(context: Context): List<AppIconPack> = withContext(Dispatchers.IO) {
        readIndex(context).packs.filter { pack ->
            pack.icons.isNotEmpty() && packDir(context, pack.id).isDirectory
        }
    }

    suspend fun import(context: Context, uri: Uri): Result<Int> = withContext(Dispatchers.IO) {
        writeLock.withLock {
            runCatching { importArchive(context, uri) }
                .onFailure { Log.w(TAG, "Cannot import icon pack", it) }
        }
    }

    suspend fun delete(context: Context, packId: String): Result<Unit> = withContext(Dispatchers.IO) {
        writeLock.withLock {
            runCatching {
                val packs = readIndex(context).packs
                if (packs.none { it.id == packId }) return@runCatching
                writeIndex(context, packs.filterNot { it.id == packId })
                packDir(context, packId).deleteRecursively()
            }.onFailure { Log.w(TAG, "Cannot delete icon pack $packId", it) }
        }
    }

    fun iconFile(context: Context, pack: AppIconPack, entry: AppIconEntry): File =
        File(packDir(context, pack.id), entry.fileName)

    suspend fun loadBitmap(
        context: Context,
        pack: AppIconPack,
        entry: AppIconEntry,
    ): Bitmap? = withContext(Dispatchers.IO) {
        runCatching { BitmapFactory.decodeFile(iconFile(context, pack, entry).absolutePath) }
            .getOrNull()
    }

    private fun importArchive(context: Context, uri: Uri): Int {
        val tempZip = File.createTempFile("app_icon_pack_", ".zip", context.cacheDir)
        try {
            val input = context.contentResolver.openInputStream(uri)
                ?: error("Cannot open the archive")
            input.use { source ->
                tempZip.outputStream().use { target -> copyLimited(source, target, MAX_ZIP_BYTES) }
            }

            val packId = randomId()
            val packDir = packDir(context, packId)
            if (!packDir.mkdirs()) error("Cannot create the icon pack directory")

            val entries = ArrayList<AppIconEntry>()
            val budget = ReadBudget(MAX_TOTAL_UNCOMPRESSED_BYTES)
            try {
                ZipFile(tempZip).use { zip ->
                    var scanned = 0
                    for (zipEntry in zip.entries()) {
                        if (entries.size >= MAX_ICONS_PER_PACK ||
                            scanned >= MAX_SCANNED_ENTRIES ||
                            budget.remaining <= 0
                        ) {
                            break
                        }
                        scanned++
                        if (zipEntry.isDirectory || !isImageEntry(zipEntry.name)) continue
                        val bytes = zip.getInputStream(zipEntry)
                            .use { readLimited(it, MAX_ENTRY_BYTES, budget) }
                            ?: continue
                        val bitmap = normalizeBitmap(bytes) ?: continue
                        val iconId = randomId()
                        val fileName = "$iconId.png"
                        val file = File(packDir, fileName)
                        val saved = runCatching {
                            file.outputStream().buffered().use { output ->
                                bitmap.compress(Bitmap.CompressFormat.PNG, 100, output)
                            }
                        }.getOrDefault(false)
                        bitmap.recycle()
                        if (!saved) {
                            file.delete()
                            continue
                        }
                        entries += AppIconEntry(
                            id = iconId,
                            name = displayIconName(context, zipEntry.name, entries.size),
                            fileName = fileName,
                        )
                    }
                }
                if (entries.isEmpty()) error("The archive does not contain usable icons")
            } catch (t: Throwable) {
                if (packDir.exists()) packDir.deleteRecursively()
                throw t
            }

            val pack = AppIconPack(
                id = packId,
                name = resolvePackName(context, uri),
                importedAt = System.currentTimeMillis(),
                icons = entries,
            )
            writeIndex(context, readIndex(context).packs + pack)
            return entries.size
        } finally {
            tempZip.delete()
        }
    }

    private fun isImageEntry(name: String): Boolean {
        if (name.startsWith("__MACOSX/") || name.startsWith(".")) return false
        val baseName = name.substringAfterLast('/')
        if (baseName.isEmpty() || baseName.startsWith(".")) return false
        return baseName.substringAfterLast('.', "").lowercase(Locale.ROOT) in imageExtensions
    }

    private fun displayIconName(context: Context, entryName: String, index: Int): String {
        val baseName = entryName.substringAfterLast('/').substringBeforeLast('.').trim()
        return baseName.take(48).ifEmpty { context.getString(R.string.app_icon_icon_default_name, index + 1) }
    }

    private fun resolvePackName(context: Context, uri: Uri): String {
        val displayName = runCatching {
            context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
                ?.use { cursor ->
                    if (cursor.moveToFirst()) cursor.getString(0) else null
                }
        }.getOrNull()
        return displayName
            ?.substringBeforeLast('.', displayName)
            ?.trim()
            ?.take(48)
            ?.takeIf { it.isNotEmpty() }
            ?: context.getString(R.string.app_icon_pack_default_name)
    }

    private fun normalizeBitmap(bytes: ByteArray): Bitmap? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        if (bounds.outWidth > MAX_SOURCE_DIMENSION || bounds.outHeight > MAX_SOURCE_DIMENSION) return null

        var sampleSize = 1
        while (bounds.outWidth / sampleSize > ICON_SIZE * 2 ||
            bounds.outHeight / sampleSize > ICON_SIZE * 2
        ) {
            sampleSize *= 2
        }
        val options = BitmapFactory.Options().apply { inSampleSize = sampleSize }
        val decoded = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options) ?: return null

        val side = minOf(decoded.width, decoded.height)
        if (side <= 0) {
            decoded.recycle()
            return null
        }
        val x = (decoded.width - side) / 2
        val y = (decoded.height - side) / 2
        val cropped = if (decoded.width == side && decoded.height == side) {
            decoded
        } else {
            Bitmap.createBitmap(decoded, x, y, side, side)
        }
        val scaled = if (side == ICON_SIZE) {
            cropped
        } else {
            cropped.scale(ICON_SIZE, ICON_SIZE)
        }
        if (cropped !== decoded) decoded.recycle()
        if (scaled !== cropped) cropped.recycle()
        return scaled
    }

    private fun copyLimited(input: InputStream, output: java.io.OutputStream, maxBytes: Long) {
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            total += read
            if (total > maxBytes) error("The archive is too large")
            output.write(buffer, 0, read)
        }
    }

    /** Returns null when the entry exceeds [maxBytes] or the remaining archive budget. */
    private fun readLimited(input: InputStream, maxBytes: Long, budget: ReadBudget): ByteArray? {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(32 * 1024)
        var total = 0L
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            total += read
            budget.remaining -= read
            if (total > maxBytes || budget.remaining < 0) return null
            output.write(buffer, 0, read)
        }
        return output.toByteArray()
    }

    private class ReadBudget(var remaining: Long)

    private fun randomId(): String = UUID.randomUUID().toString().replace("-", "").take(16)

    private fun storageDir(context: Context): File = File(context.filesDir, STORAGE_DIR)

    private fun packDir(context: Context, packId: String): File = File(storageDir(context), packId)

    private fun indexFile(context: Context): File = File(storageDir(context), INDEX_FILE)

    private fun readIndex(context: Context): AppIconIndex {
        val file = indexFile(context)
        if (!file.isFile) return AppIconIndex()
        return runCatching {
            json.decodeFromString(AppIconIndex.serializer(), file.readText())
        }.getOrElse {
            Log.w(TAG, "Cannot read the icon pack index", it)
            AppIconIndex()
        }
    }

    private fun writeIndex(context: Context, packs: List<AppIconPack>) {
        val file = indexFile(context)
        file.parentFile?.mkdirs()
        val temp = File(file.parentFile, "${file.name}.tmp")
        temp.writeText(
            json.encodeToString(
                AppIconIndex.serializer(),
                AppIconIndex(packs = packs.sortedBy { it.importedAt }),
            )
        )
        if (!temp.renameTo(file)) {
            file.delete()
            if (!temp.renameTo(file)) error("Cannot write the icon pack index")
        }
    }
}
