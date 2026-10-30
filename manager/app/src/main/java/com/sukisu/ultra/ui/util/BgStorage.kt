package com.sukisu.ultra.ui.util

import android.app.ActivityManager
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Process
import android.system.Os
import android.util.Base64
import com.materialkolor.quantize.QuantizerCelebi
import com.materialkolor.score.Score
import com.topjohnwu.superuser.CallbackList
import com.topjohnwu.superuser.ShellUtils
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicBoolean

object BgStorage {
    private const val DIR_NAME = "backgrounds"
    private const val CROP_DIR_NAME = "background_crop"
    private const val FILE_NAME = "bg_image"
    private const val SYSTEM_WALLPAPER_FILE_NAME = "system_wallpaper"
    private const val SYSTEM_WALLPAPER_SIGNATURE_FILE_NAME = "system_wallpaper.sig"
    private const val MAX_SYSTEM_WALLPAPER_PIXELS = 150_000_000L
    private const val MAX_WALLPAPER_VALIDATION_DIMENSION = 1024

    private val systemWallpaperMutex = Mutex()

    /** Result of copying the launcher wallpaper into the app's private storage. */
    data class SystemWallpaperResult(
        val path: String?,
        /** True when the cached file was written, false when it was already current. */
        val changed: Boolean,
    )

    const val CARD_ALPHA_MIN = 10
    const val CARD_ALPHA_MAX = 91
    const val DEFAULT_CARD_ALPHA = 60

    const val BACKGROUND_BLUR_PERCENT_MIN = 0
    const val BACKGROUND_BLUR_PERCENT_MAX = 100
    const val DEFAULT_BACKGROUND_BLUR_PERCENT = 50

    /** Blur radius applied to the background image at 100%. */
    const val BACKGROUND_BLUR_MAX_RADIUS_DP = 40f

    /**
     * Full-screen wallpaper blur is a noticeable GPU cost on low-RAM devices, so new installs
     * and "restore defaults" start without it there. Existing preferences are left untouched.
     */
    fun defaultBackgroundBlurPercent(context: Context): Int =
        if ((context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager)?.isLowRamDevice == true) {
            0
        } else {
            DEFAULT_BACKGROUND_BLUR_PERCENT
        }

    /** Scrim opacity: negative values darken with black, positive values brighten with white. */
    const val BACKGROUND_SCRIM_MIN = -100
    const val BACKGROUND_SCRIM_MAX = 100
    const val DEFAULT_BACKGROUND_SCRIM = -35

    suspend fun clear(context: Context) = withContext(Dispatchers.IO) {
        val targetFile = prepareFile(context)
        if (targetFile.exists()) {
            targetFile.delete()
        }
    }

    /** Cached copy of the launcher wallpaper, or a non-existent file when it has not been captured. */
    fun systemWallpaperFile(context: Context): File =
        File(backgroundsDir(context), SYSTEM_WALLPAPER_FILE_NAME)

    /**
     * Copies the launcher wallpaper into app-private storage.
     *
     * Android 13+ no longer lets third-party apps read the wallpaper through WallpaperManager
     * (Android 14 always throws), so the file behind the wallpaper service is copied with root
     * access instead and then consumed by the normal background pipeline. [force] skips the
     * signature check and is used when the user explicitly enables the switch.
     */
    suspend fun captureSystemWallpaper(
        context: Context,
        force: Boolean = false,
    ): SystemWallpaperResult = withContext(Dispatchers.IO) {
        systemWallpaperMutex.withLock {
            try {
                val dest = systemWallpaperFile(context)
                val signatureFile = File(dest.parentFile, SYSTEM_WALLPAPER_SIGNATURE_FILE_NAME)
                val source = resolveSystemWallpaperSource(systemWallpaperUserId())
                    ?: return@withLock SystemWallpaperResult(
                        path = dest.takeIf { !force && isDecodableImage(it) }?.absolutePath,
                        changed = false,
                    )
                val signature = systemWallpaperSignature(source)
                val signatureKey = signature?.let { "$source|$it" }
                val previousSignature = runCatching { signatureFile.readText() }.getOrNull()
                if (!force && dest.isFile && signatureKey != null && previousSignature == signatureKey &&
                    isDecodableImage(dest)
                ) {
                    return@withLock SystemWallpaperResult(dest.absolutePath, false)
                }

                if (!writeSystemWallpaperWithRoot(source, dest)) {
                    return@withLock SystemWallpaperResult(
                        path = dest.takeIf { !force && isDecodableImage(it) }?.absolutePath,
                        changed = false,
                    )
                }

                if (signatureKey != null) {
                    runCatching { signatureFile.writeText(signatureKey) }
                }
                SystemWallpaperResult(dest.absolutePath, true)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                SystemWallpaperResult(null, false)
            }
        }
    }

    /** Copies a validated wallpaper into [dest], preserving the previous cache on failure. */
    private fun writeSystemWallpaperWithRoot(source: String, dest: File): Boolean {
        val parent = dest.parentFile ?: return false
        val staging = runCatching {
            File.createTempFile("wallpaper_capture_", ".tmp", parent)
        }.getOrNull() ?: return false

        return try {
            // Create the file as the app first so its owner and SELinux label remain readable
            // after root writes into it. This also keeps a failed capture away from the cache.
            val copiedDirectly = runCatching {
                ShellUtils.fastCmdResult(
                    getRootShell(),
                    "cat ${source.shellQuote()} > ${staging.absolutePath.shellQuote()}",
                )
            }.getOrDefault(false)
            val copied = copiedDirectly || streamBase64Wallpaper(source, staging)
            if (!copied || !isDecodableImage(staging)) return false

            runCatching {
                Os.rename(staging.absolutePath, dest.absolutePath)
                true
            }.getOrDefault(false)
        } finally {
            if (staging.exists()) staging.delete()
        }
    }

    private fun isDecodableImage(file: File): Boolean {
        if (!file.isFile || file.length() == 0L) return false
        return try {
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeFile(file.absolutePath, bounds)
            val width = bounds.outWidth
            val height = bounds.outHeight
            if (width <= 0 || height <= 0 || width.toLong() * height > MAX_SYSTEM_WALLPAPER_PIXELS) {
                return false
            }

            val maxDimension = maxOf(width, height)
            var sampleSize = 1
            while (maxDimension / sampleSize > MAX_WALLPAPER_VALIDATION_DIMENSION) {
                sampleSize *= 2
            }
            val bitmap = BitmapFactory.decodeFile(
                file.absolutePath,
                BitmapFactory.Options().apply {
                    inSampleSize = sampleSize
                    inPreferredConfig = Bitmap.Config.RGB_565
                },
            ) ?: return false
            try {
                bitmap.width > 0 && bitmap.height > 0
            } finally {
                bitmap.recycle()
            }
        } catch (_: OutOfMemoryError) {
            false
        } catch (_: Exception) {
            false
        }
    }

    /** Streams shell output line by line to avoid building a wallpaper-sized Base64 string. */
    private fun streamBase64Wallpaper(source: String, dest: File): Boolean {
        val output = runCatching { dest.outputStream() }.getOrNull() ?: return false
        val writeFailed = AtomicBoolean(false)
        val stdout = object : CallbackList<String?>(Executor { it.run() }) {
            override fun onAddElement(line: String?) {
                if (line.isNullOrEmpty() || writeFailed.get()) return
                try {
                    output.write(Base64.decode(line, Base64.DEFAULT))
                } catch (_: Exception) {
                    writeFailed.set(true)
                }
            }
        }
        val commandSucceeded = try {
            getRootShell().newJob()
                .add("base64 ${source.shellQuote()} | fold -w 4096")
                .to(stdout, null)
                .exec()
                .isSuccess
        } catch (_: Exception) {
            false
        }
        val closeSucceeded = runCatching { output.close() }.isSuccess
        return commandSucceeded && closeSucceeded && !writeFailed.get()
    }

    /** UserHandle.myUserId()/Context.getUserId() are hidden in the SDK; the uid encodes the user. */
    private fun systemWallpaperUserId(): Int = Process.myUid() / 100000

    private fun resolveSystemWallpaperSource(userId: Int): String? {
        val candidates = buildList {
            // AOSP / most OEMs.
            add("/data/system/users/$userId/wallpaper")
            add("/data/system/users/$userId/wallpaper_orig")
            // MIUI/HyperOS keep their own home wallpaper under the theme manager. On some ROMs
            // only this copy is updated, so it is a first-class candidate rather than a fallback.
            add("/data/system/theme_magic/users/$userId/wallpaper/image/home_wallpaper.jpg")
            add("/data/system/theme_magic/users/$userId/wallpaper/image/home_wallpaper.png")
        }
        var best: String? = null
        var bestModified = Long.MIN_VALUE
        for (path in candidates) {
            val modified = wallpaperFileInfo(path)?.first ?: continue
            // Prefer the newest file: after a wallpaper change one of the copies may be stale.
            if (modified > bestModified) {
                best = path
                bestModified = modified
            }
        }
        if (best != null) return best

        // Last resort for ROMs with a custom layout that still use a recognizable file name.
        val discovered = runCatching {
            getRootShell().newJob()
                .add("find /data/system -maxdepth 7 -type f -iname 'home_wallpaper.*' 2>/dev/null | head -5")
                .exec().out
                .map { it.trim() }
                .filter { it.isNotEmpty() }
        }.getOrDefault(emptyList())
        var discoveredBest: String? = null
        var discoveredModified = Long.MIN_VALUE
        for (path in discovered) {
            val modified = wallpaperFileInfo(path)?.first ?: continue
            if (modified > discoveredModified) {
                discoveredBest = path
                discoveredModified = modified
            }
        }
        return discoveredBest
    }

    /** Returns (modifiedTimeSeconds, size) for an existing non-empty regular file. */
    private fun wallpaperFileInfo(path: String): Pair<Long, Long>? = runCatching {
        val quoted = path.shellQuote()
        val out = ShellUtils.fastCmd(getRootShell(), "[ -f $quoted ] && stat -c '%Y:%s' $quoted").trim()
        val parts = out.split(':')
        if (parts.size != 2) return@runCatching null
        val modified = parts[0].toLongOrNull() ?: return@runCatching null
        val size = parts[1].toLongOrNull() ?: return@runCatching null
        if (size > 0L) modified to size else null
    }.getOrNull()

    private fun systemWallpaperSignature(source: String): String? {
        val info = wallpaperFileInfo(source) ?: return null
        return "${info.first}:${info.second}"
    }

    private fun String.shellQuote(): String = "'" + replace("'", "'\\''") + "'"

    /**
     * Copies a picked image into the crop cache. The crop screen and the vendor gallery
     * both work on this private copy so a picker URI never has to stay readable.
     */
    suspend fun stageUri(context: Context, uri: Uri): String? = withContext(Dispatchers.IO) {
        runCatching {
            val target = File.createTempFile("source_", ".img", cropCacheDir(context))
            context.contentResolver.openInputStream(uri)?.use { input ->
                target.outputStream().use { output -> input.copyTo(output) }
            } ?: run {
                target.delete()
                return@runCatching null
            }
            if (target.length() == 0L) {
                target.delete()
                null
            } else {
                target.absolutePath
            }
        }.getOrNull()
    }

    /** Copies an already stored image (for example the current background) into the crop cache. */
    suspend fun stageFile(context: Context, source: File): String? = withContext(Dispatchers.IO) {
        runCatching {
            if (!source.isFile) return@runCatching null
            val target = File.createTempFile("source_", ".img", cropCacheDir(context))
            source.inputStream().use { input ->
                target.outputStream().use { output -> input.copyTo(output) }
            }
            target.absolutePath
        }.getOrNull()
    }

    /** Creates the destination the vendor gallery cropper should write its result to. */
    fun newCropOutput(context: Context): File =
        File.createTempFile("crop_", ".jpg", cropCacheDir(context))

    fun discardStaged(path: String?) {
        if (path.isNullOrEmpty()) return
        runCatching {
            val file = File(path)
            if (file.isFile) file.delete()
        }
    }

    private fun cropCacheDir(context: Context): File {
        val dir = File(context.cacheDir, CROP_DIR_NAME)
        if (!dir.exists()) {
            dir.mkdirs()
        }
        return dir
    }

    /** Moves [source] over the stored background image and returns the new path. */
    suspend fun replace(context: Context, source: File): String? = withContext(Dispatchers.IO) {
        runCatching {
            val targetFile = prepareFile(context)
            if (targetFile.exists() && !targetFile.delete()) return@runCatching null
            if (!source.renameTo(targetFile)) {
                source.inputStream().use { input ->
                    targetFile.outputStream().use { output -> input.copyTo(output) }
                }
            }
            targetFile.absolutePath
        }.getOrNull()
    }

    suspend fun extractSeedColor(
        file: File,
        fallbackColorArgb: Int = 0xFFF27297.toInt()
    ): Int = withContext(Dispatchers.IO) {
        if (!file.exists()) return@withContext fallbackColorArgb
        var bitmapToRecycle: Bitmap? = null
        try {
            val boundsOptions = BitmapFactory.Options().apply {
                inJustDecodeBounds = true
            }
            BitmapFactory.decodeFile(file.absolutePath, boundsOptions)
            if (boundsOptions.outWidth <= 0 || boundsOptions.outHeight <= 0) {
                return@withContext fallbackColorArgb
            }

            val maxDim = maxOf(boundsOptions.outWidth, boundsOptions.outHeight)
            var sampleSize = 1
            while (maxDim / sampleSize > 512) {
                sampleSize *= 2
            }

            val decodeOptions = BitmapFactory.Options().apply {
                inSampleSize = sampleSize
                inPreferredConfig = Bitmap.Config.ARGB_8888
            }
            val sampledBitmap = BitmapFactory.decodeFile(file.absolutePath, decodeOptions)
                ?: return@withContext fallbackColorArgb
            bitmapToRecycle = sampledBitmap

            val scaledBitmap = if (sampledBitmap.width != 128 || sampledBitmap.height != 128) {
                Bitmap.createScaledBitmap(sampledBitmap, 128, 128, true).also { scaled ->
                    if (scaled != sampledBitmap) {
                        sampledBitmap.recycle()
                        bitmapToRecycle = scaled
                    }
                }
            } else {
                sampledBitmap
            }

            val width = scaledBitmap.width
            val height = scaledBitmap.height
            val pixels = IntArray(width * height)
            scaledBitmap.getPixels(pixels, 0, width, 0, 0, width, height)

            val colorToCountMap: Map<Int, Int> = QuantizerCelebi.quantize(pixels, 128)
            val sortedColors: List<Int> = Score.score(colorToCountMap, 10, fallbackColorArgb, true)
            sortedColors.firstOrNull() ?: fallbackColorArgb
        } catch (_: OutOfMemoryError) {
            fallbackColorArgb
        } catch (e: Exception) {
            fallbackColorArgb
        } finally {
            bitmapToRecycle?.let { bitmap ->
                if (!bitmap.isRecycled) bitmap.recycle()
            }
        }
    }

    private fun backgroundsDir(context: Context): File {
        val dir = File(context.filesDir, DIR_NAME)
        if (!dir.exists()) {
            dir.mkdirs()
        }
        return dir
    }

    private fun prepareFile(context: Context): File = File(backgroundsDir(context), FILE_NAME)
}
