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

object ImageStorage {
    private const val DIR_NAME = "backgrounds"
    private const val CROP_DIR_NAME = "background_crop"
    private const val FILE_NAME = "bg_image"
    private const val SYSTEM_WALLPAPER_FILE_NAME = "system_wallpaper"
    private const val HOME_CARD_PREFIX = "home_card_image"
    private const val HOME_CARD_STICKER_PREFIX = "home_card_sticker"
    private const val BOTTOM_BAR_ICON_PREFIX = "bottom_bar_icon_"
    private const val BOTTOM_BAR_ICON_MAX_PX = 256
    private const val ADAPTIVE_BACKGROUND_LIGHT = "adaptive_bg_light"
    private const val ADAPTIVE_BACKGROUND_DARK = "adaptive_bg_dark"
    private const val ADAPTIVE_CARD_LIGHT_PREFIX = "adaptive_card_light_"
    private const val ADAPTIVE_CARD_DARK_PREFIX = "adaptive_card_dark_"
    private const val ADAPTIVE_STICKER_LIGHT_PREFIX = "adaptive_sticker_light_"
    private const val ADAPTIVE_STICKER_DARK_PREFIX = "adaptive_sticker_dark_"
    private const val ADAPTIVE_DRAFT_BACKGROUND_LIGHT = "adaptive_draft_bg_light"
    private const val ADAPTIVE_DRAFT_BACKGROUND_DARK = "adaptive_draft_bg_dark"
    private const val ADAPTIVE_DRAFT_CARD_LIGHT_PREFIX = "adaptive_draft_card_light_"
    private const val ADAPTIVE_DRAFT_CARD_DARK_PREFIX = "adaptive_draft_card_dark_"
    private const val ADAPTIVE_DRAFT_STICKER_LIGHT_PREFIX = "adaptive_draft_sticker_light_"
    private const val ADAPTIVE_DRAFT_STICKER_DARK_PREFIX = "adaptive_draft_sticker_dark_"
    private const val SYSTEM_WALLPAPER_SIGNATURE_FILE_NAME = "system_wallpaper.sig"
    private const val MAX_SYSTEM_WALLPAPER_PIXELS = 150_000_000L
    private const val MAX_WALLPAPER_VALIDATION_DIMENSION = 1024

    private val systemWallpaperMutex = Mutex()

    
    data class SystemWallpaperResult(
        val path: String?,
        
        val changed: Boolean,
    )

    const val CARD_ALPHA_MIN = 10
    const val CARD_ALPHA_MAX = 91
    const val DEFAULT_CARD_ALPHA = 60

    const val BACKGROUND_BLUR_PERCENT_MIN = 0
    const val BACKGROUND_BLUR_PERCENT_MAX = 100
    const val DEFAULT_BACKGROUND_BLUR_PERCENT = 50

    
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

    
    const val BACKGROUND_SCRIM_MIN = -100
    const val BACKGROUND_SCRIM_MAX = 100
    const val DEFAULT_BACKGROUND_SCRIM = -35

    suspend fun clear(context: Context) = withContext(Dispatchers.IO) {
        val targetFile = prepareFile(context)
        if (targetFile.exists()) {
            targetFile.delete()
        }
    }

    
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

    /**
     * Copies a picked image into the home status card slot and returns its path.
     * Each save uses a fresh file name so Coil's cache never serves the previous image.
     */
    suspend fun saveHomeCardImage(context: Context, uri: Uri): String? = withContext(Dispatchers.IO) {
        runCatching {
            val dir = backgroundsDir(context)
            val target = File(dir, HOME_CARD_PREFIX + "_" + System.currentTimeMillis())
            context.contentResolver.openInputStream(uri)?.use { input ->
                target.outputStream().use { output -> input.copyTo(output) }
            } ?: return@runCatching null
            if (target.length() == 0L) {
                target.delete()
                return@runCatching null
            }
            dir.listFiles { file -> file.name.startsWith(HOME_CARD_PREFIX) && file != target }
                ?.forEach { it.delete() }
            target.absolutePath
        }.getOrNull()
    }

    suspend fun clearHomeCardImage(context: Context) = withContext(Dispatchers.IO) {
        backgroundsDir(context)
            .listFiles { file -> file.name.startsWith(HOME_CARD_PREFIX) }
            ?.forEach { it.delete() }
    }

    private fun bottomBarIconPrefix(slot: BottomBarIconSlot) =
        BOTTOM_BAR_ICON_PREFIX + slot.key + "_"

    /**
     * Decodes the picked image, scales it down to an icon-sized PNG and writes it to [target].
     * Keeping the alpha channel matters because custom icons are drawn without a tint.
     */
    private fun writeBottomBarIcon(target: File, openInput: () -> java.io.InputStream?): Boolean {
        val raw = File(target.parentFile, target.name + ".raw")
        try {
            openInput()?.use { input -> raw.outputStream().use { input.copyTo(it) } } ?: return false
            if (raw.length() == 0L) return false
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeFile(raw.absolutePath, bounds)
            if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return false
            var sample = 1
            while (bounds.outWidth / (sample * 2) >= BOTTOM_BAR_ICON_MAX_PX &&
                bounds.outHeight / (sample * 2) >= BOTTOM_BAR_ICON_MAX_PX
            ) {
                sample *= 2
            }
            val options = BitmapFactory.Options().apply { inSampleSize = sample }
            val decoded = BitmapFactory.decodeFile(raw.absolutePath, options) ?: return false
            val longest = maxOf(decoded.width, decoded.height)
            val scaled = if (longest > BOTTOM_BAR_ICON_MAX_PX) {
                val ratio = BOTTOM_BAR_ICON_MAX_PX.toFloat() / longest
                Bitmap.createScaledBitmap(
                    decoded,
                    (decoded.width * ratio).toInt().coerceAtLeast(1),
                    (decoded.height * ratio).toInt().coerceAtLeast(1),
                    true,
                )
            } else {
                decoded
            }
            val written = target.outputStream().use { out ->
                scaled.compress(Bitmap.CompressFormat.PNG, 100, out)
            }
            if (scaled !== decoded) scaled.recycle()
            decoded.recycle()
            return written && target.length() > 0L
        } catch (_: Exception) {
            return false
        } finally {
            raw.delete()
        }
    }

    suspend fun saveBottomBarIcon(
        context: Context,
        slot: BottomBarIconSlot,
        uri: Uri,
    ): String? = withContext(Dispatchers.IO) {
        runCatching {
            val dir = backgroundsDir(context)
            val prefix = bottomBarIconPrefix(slot)
            val target = File(dir, prefix + System.currentTimeMillis() + "_" + System.nanoTime())
            if (!writeBottomBarIcon(target) { context.contentResolver.openInputStream(uri) }) {
                target.delete()
                return@runCatching null
            }
            dir.listFiles { file -> file.name.startsWith(prefix) && file != target }
                ?.forEach { it.delete() }
            target.absolutePath
        }.getOrNull()
    }

    suspend fun importBottomBarIcon(
        context: Context,
        slot: BottomBarIconSlot,
        source: File,
    ): String? = withContext(Dispatchers.IO) {
        runCatching {
            val dir = backgroundsDir(context)
            val prefix = bottomBarIconPrefix(slot)
            val target = File(dir, prefix + System.currentTimeMillis() + "_" + System.nanoTime())
            if (!writeBottomBarIcon(target) { source.inputStream() }) {
                target.delete()
                return@runCatching null
            }
            dir.listFiles { file -> file.name.startsWith(prefix) && file != target }
                ?.forEach { it.delete() }
            target.absolutePath
        }.getOrNull()
    }

    suspend fun clearBottomBarIcon(context: Context, slot: BottomBarIconSlot) =
        withContext(Dispatchers.IO) {
            backgroundsDir(context)
                .listFiles { file -> file.name.startsWith(bottomBarIconPrefix(slot)) }
                ?.forEach { it.delete() }
        }

    suspend fun clearBottomBarIcons(context: Context) = withContext(Dispatchers.IO) {
        backgroundsDir(context)
            .listFiles { file -> file.name.startsWith(BOTTOM_BAR_ICON_PREFIX) }
            ?.forEach { it.delete() }
    }

    suspend fun saveHomeCardSticker(context: Context, uri: Uri): String? = withContext(Dispatchers.IO) {
        runCatching {
            val dir = backgroundsDir(context)
            val target = File(dir, HOME_CARD_STICKER_PREFIX + "_" + System.currentTimeMillis() + "_" + System.nanoTime())
            context.contentResolver.openInputStream(uri)?.use { input ->
                target.outputStream().use { output -> input.copyTo(output) }
            } ?: return@runCatching null
            if (target.length() == 0L) {
                target.delete()
                return@runCatching null
            }
            target.absolutePath
        }.getOrNull()
    }

    
    suspend fun deleteHomeCardSticker(context: Context, path: String) = withContext(Dispatchers.IO) {
        val dir = backgroundsDir(context)
        File(path).takeIf { it.parentFile == dir }?.delete()
    }

    suspend fun clearHomeCardSticker(context: Context) = withContext(Dispatchers.IO) {
        backgroundsDir(context)
            .listFiles { file -> file.name.startsWith(HOME_CARD_STICKER_PREFIX) }
            ?.forEach { it.delete() }
    }

    
    suspend fun importHomeCardSticker(context: Context, source: File): String? = withContext(Dispatchers.IO) {
        runCatching {
            val dir = backgroundsDir(context)
            val target = File(dir, HOME_CARD_STICKER_PREFIX + "_" + System.currentTimeMillis() + "_" + System.nanoTime())
            if (!source.renameTo(target)) {
                source.inputStream().use { input ->
                    target.outputStream().use { output -> input.copyTo(output) }
                }
            }
            if (target.length() == 0L) {
                target.delete()
                return@runCatching null
            }
            target.absolutePath
        }.getOrNull()
    }

    
    suspend fun replaceHomeCardImage(context: Context, source: File): String? = withContext(Dispatchers.IO) {
        runCatching {
            val dir = backgroundsDir(context)
            val target = File(dir, HOME_CARD_PREFIX + "_" + System.currentTimeMillis())
            if (!source.renameTo(target)) {
                source.inputStream().use { input ->
                    target.outputStream().use { output -> input.copyTo(output) }
                }
            }
            if (target.length() == 0L) {
                target.delete()
                return@runCatching null
            }
            dir.listFiles { file -> file.name.startsWith(HOME_CARD_PREFIX) && file != target }
                ?.forEach { it.delete() }
            target.absolutePath
        }.getOrNull()
    }

    private fun adaptiveBackgroundName(dark: Boolean, draft: Boolean): String = when {
        draft && dark -> ADAPTIVE_DRAFT_BACKGROUND_DARK
        draft -> ADAPTIVE_DRAFT_BACKGROUND_LIGHT
        dark -> ADAPTIVE_BACKGROUND_DARK
        else -> ADAPTIVE_BACKGROUND_LIGHT
    }

    private fun adaptiveCardPrefix(dark: Boolean, draft: Boolean): String = when {
        draft && dark -> ADAPTIVE_DRAFT_CARD_DARK_PREFIX
        draft -> ADAPTIVE_DRAFT_CARD_LIGHT_PREFIX
        dark -> ADAPTIVE_CARD_DARK_PREFIX
        else -> ADAPTIVE_CARD_LIGHT_PREFIX
    }

    private fun adaptiveStickerPrefix(dark: Boolean, draft: Boolean): String = when {
        draft && dark -> ADAPTIVE_DRAFT_STICKER_DARK_PREFIX
        draft -> ADAPTIVE_DRAFT_STICKER_LIGHT_PREFIX
        dark -> ADAPTIVE_STICKER_DARK_PREFIX
        else -> ADAPTIVE_STICKER_LIGHT_PREFIX
    }

    /**
     * Adaptive themes keep one background per system mode. The files live beside the normal
     * background but use their own names so a manual background change cannot delete them.
     * [draft] uses a separate slot set for the in-app builder, so capturing a draft never
     * overwrites the theme that is currently applied.
     */
    suspend fun replaceAdaptiveBackground(
        context: Context,
        source: File,
        dark: Boolean,
        draft: Boolean = false,
    ): String? = withContext(Dispatchers.IO) {
        runCatching {
            val target = File(backgroundsDir(context), adaptiveBackgroundName(dark, draft))
            if (!source.renameTo(target)) {
                source.inputStream().use { input ->
                    target.outputStream().use { output -> input.copyTo(output) }
                }
            }
            if (target.length() == 0L) {
                target.delete()
                return@runCatching null
            }
            target.absolutePath
        }.getOrNull()
    }

    suspend fun clearAdaptiveBackground(
        context: Context,
        dark: Boolean,
        draft: Boolean = false,
    ) = withContext(Dispatchers.IO) {
        val file = File(backgroundsDir(context), adaptiveBackgroundName(dark, draft))
        if (file.isFile) file.delete()
    }

    
    suspend fun replaceAdaptiveHomeCardImage(
        context: Context,
        source: File,
        dark: Boolean,
        draft: Boolean = false,
    ): String? = withContext(Dispatchers.IO) {
        runCatching {
            val dir = backgroundsDir(context)
            val prefix = adaptiveCardPrefix(dark, draft)
            val target = File(dir, prefix + System.currentTimeMillis())
            if (!source.renameTo(target)) {
                source.inputStream().use { input ->
                    target.outputStream().use { output -> input.copyTo(output) }
                }
            }
            if (target.length() == 0L) {
                target.delete()
                return@runCatching null
            }
            dir.listFiles { file -> file.name.startsWith(prefix) && file != target }
                ?.forEach { it.delete() }
            target.absolutePath
        }.getOrNull()
    }

    suspend fun clearAdaptiveHomeCardImage(
        context: Context,
        dark: Boolean,
        draft: Boolean = false,
    ) = withContext(Dispatchers.IO) {
        val prefix = adaptiveCardPrefix(dark, draft)
        backgroundsDir(context)
            .listFiles { file -> file.name.startsWith(prefix) }
            ?.forEach { it.delete() }
    }

    
    suspend fun importAdaptiveHomeCardSticker(
        context: Context,
        source: File,
        dark: Boolean,
        index: Int,
        draft: Boolean = false,
    ): String? = withContext(Dispatchers.IO) {
        runCatching {
            val dir = backgroundsDir(context)
            val prefix = adaptiveStickerPrefix(dark, draft)
            val target = File(
                dir,
                prefix + index + "_" + System.currentTimeMillis() + "_" + System.nanoTime(),
            )
            if (!source.renameTo(target)) {
                source.inputStream().use { input ->
                    target.outputStream().use { output -> input.copyTo(output) }
                }
            }
            if (target.length() == 0L) {
                target.delete()
                return@runCatching null
            }
            target.absolutePath
        }.getOrNull()
    }

    suspend fun clearAdaptiveHomeCardStickers(
        context: Context,
        dark: Boolean,
        draft: Boolean = false,
    ) = withContext(Dispatchers.IO) {
        val prefix = adaptiveStickerPrefix(dark, draft)
        backgroundsDir(context)
            .listFiles { file -> file.name.startsWith(prefix) }
            ?.forEach { it.delete() }
    }

    
    suspend fun clearAdaptiveImages(context: Context) = withContext(Dispatchers.IO) {
        val dir = backgroundsDir(context)
        dir.listFiles { file ->
            file.name == ADAPTIVE_BACKGROUND_LIGHT ||
                file.name == ADAPTIVE_BACKGROUND_DARK ||
                file.name == ADAPTIVE_DRAFT_BACKGROUND_LIGHT ||
                file.name == ADAPTIVE_DRAFT_BACKGROUND_DARK ||
                file.name.startsWith(ADAPTIVE_CARD_LIGHT_PREFIX) ||
                file.name.startsWith(ADAPTIVE_CARD_DARK_PREFIX) ||
                file.name.startsWith(ADAPTIVE_DRAFT_CARD_LIGHT_PREFIX) ||
                file.name.startsWith(ADAPTIVE_DRAFT_CARD_DARK_PREFIX) ||
                file.name.startsWith(ADAPTIVE_STICKER_LIGHT_PREFIX) ||
                file.name.startsWith(ADAPTIVE_STICKER_DARK_PREFIX) ||
                file.name.startsWith(ADAPTIVE_DRAFT_STICKER_LIGHT_PREFIX) ||
                file.name.startsWith(ADAPTIVE_DRAFT_STICKER_DARK_PREFIX)
        }?.forEach { it.delete() }
    }

    /**
     * Unified exporter for custom images (background wallpaper, home status card and sticker).
     * Multiple images are bundled into a standard unencrypted ZIP archive; a single image is
     * copied directly.
     */
    suspend fun exportImages(
        context: Context,
        uri: Uri,
        backgroundFile: File?,
        cardBackgroundFile: File?,
        stickerFiles: List<File> = emptyList(),
    ): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val entries = buildList {
                backgroundFile?.takeIf { it.isFile }?.let { add("background.png" to it) }
                cardBackgroundFile?.takeIf { it.isFile }?.let { add("home_card.png" to it) }
                stickerFiles.filter { it.isFile }.forEachIndexed { index, file ->
                    add("sticker_${index + 1}.png" to file)
                }
            }
            if (entries.isEmpty()) error("No image to export")

            val output = context.contentResolver.openOutputStream(uri)
                ?: error("Cannot open destination")

            if (entries.size > 1) {
                java.io.BufferedOutputStream(output).use { out ->
                    java.util.zip.ZipOutputStream(out).use { zip ->
                        entries.forEach { (name, file) ->
                            zip.putNextEntry(java.util.zip.ZipEntry(name))
                            file.inputStream().use { it.copyTo(zip) }
                            zip.closeEntry()
                        }
                    }
                }
            } else {
                java.io.BufferedOutputStream(output).use { out ->
                    entries.single().second.inputStream().use { it.copyTo(out) }
                }
            }
            Unit
        }
    }

    
    fun exportImagesFileName(
        hasBackground: Boolean,
        hasCardBackground: Boolean,
        stickerCount: Int,
    ): String = when {
        listOf(hasBackground, hasCardBackground).count { it } + stickerCount > 1 -> "SukiSU-images.zip"
        hasBackground -> "SukiSU-background.png"
        hasCardBackground -> "SukiSU-home-card.png"
        stickerCount > 0 -> "SukiSU-sticker.png"
        else -> "SukiSU-images.zip"
    }
}
