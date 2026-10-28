package com.sukisu.ultra.ui.util

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import com.materialkolor.quantize.QuantizerCelebi
import com.materialkolor.score.Score
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

object BgStorage {
    private const val DIR_NAME = "backgrounds"
    private const val CROP_DIR_NAME = "background_crop"
    private const val FILE_NAME = "bg_image"

    const val CARD_ALPHA_MIN = 10
    const val CARD_ALPHA_MAX = 91
    const val DEFAULT_CARD_ALPHA = 60

    const val BACKGROUND_BLUR_PERCENT_MIN = 0
    const val BACKGROUND_BLUR_PERCENT_MAX = 100
    const val DEFAULT_BACKGROUND_BLUR_PERCENT = 50

    /** Blur radius applied to the background image at 100%. */
    const val BACKGROUND_BLUR_MAX_RADIUS_DP = 40f

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

            val scaledBitmap = if (sampledBitmap.width != 128 || sampledBitmap.height != 128) {
                Bitmap.createScaledBitmap(sampledBitmap, 128, 128, true).also {
                    if (it != sampledBitmap) sampledBitmap.recycle()
                }
            } else {
                sampledBitmap
            }

            val width = scaledBitmap.width
            val height = scaledBitmap.height
            val pixels = IntArray(width * height)
            scaledBitmap.getPixels(pixels, 0, width, 0, 0, width, height)
            scaledBitmap.recycle()

            val colorToCountMap: Map<Int, Int> = QuantizerCelebi.quantize(pixels, 128)
            val sortedColors: List<Int> = Score.score(colorToCountMap, 10, fallbackColorArgb, true)
            sortedColors.firstOrNull() ?: fallbackColorArgb
        } catch (e: Exception) {
            fallbackColorArgb
        }
    }

    private fun prepareFile(context: Context): File {
        val dir = File(context.filesDir, DIR_NAME)
        if (!dir.exists()) {
            dir.mkdirs()
        }
        return File(dir, FILE_NAME)
    }
}
