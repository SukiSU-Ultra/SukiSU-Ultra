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
import java.io.IOException

object BgStorage {
    private const val DIR_NAME = "backgrounds"
    private const val FILE_NAME = "bg_image"

    const val CARD_ALPHA_MIN = 10
    const val CARD_ALPHA_MAX = 91
    const val DEFAULT_CARD_ALPHA = 60

    suspend fun persist(context: Context, uri: Uri): String? = withContext(Dispatchers.IO) {
        runCatching {
            val targetFile = prepareFile(context)
            context.contentResolver.openInputStream(uri)?.use { input ->
                targetFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            } ?: return@runCatching null
            targetFile.absolutePath
        }.getOrNull()
    }

    suspend fun clear(context: Context) = withContext(Dispatchers.IO) {
        val targetFile = prepareFile(context)
        if (targetFile.exists()) {
            targetFile.delete()
        }
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
