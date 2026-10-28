package com.sukisu.ultra.ui.screen.backgroundcrop

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Matrix
import android.graphics.Paint
import android.media.ExifInterface
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import java.io.File
import java.io.FileOutputStream
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt

/** Sources are downsampled to this longest edge; it is plenty for a full-screen background. */
private const val MAX_SOURCE_DIMENSION = 2560

/** Crops are rendered at most at this longest edge. */
private const val MAX_OUTPUT_DIMENSION = 2560

/** Keep the transient bitmaps smaller on low-RAM devices. */
private const val LOW_RAM_SOURCE_DIMENSION = 2048
private const val LOW_RAM_OUTPUT_DIMENSION = 2048

private const val JPEG_QUALITY = 95

const val CROP_MAX_ZOOM = 8f

data class CropTransform(
    val zoom: Float = 1f,
    val offset: Offset = Offset.Zero,
)

data class OrientedImageSize(val width: Int, val height: Int)

fun orientedImageSize(bitmap: Bitmap, quarterTurns: Int): OrientedImageSize {
    val turns = normalizeTurns(quarterTurns)
    return if (turns % 2 == 0) {
        OrientedImageSize(bitmap.width, bitmap.height)
    } else {
        OrientedImageSize(bitmap.height, bitmap.width)
    }
}

/** Scale at which the oriented image exactly covers the viewport. */
fun coverScale(viewport: Size, image: OrientedImageSize): Float {
    if (viewport.width <= 0f || viewport.height <= 0f || image.width <= 0 || image.height <= 0) {
        return 1f
    }
    return max(viewport.width / image.width, viewport.height / image.height)
}

fun clampCropTransform(
    transform: CropTransform,
    viewport: Size,
    image: OrientedImageSize,
): CropTransform {
    if (viewport.width <= 0f || viewport.height <= 0f || image.width <= 0 || image.height <= 0) {
        return CropTransform()
    }
    val zoom = transform.zoom.coerceIn(1f, CROP_MAX_ZOOM)
    val base = coverScale(viewport, image)
    val maxX = max(0f, (image.width * base * zoom - viewport.width) / 2f)
    val maxY = max(0f, (image.height * base * zoom - viewport.height) / 2f)
    return CropTransform(
        zoom = zoom,
        offset = Offset(
            x = transform.offset.x.coerceIn(-maxX, maxX),
            y = transform.offset.y.coerceIn(-maxY, maxY),
        ),
    )
}

/**
 * Loads a crop source, applying the EXIF orientation so the editor and both crop paths
 * see the same upright image.
 */
fun loadCropSource(file: File, lowRam: Boolean = false): Bitmap? {
    if (!file.isFile) return null
    val maxDimension = if (lowRam) LOW_RAM_SOURCE_DIMENSION else MAX_SOURCE_DIMENSION
    return runCatching {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.absolutePath, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null

        var sampleSize = 1
        while (max(bounds.outWidth, bounds.outHeight) / sampleSize > maxDimension) {
            sampleSize *= 2
        }
        val options = BitmapFactory.Options().apply {
            inSampleSize = sampleSize
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        val decoded = BitmapFactory.decodeFile(file.absolutePath, options) ?: return null
        val matrix = exifMatrix(readExifOrientation(file))
        if (matrix == null) {
            decoded
        } else {
            val oriented = Bitmap.createBitmap(decoded, 0, 0, decoded.width, decoded.height, matrix, true)
            if (oriented != decoded) decoded.recycle()
            oriented
        }
    }.getOrNull()
}

/**
 * Renders exactly what the crop editor shows, without allocating an intermediate rotated
 * bitmap. The source is drawn once into the output through the same transform used by
 * [CropViewport]; on a rotated crop the old implementation kept a rotated copy plus a
 * cropped copy alive, which was the main memory peak for large images.
 */
fun renderCroppedBitmap(
    source: Bitmap,
    quarterTurns: Int,
    transform: CropTransform,
    viewport: Size,
    lowRam: Boolean = false,
): Bitmap? {
    if (source.isRecycled || viewport.width <= 0f || viewport.height <= 0f) return null
    val turns = normalizeTurns(quarterTurns)
    val imageSize = orientedImageSize(source, turns)
    val scale = coverScale(viewport, imageSize) * transform.zoom
    if (!scale.isFinite() || scale <= 0f) return null

    val viewportMax = max(viewport.width, viewport.height)
    val maxOutput = (if (lowRam) LOW_RAM_OUTPUT_DIMENSION else MAX_OUTPUT_DIMENSION).toFloat()
    // Do not upscale beyond the source pixels that are visible in the crop frame.
    val visibleSourceMax = viewportMax / scale
    val outputScale = min(maxOutput, visibleSourceMax) / viewportMax
    if (!outputScale.isFinite() || outputScale <= 0f) return null

    val outWidth = (viewport.width * outputScale).roundToInt().coerceAtLeast(1)
    val outHeight = (viewport.height * outputScale).roundToInt().coerceAtLeast(1)

    return runCatching {
        val output = Bitmap.createBitmap(outWidth, outHeight, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(output)
        // Map output pixels back to the editor's viewport, then apply the same source transform
        // the editor uses: centre the source, scale to cover, rotate, place in the viewport.
        canvas.scale(outputScale, outputScale)
        val matrix = Matrix().apply {
            postTranslate(-source.width / 2f, -source.height / 2f)
            postScale(scale, scale)
            postRotate(turns * 90f)
            postTranslate(
                viewport.width / 2f + transform.offset.x,
                viewport.height / 2f + transform.offset.y,
            )
        }
        canvas.concat(matrix)
        canvas.drawBitmap(
            source,
            0f,
            0f,
            Paint(Paint.ANTI_ALIAS_FLAG or Paint.FILTER_BITMAP_FLAG),
        )
        output
    }.getOrNull()
}

fun saveCropBitmap(bitmap: Bitmap, file: File): Boolean = runCatching {
    file.parentFile?.mkdirs()
    FileOutputStream(file).use { output ->
        bitmap.compress(Bitmap.CompressFormat.JPEG, JPEG_QUALITY, output)
    }
}.getOrDefault(false)

private fun normalizeTurns(turns: Int): Int = ((turns % 4) + 4) % 4

private fun readExifOrientation(file: File): Int = runCatching {
    ExifInterface(file.absolutePath).getAttributeInt(
        ExifInterface.TAG_ORIENTATION,
        ExifInterface.ORIENTATION_NORMAL,
    )
}.getOrDefault(ExifInterface.ORIENTATION_NORMAL)

private fun exifMatrix(orientation: Int): Matrix? {
    if (orientation == ExifInterface.ORIENTATION_NORMAL || orientation == ExifInterface.ORIENTATION_UNDEFINED) {
        return null
    }
    return Matrix().apply {
        when (orientation) {
            ExifInterface.ORIENTATION_FLIP_HORIZONTAL -> postScale(-1f, 1f)
            ExifInterface.ORIENTATION_ROTATE_180 -> postRotate(180f)
            ExifInterface.ORIENTATION_FLIP_VERTICAL -> postScale(1f, -1f)
            ExifInterface.ORIENTATION_TRANSPOSE -> {
                postRotate(270f)
                postScale(-1f, 1f)
            }
            ExifInterface.ORIENTATION_ROTATE_90 -> postRotate(90f)
            ExifInterface.ORIENTATION_TRANSVERSE -> {
                postRotate(90f)
                postScale(-1f, 1f)
            }
            ExifInterface.ORIENTATION_ROTATE_270 -> postRotate(270f)
            else -> return null
        }
    }
}
