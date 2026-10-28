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

private const val JPEG_QUALITY = 95

const val CROP_MAX_ZOOM = 8f

data class CropTransform(
    val zoom: Float = 1f,
    val offset: Offset = Offset.Zero,
)

data class OrientedImageSize(val width: Int, val height: Int)

data class CropRect(
    val left: Float,
    val top: Float,
    val right: Float,
    val bottom: Float,
) {
    val width: Float get() = right - left
    val height: Float get() = bottom - top
}

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
fun loadCropSource(file: File): Bitmap? {
    if (!file.isFile) return null
    return runCatching {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.absolutePath, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null

        var sampleSize = 1
        while (max(bounds.outWidth, bounds.outHeight) / sampleSize > MAX_SOURCE_DIMENSION) {
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

/** Produces the bitmap for the current viewport, up to [MAX_OUTPUT_DIMENSION] on its longest edge. */
fun renderCroppedBitmap(
    source: Bitmap,
    quarterTurns: Int,
    transform: CropTransform,
    viewport: Size,
): Bitmap? {
    if (source.isRecycled || viewport.width <= 0f || viewport.height <= 0f) return null
    val turns = normalizeTurns(quarterTurns)
    val oriented = runCatching {
        if (turns == 0) source else rotateBitmap(source, turns)
    }.getOrNull() ?: return null

    val result = runCatching {
        val imageSize = OrientedImageSize(oriented.width, oriented.height)
        val matrix = cropMatrix(viewport, imageSize, transform, turns)
        val inverse = Matrix()
        if (!matrix.invert(inverse)) return@runCatching null
        val crop = viewportCropRect(inverse, viewport, imageSize)
        if (crop.width < 1f || crop.height < 1f) return@runCatching null

        val outputScale = min(1f, MAX_OUTPUT_DIMENSION / max(crop.width, crop.height))
        val outWidth = (crop.width * outputScale).roundToInt().coerceAtLeast(1)
        val outHeight = (crop.height * outputScale).roundToInt().coerceAtLeast(1)
        val output = Bitmap.createBitmap(outWidth, outHeight, Bitmap.Config.ARGB_8888)
        val drawMatrix = Matrix().apply {
            postTranslate(-crop.left, -crop.top)
            postScale(outWidth / crop.width, outHeight / crop.height)
        }
        Canvas(output).drawBitmap(
            oriented,
            drawMatrix,
            Paint(Paint.ANTI_ALIAS_FLAG or Paint.FILTER_BITMAP_FLAG),
        )
        output
    }.getOrNull()

    if (oriented !== source) oriented.recycle()
    return result
}

fun saveCropBitmap(bitmap: Bitmap, file: File): Boolean = runCatching {
    file.parentFile?.mkdirs()
    FileOutputStream(file).use { output ->
        bitmap.compress(Bitmap.CompressFormat.JPEG, JPEG_QUALITY, output)
    }
}.getOrDefault(false)

private fun cropMatrix(
    viewport: Size,
    image: OrientedImageSize,
    transform: CropTransform,
    quarterTurns: Int,
): Matrix {
    val scale = coverScale(viewport, image) * transform.zoom
    return Matrix().apply {
        postTranslate(-image.width / 2f, -image.height / 2f)
        postScale(scale, scale)
        postRotate(quarterTurns * 90f)
        postTranslate(
            viewport.width / 2f + transform.offset.x,
            viewport.height / 2f + transform.offset.y,
        )
    }
}

private fun viewportCropRect(
    inverse: Matrix,
    viewport: Size,
    image: OrientedImageSize,
): CropRect {
    val points = floatArrayOf(
        0f, 0f,
        viewport.width, 0f,
        viewport.width, viewport.height,
        0f, viewport.height,
    )
    inverse.mapPoints(points)
    var left = points[0]
    var top = points[1]
    var right = points[0]
    var bottom = points[1]
    var index = 2
    while (index < points.size) {
        val x = points[index]
        val y = points[index + 1]
        left = min(left, x)
        top = min(top, y)
        right = max(right, x)
        bottom = max(bottom, y)
        index += 2
    }
    return CropRect(
        left = left.coerceIn(0f, image.width.toFloat()),
        top = top.coerceIn(0f, image.height.toFloat()),
        right = right.coerceIn(0f, image.width.toFloat()),
        bottom = bottom.coerceIn(0f, image.height.toFloat()),
    )
}

private fun normalizeTurns(turns: Int): Int = ((turns % 4) + 4) % 4

private fun rotateBitmap(source: Bitmap, quarterTurns: Int): Bitmap {
    val matrix = Matrix().apply { postRotate(quarterTurns * 90f) }
    return Bitmap.createBitmap(source, 0, 0, source.width, source.height, matrix, true)
}

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
