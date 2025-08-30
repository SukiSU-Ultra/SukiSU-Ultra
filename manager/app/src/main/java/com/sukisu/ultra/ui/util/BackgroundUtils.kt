package com.sukisu.ultra.ui.util

import android.content.ContentResolver
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Matrix
import android.net.Uri
import android.util.Log
import androidx.core.graphics.createBitmap
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream

data class BackgroundTransformation(
    val scale: Float = 1f,
    val offsetX: Float = 0f,
    val offsetY: Float = 0f
)

fun Context.getImageBitmap(uri: Uri): Bitmap? {
    return try {
        val contentResolver: ContentResolver = contentResolver
        val inputStream: InputStream = contentResolver.openInputStream(uri) ?: return null
        val bitmap = BitmapFactory.decodeStream(inputStream)
        inputStream.close()
        bitmap
    } catch (e: Exception) {
        Log.e("BackgroundUtils", "Failed to get image bitmap: ${e.message}")
        null
    }
}

fun Context.applyTransformationToBitmap(bitmap: Bitmap, transformation: BackgroundTransformation): Bitmap {
    val width = bitmap.width
    val height = bitmap.height

    // 创建与屏幕比例相同的目标位图
    val displayMetrics = resources.displayMetrics
    val screenWidth = displayMetrics.widthPixels
    val screenHeight = displayMetrics.heightPixels
    val screenRatio = screenHeight.toFloat() / screenWidth.toFloat()

    // 计算目标宽高
    val targetWidth: Int
    val targetHeight: Int
    if (width.toFloat() / height.toFloat() > screenRatio) {
        targetHeight = height
        targetWidth = (height / screenRatio).toInt()
    } else {
        targetWidth = width
        targetHeight = (width * screenRatio).toInt()
    }

    // 创建与目标相同大小的位图
    val scaledBitmap = createBitmap(targetWidth, targetHeight)
    val canvas = Canvas(scaledBitmap)

    val matrix = Matrix()

    // 确保缩放值有效
    val safeScale = maxOf(0.1f, transformation.scale)
    matrix.postScale(safeScale, safeScale)

    // 计算偏移量，确保不会出现负最大值的问题
    val widthDiff = (bitmap.width * safeScale - targetWidth)
    val heightDiff = (bitmap.height * safeScale - targetHeight)

    // 安全计算偏移量边界
    val maxOffsetX = maxOf(0f, widthDiff / 2)
    val maxOffsetY = maxOf(0f, heightDiff / 2)

    // 限制偏移范围
    val safeOffsetX = if (maxOffsetX > 0)
        transformation.offsetX.coerceIn(-maxOffsetX, maxOffsetX) else 0f
    val safeOffsetY = if (maxOffsetY > 0)
        transformation.offsetY.coerceIn(-maxOffsetY, maxOffsetY) else 0f

    // 应用偏移量到矩阵
    val translationX = -widthDiff / 2 + safeOffsetX
    val translationY = -heightDiff / 2 + safeOffsetY

    matrix.postTranslate(translationX, translationY)

    // 将原始位图绘制到新位图上
    canvas.drawBitmap(bitmap, matrix, null)

    return scaledBitmap
}

fun Context.saveTransformedBackground(uri: Uri, transformation: BackgroundTransformation): Uri? {
    try {
        val bitmap = getImageBitmap(uri) ?: return null
        val transformedBitmap = applyTransformationToBitmap(bitmap, transformation)

        val fileName = "custom_background_transformed.jpg"
        val file = File(filesDir, fileName)
        val outputStream = FileOutputStream(file)

        transformedBitmap.compress(Bitmap.CompressFormat.JPEG, 90, outputStream)
        outputStream.flush()
        outputStream.close()

        return Uri.fromFile(file)
    } catch (e: Exception) {
        Log.e("BackgroundUtils", "Failed to save transformed image: ${e.message}", e)
        return null
    }
}