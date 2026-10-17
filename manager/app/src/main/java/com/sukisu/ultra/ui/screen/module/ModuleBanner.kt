package com.sukisu.ultra.ui.screen.module

import android.graphics.BitmapFactory
import android.util.Log
import android.util.LruCache
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.util.getRootShell
import com.topjohnwu.superuser.io.SuFile
import com.topjohnwu.superuser.io.SuFileInputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Request
import kotlin.math.roundToInt

private const val TAG = "ModuleBanner"

private const val MODULE_DIR = "/data/adb/modules/"
private const val MODULE_UPDATE_DIR = "/data/adb/modules_update/"
private const val MAX_BANNER_BYTES = 4L * 1024 * 1024
private const val BANNER_DECODE_PX = 720
private val bannerCache = LruCache<String, ImageBitmap>(32)

private fun readBanner(moduleId: String, banner: String): ByteArray? {
    if (banner.startsWith("http://", true) || banner.startsWith("https://", true)) {
        return ksuApp.okhttpClient.newCall(Request.Builder().url(banner).build()).execute().use { resp ->
            if (!resp.isSuccessful) return null
            val source = resp.body.source()
            if (source.request(MAX_BANNER_BYTES + 1)) return null
            source.readByteArray()
        }
    }
    if (banner.split('/').contains("..")) return null
    val candidates = if (banner.startsWith("/")) {
        listOf(banner).filter { it.startsWith(MODULE_DIR) || it.startsWith(MODULE_UPDATE_DIR) }
    } else {
        listOf("$MODULE_DIR$moduleId/$banner", "$MODULE_UPDATE_DIR$moduleId/$banner")
    }
    val shell = getRootShell()
    val file = candidates.map { SuFile(it).apply { this.shell = shell } }.firstOrNull { it.isFile } ?: return null
    if (file.length() > MAX_BANNER_BYTES) return null
    return SuFileInputStream.open(file).use { it.readBytes() }
}

private fun loadModuleBanner(moduleId: String, banner: String): ImageBitmap? = runCatching {
    val bytes = readBanner(moduleId, banner) ?: return null
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
    var sample = 1
    while (maxOf(bounds.outWidth, bounds.outHeight) / (sample * 2) >= BANNER_DECODE_PX) sample *= 2
    BitmapFactory.decodeByteArray(bytes, 0, bytes.size, BitmapFactory.Options().apply { inSampleSize = sample })
        ?.asImageBitmap()
}.onFailure { Log.w(TAG, "load banner for $moduleId failed: $banner", it) }
    .getOrNull()?.also { bannerCache.put("$moduleId:$banner", it) }

@Composable
fun rememberModuleBanner(moduleId: String, banner: String?): ImageBitmap? {
    if (banner == null) return null
    val key = "$moduleId:$banner"
    val bitmap by produceState(bannerCache.get(key), key) {
        if (value == null) value = withContext(Dispatchers.IO) { loadModuleBanner(moduleId, banner) }
    }
    return bitmap
}

fun Modifier.moduleBanner(banner: ImageBitmap?, scrim: Color): Modifier {
    if (banner == null) return this
    return drawWithCache {
        val scale = maxOf(size.width / banner.width, size.height / banner.height)
        val srcW = (size.width / scale).roundToInt().coerceIn(1, banner.width)
        val srcH = (size.height / scale).roundToInt().coerceIn(1, banner.height)
        val srcOffset = IntOffset((banner.width - srcW) / 2, (banner.height - srcH) / 2)
        val srcSize = IntSize(srcW, srcH)
        val dstSize = IntSize(size.width.roundToInt(), size.height.roundToInt())
        val gradient = Brush.horizontalGradient(
            listOf(scrim.copy(alpha = 0.92f), scrim.copy(alpha = 0.78f), scrim.copy(alpha = 0.45f))
        )
        onDrawBehind {
            drawImage(image = banner, srcOffset = srcOffset, srcSize = srcSize, dstSize = dstSize)
            drawRect(gradient)
        }
    }
}
