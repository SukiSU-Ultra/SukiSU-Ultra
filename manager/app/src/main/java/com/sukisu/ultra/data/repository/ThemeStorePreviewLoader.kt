package com.sukisu.ultra.data.repository

import android.content.Context
import coil.ImageLoader
import coil.memory.MemoryCache
import com.sukisu.ultra.ksuApp
import okhttp3.Dispatcher

/**
 * Dedicated Coil loader for theme-store grid previews.
 *
 * Only preview cards use this loader, and its OkHttp dispatcher allows four
 * in-flight requests. A finished preview frees a slot for the next card, so a
 * fast scroll cannot fan out dozens of image downloads at once. Detail
 * screenshots keep using the app's normal loader, which has its own dispatcher
 * and therefore starts immediately while the grid's requests are paused.
 */
object ThemeStorePreviewLoader {
    const val MAX_PARALLEL_PREVIEWS = 4

    @Volatile
    private var loader: ImageLoader? = null

    fun get(context: Context): ImageLoader {
        loader?.let { return it }
        return synchronized(this) {
            loader ?: build(context.applicationContext).also { loader = it }
        }
    }

    private fun build(context: Context): ImageLoader {
        val dispatcher = Dispatcher().apply {
            maxRequests = MAX_PARALLEL_PREVIEWS
            maxRequestsPerHost = MAX_PARALLEL_PREVIEWS
        }
        val client = ksuApp.okhttpClient.newBuilder()
            .dispatcher(dispatcher)
            .build()
        return ImageLoader.Builder(context)
            // A separate loader has its own memory cache; keep it small since the
            // shared disk cache still stores the decoded files.
            .memoryCache {
                MemoryCache.Builder(context)
                    .maxSizePercent(0.10)
                    .build()
            }
            .okHttpClient(client)
            .crossfade(true)
            .build()
    }
}
