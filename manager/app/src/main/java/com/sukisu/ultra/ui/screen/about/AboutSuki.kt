package com.sukisu.ultra.ui.screen.about

import android.content.Context
import android.graphics.BitmapFactory
import android.util.Log
import android.util.LruCache
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

private const val TAG = "AboutSuki"

// Generated into assets/about by hand before a release, most recently active first.
private const val CONTRIBUTORS_JSON = "about/contributors.json"
private const val AVATAR_DIR = "about/contributors"

private val json = Json { ignoreUnknownKeys = true }
private val avatarCache = LruCache<String, ImageBitmap>(64)
private var contributorsCache: List<Contributor>? = null

@Immutable
@Serializable
data class Contributor(
    val login: String,
    val profileUrl: String,
)

private fun loadContributors(context: Context): List<Contributor> = runCatching {
    context.assets.open(CONTRIBUTORS_JSON).use { json.decodeFromString<List<Contributor>>(it.readBytes().decodeToString()) }
}.onFailure { Log.w(TAG, "load contributors failed", it) }
    .getOrDefault(emptyList())
    .also { contributorsCache = it }

private fun loadAvatar(context: Context, login: String): ImageBitmap? = runCatching {
    context.assets.open("$AVATAR_DIR/$login.jpg").use { BitmapFactory.decodeStream(it)?.asImageBitmap() }
}.onFailure { Log.w(TAG, "load avatar failed: $login", it) }
    .getOrNull()?.also { avatarCache.put(login, it) }

/** Main contributors bundled with the app, most recently active first. */
@Composable
fun rememberContributors(): List<Contributor> {
    val context = LocalContext.current
    val list by produceState(contributorsCache.orEmpty()) {
        if (value.isEmpty()) value = withContext(Dispatchers.IO) { loadContributors(context) }
    }
    return list
}

@Composable
fun rememberContributorAvatar(login: String): ImageBitmap? {
    val context = LocalContext.current
    val bitmap by produceState(avatarCache.get(login), login) {
        if (value == null) value = withContext(Dispatchers.IO) { loadAvatar(context, login) }
    }
    return bitmap
}
