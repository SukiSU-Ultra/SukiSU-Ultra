package com.sukisu.ultra.ai.host

import com.sukisu.ultra.ai.api.AiThemeImageResult
import com.sukisu.ultra.ai.api.AiThemeImageService

import android.content.Intent
import android.graphics.BitmapFactory
import androidx.core.content.FileProvider
import com.sukisu.ultra.BuildConfig
import com.sukisu.ultra.data.repository.SettingsRepositoryImpl
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.util.ImageStorage
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Theme background/home-card image storage and sharing.
 */
object AiThemeImageStore : AiThemeImageService {

    private val repo = SettingsRepositoryImpl()


    override suspend fun applyToTheme(source: File, target: String): AiThemeImageResult =
        withContext(Dispatchers.IO) {
            check(source.isFile) { "Image file not found" }
            val display = File(ksuApp.cacheDir, "ai-image-${System.currentTimeMillis()}.png")
            source.copyTo(display, overwrite = true)
            val staging = File(ksuApp.cacheDir, "ai-theme-${System.currentTimeMillis()}.png")
            display.copyTo(staging, overwrite = true)
            val normalizedTarget = target.trim().lowercase().replace('-', '_')
            val themePath = when (normalizedTarget) {
                "background", "wallpaper" -> {
                    val path = ImageStorage.replace(ksuApp, staging)
                        ?: throw IllegalStateException("Failed to store the background image")
                    repo.customBackgroundUri = path
                    repo.customBackgroundUpdatedAt = System.currentTimeMillis()
                    repo.useSystemWallpaper = false
                    if (repo.extractColorFromBackground) {
                        repo.keyColor = ImageStorage.extractSeedColor(File(path), repo.keyColor)
                    }
                    path
                }

                "home_card", "home", "card" -> {
                    val path = ImageStorage.replaceHomeCardImage(ksuApp, staging)
                        ?: throw IllegalStateException("Failed to store the home card image")
                    repo.homeCardImagePath = path
                    path
                }

                else -> throw IllegalArgumentException("target must be background or home_card")
            }
            AiThemeImageResult(
                displayPath = display.absolutePath,
                themePath = themePath,
                target = normalizedTarget,
            )
        }

    override suspend fun setFromUri(uri: android.net.Uri, target: String): AiThemeImageResult =
        withContext(Dispatchers.IO) {
            val staged = ImageStorage.stageUri(ksuApp, uri)
                ?: throw IllegalStateException("Could not read the selected image")
            try {
                val file = File(staged)
                val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                BitmapFactory.decodeFile(file.absolutePath, bounds)
                check(bounds.outWidth > 0 && bounds.outHeight > 0) {
                    "The selected file is not a decodable image"
                }
                check(bounds.outWidth.toLong() * bounds.outHeight <= 100_000_000L) {
                    "The selected image is too large"
                }
                applyToTheme(file, target)
            } finally {
                ImageStorage.discardStaged(staged)
            }
        }

    override fun currentThemeImage(target: String): File? {
        val normalized = target.trim().lowercase().replace('-', '_')
        if (normalized == "background" || normalized == "wallpaper") {
            if (repo.useSystemWallpaper) {
                ImageStorage.systemWallpaperFile(ksuApp).takeIf { it.isFile }?.let { return it }
            }
            return repo.customBackgroundUri.takeIf { it.isNotBlank() }
                ?.let(::File)?.takeIf { it.isFile }
        }
        val path = when (normalized) {
            "home_card", "home", "card" -> repo.homeCardImagePath
            else -> ""
        }
        return path.takeIf { it.isNotBlank() }?.let(::File)?.takeIf { it.isFile }
    }

    override fun shareImages(files: List<File>, title: String): Boolean {
        val valid = files.filter { it.isFile }.take(5)
        return valid.isNotEmpty() && runCatching {
            val dir = File(ksuApp.cacheDir, "ai_share")
            if (!dir.exists()) dir.mkdirs()
            val uris = valid.map { file ->
                val shared = File(dir, "ai-${System.currentTimeMillis()}-${file.name}")
                file.copyTo(shared, overwrite = true)
                FileProvider.getUriForFile(
                    ksuApp,
                    "${BuildConfig.APPLICATION_ID}.fileprovider",
                    shared,
                )
            }
            val intent = Intent(
                if (uris.size == 1) Intent.ACTION_SEND else Intent.ACTION_SEND_MULTIPLE
            ).apply {
                type = "image/*"
                if (uris.size == 1) {
                    putExtra(Intent.EXTRA_STREAM, uris.first())
                } else {
                    putParcelableArrayListExtra(Intent.EXTRA_STREAM, ArrayList(uris))
                }
                putExtra(Intent.EXTRA_TITLE, title)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            ksuApp.startActivity(
                Intent.createChooser(intent, title)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
            true
        }.getOrDefault(false)
    }
}
