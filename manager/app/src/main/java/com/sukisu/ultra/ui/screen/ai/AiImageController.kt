package com.sukisu.ultra.ui.screen.ai

import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Base64
import androidx.core.content.FileProvider
import com.sukisu.ultra.BuildConfig
import com.sukisu.ultra.data.repository.SettingsRepositoryImpl
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.util.ImageStorage
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

data class AiThemeImageResult(
    val displayPath: String,
    val themePath: String,
    val target: String,
)

/**
 * OpenAI-compatible image generation/editing plus theme image replacement.
 * Image support is opt-in through a separate image model; a chat-only endpoint
 * simply reports that image generation is not configured.
 */
object AiImageController {

    private const val MAX_IMAGE_BYTES = 32L * 1024 * 1024
    private const val MAX_RESPONSE_BYTES = 64L * 1024 * 1024
    private const val MAX_EDIT_SOURCE_DIMENSION = 2048
    private val json = Json { ignoreUnknownKeys = true; isLenient = true }
    private val jsonMedia = "application/json; charset=utf-8".toMediaType()
    private val repo = SettingsRepositoryImpl()

    private val client = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(180, TimeUnit.SECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
        .build()

    suspend fun generate(config: AiConfig, prompt: String, size: String?): File =
        withContext(Dispatchers.IO) {
            requireConfigured(config)
            val cleanedPrompt = requirePrompt(prompt)
            val payload = buildJsonObject {
                put("model", config.imageModel)
                put("prompt", cleanedPrompt)
                put("n", 1)
                put("size", normalizeSize(size))
                put("response_format", "b64_json")
            }
            val request = Request.Builder()
                .url(config.resolvedImageEndpoint())
                .post(payload.toString().toRequestBody(jsonMedia))
                .applyAuth(config)
                .applyAdvancedHeaders(config)
                .build()
            executeImageRequest(request, "image generation")
        }

    suspend fun edit(
        config: AiConfig,
        prompt: String,
        size: String?,
        source: File,
    ): File = withContext(Dispatchers.IO) {
        requireConfigured(config)
        val cleanedPrompt = requirePrompt(prompt)
        check(source.isFile) { "Source image not found" }
        val png = normalizeForEdit(source)
        try {
            val body = MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("model", config.imageModel)
                .addFormDataPart("prompt", cleanedPrompt)
                .addFormDataPart("n", "1")
                .addFormDataPart("size", normalizeSize(size))
                .addFormDataPart("response_format", "b64_json")
                .addFormDataPart(
                    "image",
                    "source.png",
                    png.readBytes().toRequestBody("image/png".toMediaType()),
                )
                .build()
            val request = Request.Builder()
                .url(config.resolvedImageEditEndpoint())
                .post(body)
                .applyAuth(config)
                .applyAdvancedHeaders(config)
                .build()
            executeImageRequest(request, "image editing")
        } finally {
            png.delete()
        }
    }

    /**
     * Copies the image into the theme slot and returns both the display copy
     * and the stored theme path. [source] may be moved by ImageStorage.
     */
    suspend fun applyToTheme(source: File, target: String): AiThemeImageResult =
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

    suspend fun setFromUri(uri: android.net.Uri, target: String): AiThemeImageResult =
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

    fun currentThemeImage(target: String): File? {
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

    fun shareImages(files: List<File>, title: String): Boolean {
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

    private fun requireConfigured(config: AiConfig) {
        check(config.effectiveFormat() == AiProviderFormat.OPENAI) {
            "Image generation requires an OpenAI-compatible endpoint; the current format is ${config.effectiveFormat().name}. Set the image model in assistant settings."
        }
        check(config.imageModel.isNotBlank()) {
            "Image generation is not configured. Set an image model in assistant settings first."
        }
        check(config.endpoint.isNotBlank()) { "API address is empty" }
    }

    private fun requirePrompt(prompt: String): String {
        val cleaned = prompt.trim()
        require(cleaned.isNotEmpty()) { "prompt is required" }
        require(cleaned.length <= 1200) { "prompt is too long" }
        return cleaned
    }

    private fun normalizeSize(size: String?): String {
        val value = size?.trim().orEmpty()
        if (value.isEmpty()) return "1024x1024"
        require(Regex("""^\d{2,4}x\d{2,4}$""").matches(value)) {
            "size must look like 1024x1024"
        }
        return value
    }

    private fun Request.Builder.applyAdvancedHeaders(config: AiConfig): Request.Builder {
        if (config.advancedMode) {
            config.advancedOptions().headers.forEach { (name, value) ->
                if (name.isNotBlank()) header(name, value)
            }
        }
        return this
    }

    private fun Request.Builder.applyAuth(config: AiConfig): Request.Builder {
        val key = config.apiKey.trim()
        if (key.isNotEmpty()) {
            if (config.resolvedImageEndpoint().contains("openai.azure.com", true)) {
                header("api-key", key)
            } else {
                header("Authorization", "Bearer $key")
            }
        }
        return this
    }

    private fun executeImageRequest(request: Request, operation: String): File {
        client.newCall(request).execute().use { response ->
            val source = response.body.source()
            check(!source.request(MAX_RESPONSE_BYTES + 1)) { "Image response is too large" }
            val body = source.readUtf8()
            if (!response.isSuccessful) {
                val message = runCatching {
                    val root = json.parseToJsonElement(body) as? JsonObject
                    root?.get("error")?.let { error ->
                        if (error is JsonObject) {
                            (error["message"] as? JsonPrimitive)?.contentOrNull
                        } else {
                            (error as? JsonPrimitive)?.contentOrNull
                        }
                    }
                }.getOrNull()
                throw IllegalStateException(
                    "HTTP ${response.code} during $operation: ${message?.take(400) ?: body.take(400)}"
                )
            }
            val root = runCatching { json.parseToJsonElement(body) as? JsonObject }.getOrNull()
                ?: throw IllegalStateException("Unexpected image response")
            root["error"]?.let { error ->
                val message = if (error is JsonObject) {
                    (error["message"] as? JsonPrimitive)?.contentOrNull
                } else {
                    (error as? JsonPrimitive)?.contentOrNull
                }
                throw IllegalStateException(message ?: "Image request rejected")
            }
            val data = root["data"] as? JsonArray
            val first = data?.firstOrNull() as? JsonObject
                ?: throw IllegalStateException("Image response has no data")
            val base64 = (first["b64_json"] as? JsonPrimitive)?.contentOrNull
            if (!base64.isNullOrBlank()) {
                return writeBase64Image(base64)
            }
            val url = (first["url"] as? JsonPrimitive)?.contentOrNull
                ?: throw IllegalStateException("Image response has neither b64_json nor url")
            return downloadImage(url)
        }
    }

    private fun writeBase64Image(value: String): File {
        val bytes = Base64.decode(value, Base64.DEFAULT)
        check(bytes.size <= MAX_IMAGE_BYTES) { "Generated image is too large" }
        return writeImage(bytes)
    }

    private fun downloadImage(url: String): File {
        require(url.startsWith("https://", true)) { "Image URL must use HTTPS" }
        val request = Request.Builder().url(url).build()
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) throw IllegalStateException("HTTP ${response.code} downloading image")
            val body = response.body
            val source = body.source()
            check(!source.request(MAX_IMAGE_BYTES + 1)) { "Generated image is too large" }
            val bytes = source.readByteArray()
            check(bytes.size <= MAX_IMAGE_BYTES) { "Generated image is too large" }
            return writeImage(bytes)
        }
    }

    private fun writeImage(bytes: ByteArray): File {
        val file = File(ksuApp.cacheDir, "ai-generated-${System.currentTimeMillis()}.png")
        file.writeBytes(bytes)
        val options = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(file.absolutePath, options)
        if (options.outWidth <= 0 || options.outHeight <= 0) {
            file.delete()
            throw IllegalStateException("Provider returned data that is not a decodable image")
        }
        return file
    }

    private fun normalizeForEdit(source: File): File {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(source.absolutePath, bounds)
        check(bounds.outWidth > 0 && bounds.outHeight > 0) { "Source is not a decodable image" }
        var sample = 1
        while (maxOf(bounds.outWidth, bounds.outHeight) / sample > MAX_EDIT_SOURCE_DIMENSION) {
            sample *= 2
        }
        val options = BitmapFactory.Options().apply {
            inSampleSize = sample
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        val bitmap = BitmapFactory.decodeFile(source.absolutePath, options)
            ?: throw IOException("Cannot decode the source image")
        val output = File(ksuApp.cacheDir, "ai-edit-source-${System.currentTimeMillis()}.png")
        try {
            output.outputStream().use { stream ->
                check(bitmap.compress(Bitmap.CompressFormat.PNG, 100, stream)) {
                    "Cannot encode the source image"
                }
            }
        } finally {
            bitmap.recycle()
        }
        return output
    }
}
