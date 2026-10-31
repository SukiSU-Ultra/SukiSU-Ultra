package com.sukisu.ultra.ai

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Base64
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

/**
 * OpenAI-compatible image generation/editing. Theme storage stays in the host
 * behind [com.sukisu.ultra.ai.api.AiThemeImageService].
 */
object AiImageController {

    private const val MAX_IMAGE_BYTES = 32L * 1024 * 1024
    private const val MAX_RESPONSE_BYTES = 64L * 1024 * 1024
    private const val MAX_EDIT_SOURCE_DIMENSION = 2048
    private val json = Json { ignoreUnknownKeys = true; isLenient = true }
    private val jsonMedia = "application/json; charset=utf-8".toMediaType()

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
        val file = File(aiContext.cacheDir, "ai-generated-${System.currentTimeMillis()}.png")
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
        val output = File(aiContext.cacheDir, "ai-edit-source-${System.currentTimeMillis()}.png")
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
