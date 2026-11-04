package com.sukisu.ultra.ui.util

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import androidx.annotation.RequiresApi
import androidx.core.content.FileProvider
import java.io.File
import java.io.IOException
import java.io.OutputStream
import java.util.concurrent.ConcurrentHashMap

internal class DownloadDestination private constructor(
    val uri: Uri,
    val displayName: String,
    private val openOutput: () -> OutputStream,
    private val publishOutput: () -> Unit,
    private val cleanupOutput: () -> Unit,
) {
    fun openOutputStream(): OutputStream = openOutput()
    fun publish() = publishOutput()
    fun delete() {
        cleanupOutput()
        LegacyDownloadFiles.forget(uri)
    }

    companion object {
        fun create(context: Context, displayName: String, mimeType: String?): DownloadDestination {
            val safeName = sanitizeDisplayName(displayName)
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                createMediaStoreDestination(context, safeName, mimeType)
            } else {
                createCacheDestination(context, safeName)
            }
        }

        @RequiresApi(Build.VERSION_CODES.Q)
        private fun createMediaStoreDestination(
            context: Context,
            displayName: String,
            mimeType: String?,
        ): DownloadDestination {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, displayName)
                put(MediaStore.Downloads.MIME_TYPE, mimeType ?: "application/octet-stream")
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
            val uri = context.contentResolver.insert(
                MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY),
                values,
            ) ?: throw IOException("Failed to create download")
            return DownloadDestination(
                uri = uri,
                displayName = uri.getFileName(context) ?: displayName,
                openOutput = {
                    context.contentResolver.openOutputStream(uri)
                        ?: throw IOException("Failed to open download")
                },
                publishOutput = {
                    val published = ContentValues().apply {
                        put(MediaStore.Downloads.IS_PENDING, 0)
                    }
                    if (context.contentResolver.update(uri, published, null, null) != 1) {
                        throw IOException("Failed to publish download")
                    }
                },
                cleanupOutput = {
                    runCatching { context.contentResolver.delete(uri, null, null) }
                },
            )
        }

        private fun createCacheDestination(context: Context, displayName: String): DownloadDestination {
            val directory = File(context.cacheDir, "downloads").apply { mkdirs() }
            val file = createUniqueFile(directory, displayName)
            val uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                file,
            )
            LegacyDownloadFiles.remember(uri, file)
            return DownloadDestination(
                uri = uri,
                displayName = file.name,
                openOutput = { file.outputStream() },
                publishOutput = {},
                cleanupOutput = { file.delete() },
            )
        }

        private fun createUniqueFile(directory: File, displayName: String): File {
            val dot = displayName.lastIndexOf('.')
            val stem = if (dot > 0) displayName.substring(0, dot) else displayName
            val extension = if (dot > 0) displayName.substring(dot) else ""
            var file = File(directory, displayName)
            var index = 1
            while (!file.createNewFile()) {
                file = File(directory, "$stem (${index++})$extension")
            }
            return file
        }

        private fun sanitizeDisplayName(raw: String): String =
            raw.substringAfterLast('/').substringAfterLast('\\').trim()
                .replace(Regex("[\\x00-\\x1F]"), "_")
                .ifBlank { "download.bin" }
    }
}

internal object LegacyDownloadFiles {
    private val files = ConcurrentHashMap<String, File>()

    fun remember(uri: Uri, file: File) {
        files[uri.toString()] = file
    }

    fun forget(uri: Uri) {
        files.remove(uri.toString())
    }

    fun delete(uri: Uri): Boolean {
        val file = files.remove(uri.toString()) ?: return false
        return runCatching { file.delete() }.getOrDefault(false)
    }
}
