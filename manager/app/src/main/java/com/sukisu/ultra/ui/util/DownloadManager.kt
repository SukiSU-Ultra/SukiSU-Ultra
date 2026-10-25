package com.sukisu.ultra.ui.util

import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.provider.DocumentsContract
import android.util.Log
import androidx.core.content.ContextCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import com.sukisu.ultra.data.registry.DownloadVerificationException
import com.sukisu.ultra.data.registry.ExpectedFile
import com.sukisu.ultra.data.registry.RegistryUrls
import com.sukisu.ultra.data.registry.canShareDownload
import com.sukisu.ultra.ksuApp
import com.topjohnwu.superuser.ShellUtils
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

object DownloadManager {

    enum class Status { PENDING, DOWNLOADING, COMPLETED, FAILED }

    data class DownloadState(
        val id: Int,
        val fileName: String,
        val url: String,
        val progress: Int = 0,
        val status: Status = Status.PENDING,
        val resultUri: Uri? = null,
        val error: String? = null,
        /** Set when a registry download was rejected (URL allowlist, size or SHA-256 mismatch). */
        val verificationFailure: DownloadVerificationException.Reason? = null,
        /** Size + SHA-256 a registry download is verified against; null for plain downloads. */
        val expected: ExpectedFile? = null,
    )

    private val idCounter = AtomicInteger(0)
    private val _downloads = MutableStateFlow<Map<Int, DownloadState>>(emptyMap())
    val downloads: StateFlow<Map<Int, DownloadState>> = _downloads.asStateFlow()

    private val completionCallbacks = ConcurrentHashMap<Int, (Uri) -> Unit>()
    private val mainHandler = Handler(Looper.getMainLooper())

    fun enqueue(
        context: Context,
        url: String,
        fileName: String,
        onCompleted: ((Uri) -> Unit)? = null,
        expected: ExpectedFile? = null,
    ): Int {
        // Only share an in-flight download that is verified exactly like this request.
        val existing = _downloads.value.values.find {
            (it.status == Status.PENDING || it.status == Status.DOWNLOADING) &&
                canShareDownload(url, expected, it.url, it.expected)
        }
        if (existing != null) {
            if (onCompleted != null) {
                completionCallbacks.merge(existing.id, onCompleted) { a, b -> { uri -> a(uri); b(uri) } }
                // It may have finished in between; markCompleted / markFailed already drained the
                // callbacks then, so run (completed) or drop (failed) what was merged afterwards.
                val now = _downloads.value[existing.id]
                if (now?.status == Status.COMPLETED && now.resultUri != null) {
                    completionCallbacks.remove(existing.id)?.let { cb -> mainHandler.post { cb(now.resultUri) } }
                } else if (now == null || now.status == Status.FAILED) {
                    completionCallbacks.remove(existing.id)
                }
            }
            return existing.id
        }

        val id = idCounter.incrementAndGet()
        val state = DownloadState(id = id, fileName = fileName, url = url, expected = expected)
        _downloads.update { it + (id to state) }

        if (expected != null && !RegistryUrls.isAllowedReleaseDownloadUrl(url)) {
            markFailed(id, "Download URL not allowed", DownloadVerificationException.Reason.URL_NOT_ALLOWED)
            return id
        }

        if (onCompleted != null) {
            completionCallbacks[id] = onCompleted
        }

        val intent = Intent(context, DownloadService::class.java).apply {
            action = DownloadService.ACTION_DOWNLOAD
            putExtra(DownloadService.EXTRA_DOWNLOAD_ID, id)
            putExtra(DownloadService.EXTRA_URL, url)
            putExtra(DownloadService.EXTRA_FILE_NAME, fileName)
            if (expected != null) {
                putExtra(DownloadService.EXTRA_EXPECTED_SIZE, expected.size)
                putExtra(DownloadService.EXTRA_EXPECTED_SHA256, expected.sha256)
            }
        }
        ContextCompat.startForegroundService(context, intent)

        return id
    }

    internal fun updateProgress(id: Int, progress: Int) {
        _downloads.update { map ->
            val state = map[id] ?: return@update map
            map + (id to state.copy(progress = progress, status = Status.DOWNLOADING))
        }
    }

    internal fun markCompleted(id: Int, uri: Uri) {
        _downloads.update { map ->
            val state = map[id] ?: return@update map
            map + (id to state.copy(status = Status.COMPLETED, progress = 100, resultUri = uri))
        }

        val callback = completionCallbacks.remove(id)
        if (callback != null) {
            mainHandler.post { callback(uri) }
        }
    }

    internal fun markFailed(
        id: Int,
        error: String,
        verificationFailure: DownloadVerificationException.Reason? = null,
    ) {
        _downloads.update { map ->
            val state = map[id] ?: return@update map
            map + (id to state.copy(status = Status.FAILED, error = error, verificationFailure = verificationFailure))
        }
        completionCallbacks.remove(id)
    }
}

private const val EXTERNAL_STORAGE_AUTHORITY = "com.android.externalstorage.documents"
private const val DOWNLOADS_AUTHORITY = "com.android.providers.downloads.documents"
private const val MEDIA_DOCUMENTS_AUTHORITY = "com.android.providers.media.documents"

private val DATA_COLUMN = Regex("""_data=(.*?)(?:, [A-Za-z_]+=|$)""")

// Only shareable storage is a valid delete target for picked documents; anything else means the
// URI was crafted or the provider reported a path we must not touch as root.
private val EXTERNAL_ROOTS = listOf("/storage/", "/mnt/media_rw/", "/data/media/")

/**
 * Best-effort deletion of the ZIP a module was installed from: an app-private registry download,
 * a document the user picked for installing, or a download created by the manager.
 *
 * The manager has no all-files access, so the path is resolved for the root shell and removed
 * with `rm`; Android file/provider APIs cannot delete files the app does not own.
 */
fun deleteInstalledModuleZip(uri: Uri): Boolean = runCatching {
    val path = when (uri.scheme) {
        ContentResolver.SCHEME_FILE -> uri.path
        ContentResolver.SCHEME_CONTENT ->
            if (DocumentsContract.isDocumentUri(ksuApp, uri)) resolveDocumentPath(uri) else queryDataPath(uri)
        else -> null
    } ?: return false
    if (!isSafeToDelete(uri, path)) {
        Log.w("DownloadManager", "Refusing to delete unexpected path for $uri")
        return false
    }
    // Job.add() runs every argument as a separate command line, so the whole command is one string.
    val cmd = "/system/bin/rm -f -- ${ShellUtils.escapedString(path)}"
    getRootShell().newJob().add(cmd).exec().isSuccess
}.onFailure {
    Log.w("DownloadManager", "Failed to delete module zip: $uri", it)
}.getOrDefault(false)

private fun isSafeToDelete(uri: Uri, path: String): Boolean = runCatching {
    if (!path.startsWith('/') || path.split('/').any { it == ".." }) return false
    if (uri.scheme == ContentResolver.SCHEME_FILE) {
        val file = File(path).canonicalFile
        file.startsWith(ksuApp.filesDir.canonicalFile) || file.startsWith(ksuApp.cacheDir.canonicalFile)
    } else {
        EXTERNAL_ROOTS.any { path.startsWith(it) }
    }
}.getOrDefault(false)

private fun resolveDocumentPath(uri: Uri): String? {
    val docId = runCatching { DocumentsContract.getDocumentId(uri) }.getOrNull() ?: return null
    return when (uri.authority) {
        EXTERNAL_STORAGE_AUTHORITY -> {
            val parts = docId.split(':', limit = 2)
            if (parts.size != 2) return null
            val volume = parts[0]
            val root = when {
                volume.equals("primary", ignoreCase = true) -> "/storage/emulated/0"
                volume.equals("home", ignoreCase = true) -> "/storage/emulated/0/Documents"
                else -> "/storage/$volume"
            }
            "$root/${parts[1]}"
        }

        DOWNLOADS_AUTHORITY ->
            if (docId.startsWith("raw:")) {
                docId.removePrefix("raw:")
            } else {
                queryDataPath(Uri.parse("content://media/external/downloads/${docId.removePrefix("msf:")}"))
            }

        MEDIA_DOCUMENTS_AUTHORITY -> {
            val parts = docId.split(':', limit = 2)
            if (parts.size != 2) return null
            val collection = when (parts[0]) {
                "image" -> "images"
                "audio" -> "audio"
                "video" -> "video"
                "downloads" -> "downloads"
                else -> return null
            }
            queryDataPath(Uri.parse("content://media/external/$collection/${parts[1]}"))
        }

        else -> null
    }
}

/** Reads the backing file path of a MediaStore row through the root shell. */
private fun queryDataPath(uri: Uri): String? {
    val cmd = "/system/bin/content query --uri ${ShellUtils.escapedString(uri.toString())} --projection _data"
    val out = getRootShell().newJob().add(cmd).to(ArrayList(), null).exec().out
    val line = out.firstOrNull { it.contains("_data=") } ?: return null
    return DATA_COLUMN.find(line)?.groupValues?.get(1)?.trim()
}
