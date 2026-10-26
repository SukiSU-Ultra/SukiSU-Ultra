package com.sukisu.ultra.ui.util

import android.content.ContentResolver
import android.net.Uri
import android.provider.DocumentsContract
import android.util.Log
import com.sukisu.ultra.data.registry.RegistryDownloadStore
import com.sukisu.ultra.ksuApp
import java.io.File

/** Deletion only happens when the user opted in and ksud reported a successful install. */
internal fun shouldDeleteSourceAfterInstall(enabled: Boolean, installSucceeded: Boolean): Boolean =
    enabled && installSucceeded

/**
 * Best-effort deletion of the ZIP a module was installed from.
 *
 * app-private files are removed directly, and content URIs are deleted by the provider that owns the
 * document (SAF write grant for picked documents, ownership for manager-created MediaStore rows).
 * A provider that refuses deletion leaves the ZIP untouched.
 */
fun deleteInstalledModuleZip(uri: Uri): Boolean {
    val deleted = deleteModuleZip(
        scheme = uri.scheme,
        filePath = uri.path,
        filesDir = ksuApp.filesDir,
        cacheDir = ksuApp.cacheDir,
        isDocument = { DocumentsContract.isDocumentUri(ksuApp, uri) },
        deleteDocument = { DocumentsContract.deleteDocument(ksuApp.contentResolver, uri) },
        deleteRow = { ksuApp.contentResolver.delete(uri, null, null) },
    )
    if (!deleted) Log.w("ModuleZipDeletion", "Module zip was not deleted: $uri")
    return deleted
}

internal fun deleteModuleZip(
    scheme: String?,
    filePath: String?,
    filesDir: File,
    cacheDir: File,
    isDocument: () -> Boolean,
    deleteDocument: () -> Boolean,
    deleteRow: () -> Int,
): Boolean = when (scheme) {
    ContentResolver.SCHEME_FILE -> deletePrivateZip(filePath, filesDir, cacheDir)
    ContentResolver.SCHEME_CONTENT -> runCatching {
        if (isDocument()) deleteDocument() else deleteRow() > 0
    }.getOrDefault(false)
    else -> false
}

/** Only app-private ZIPs are deleted directly; canonical paths keep symlinks from escaping. */
internal fun deletePrivateZip(path: String?, filesDir: File, cacheDir: File): Boolean {
    val file = path?.let(::File)?.let { runCatching { it.canonicalFile }.getOrNull() } ?: return false
    val registryRoot = runCatching { File(filesDir, RegistryDownloadStore.DIR_NAME).canonicalFile }.getOrNull()
    val cacheRoot = runCatching { cacheDir.canonicalFile }.getOrNull()
    return when {
        registryRoot != null && file.toPath().startsWith(registryRoot.toPath()) ->
            runCatching { RegistryDownloadStore.delete(registryRoot, file) || file.delete() }.getOrDefault(false)
        cacheRoot != null && file.toPath().startsWith(cacheRoot.toPath()) ->
            runCatching { file.delete() }.getOrDefault(false)
        else -> false
    }
}
