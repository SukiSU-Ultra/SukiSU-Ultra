package com.sukisu.ultra.ui.navigation3

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.util.Log
import android.widget.Toast
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.dialog.ConfirmResult
import com.sukisu.ultra.ui.component.dialog.rememberConfirmDialog
import com.sukisu.ultra.ui.kernelFlash.rememberExternalKernelFlasher
import com.sukisu.ultra.ui.screen.flash.FlashIt
import com.sukisu.ultra.ui.screen.scriptrun.ScriptRunArg
import com.sukisu.ultra.ui.util.getFileName
import com.sukisu.ultra.data.script.ScriptRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.zip.ZipInputStream

private const val TAG = "ZipFileIntentHandler"
private val ZIP_MIME_TYPES = setOf(
    "application/zip",
    "application/x-zip",
    "application/x-zip-compressed",
    "application/octet-stream",
    "application/x-android-package-archive",
)
private const val APK_MIME_TYPE = "application/vnd.android.package-archive"

@Composable
fun rememberZipFileIntentHandler(): suspend (Intent) -> Unit {
    val context = LocalContext.current
    val navigator = LocalNavigator.current
    val confirmDialog = rememberConfirmDialog()
    val flashKernel = rememberExternalKernelFlasher()
    val strings = Strings(
        safeMode = stringResource(R.string.safe_mode_module_disabled),
        zipTypeModule = stringResource(R.string.zip_type_module),
        zipFileUnknown = stringResource(R.string.zip_file_unknown),
        moduleInstallPrompt = stringResource(R.string.module_install_prompt_with_name),
        module = stringResource(R.string.module),
        kernel = stringResource(R.string.horizon_kernel),
        kernelInstallPrompt = stringResource(R.string.external_kernel_flash_prompt),
        separateKernel = stringResource(R.string.external_kernel_separate_files),
    )

    return remember(context, navigator, confirmDialog, strings, flashKernel) {
        val handler: suspend (Intent) -> Unit = { intent ->
            val zipUris = extractZipUris(context, intent)
            if (zipUris.isNotEmpty()) {
                val zipTypes = withContext(Dispatchers.IO) {
                    zipUris.map { uri -> detectZipType(context, uri) }
                }
                if (ZipType.ANYKERNEL3 in zipTypes) {
                    if (zipUris.size != 1) {
                        Toast.makeText(context, strings.separateKernel, Toast.LENGTH_LONG).show()
                    } else if (confirmDialog.awaitConfirm(
                            title = strings.kernel,
                            content = strings.kernelInstallPrompt.format(
                                zipUris.single().getFileName(context) ?: strings.zipFileUnknown
                            ),
                        ) == ConfirmResult.Confirmed
                    ) {
                        val cachedUri = withContext(Dispatchers.IO) {
                            copyUriToCache(context, zipUris.single())
                        }
                        if (cachedUri != null) {
                            flashKernel(cachedUri)
                        } else {
                            Toast.makeText(context, strings.zipFileUnknown, Toast.LENGTH_SHORT).show()
                        }
                    }
                } else {
                    val fileNames = buildFileNames(zipUris, zipTypes, context, strings)
                    val confirmContent = strings.moduleInstallPrompt.format(fileNames)

                    if (confirmDialog.awaitConfirm(
                            title = strings.module,
                            content = confirmContent,
                        ) == ConfirmResult.Confirmed
                    ) {
                        handleConfirmed(zipUris, context, navigator, strings)
                    }
                }
            }
        }
        handler
    }
}

fun hasZipFileIntent(context: Context, intent: Intent): Boolean =
    extractZipUris(context, intent).isNotEmpty()

private data class Strings(
    val safeMode: String,
    val zipTypeModule: String,
    val zipFileUnknown: String,
    val moduleInstallPrompt: String,
    val module: String,
    val kernel: String,
    val kernelInstallPrompt: String,
    val separateKernel: String,
)

private fun extractZipUris(context: Context, intent: Intent): List<Uri> {
    val uris = linkedSetOf<Uri>()

    fun addIfZip(uri: Uri?) {
        if (uri != null && isZipFile(context, intent, uri)) uris.add(uri)
    }

    when (intent.action) {
        Intent.ACTION_VIEW, Intent.ACTION_SEND -> {
            addIfZip(intent.data)
            addIfZip(intent.getStreamUri())
        }

        Intent.ACTION_SEND_MULTIPLE -> {
            intent.getStreamUris()?.forEach(::addIfZip)
        }
    }

    for (index in 0 until (intent.clipData?.itemCount ?: 0)) {
        addIfZip(intent.clipData?.getItemAt(index)?.uri)
    }

    return uris.toList()
}

private fun Intent.getStreamUri(): Uri? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
    getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
} else {
    @Suppress("DEPRECATION")
    getParcelableExtra(Intent.EXTRA_STREAM)
}

private fun Intent.getStreamUris(): List<Uri>? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
    getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
} else {
    @Suppress("DEPRECATION")
    getParcelableArrayListExtra(Intent.EXTRA_STREAM)
}

private fun isZipFile(context: Context, intent: Intent, uri: Uri): Boolean {
    val fileName = uri.getFileName(context) ?: uri.lastPathSegment.orEmpty()
    val cleanName = fileName.substringBefore('?')
    if (cleanName.endsWith(".sukisu", ignoreCase = true)) return false

    val mimeType = (intent.type ?: context.contentResolver.getType(uri))
        ?.substringBefore(';')
        ?.trim()
        ?.lowercase()
    if (mimeType == com.sukisu.ultra.ui.util.ThemePackageStorage.THEME_MIME_TYPE) return false
    if (mimeType in ZIP_MIME_TYPES || mimeType == APK_MIME_TYPE) return true

    return cleanName.endsWith(".zip", ignoreCase = true) || cleanName.endsWith(".apk", ignoreCase = true)
}

private fun buildFileNames(
    uris: List<Uri>,
    types: List<ZipType>,
    context: Context,
    strings: Strings,
): String = uris.mapIndexed { index, uri ->
    val fileName = uri.getFileName(context) ?: strings.zipFileUnknown
    val typeStr = when (types[index]) {
        ZipType.ANYKERNEL3 -> strings.kernel
        ZipType.MODULE -> strings.zipTypeModule
        ZipType.UNKNOWN -> strings.zipFileUnknown
    }
    "\n${index + 1}. $fileName$typeStr"
}.joinToString("")

private suspend fun handleConfirmed(
    moduleUris: List<Uri>,
    context: Context,
    navigator: Navigator,
    strings: Strings,
) {
    if (moduleUris.isEmpty()) return

    if (Natives.isSafeMode) {
        Toast.makeText(context, strings.safeMode, Toast.LENGTH_SHORT).show()
        return
    }

    val cachedUris = withContext(Dispatchers.IO) {
        moduleUris.mapNotNull { copyUriToCache(context, it) }
    }

    if (cachedUris.size == 1) {
        val script = ScriptRepository.peekOneshot(cachedUris.single())
        if (script != null) {
            navigator.push(
                Route.ScriptRun(
                    ScriptRunArg(cachedUris.single(), offerInstall = true, displayName = script.name)
                )
            )
            return
        }
    }

    if (cachedUris.isNotEmpty()) {
        navigator.push(Route.Flash(FlashIt.FlashModules(cachedUris)))
    } else {
        Toast.makeText(context, strings.zipFileUnknown, Toast.LENGTH_SHORT).show()
    }
}

private fun copyUriToCache(context: Context, uri: Uri): Uri? {
    return try {
        val originalName = uri.getFileName(context) ?: "module.zip"
        val safeName = File(originalName).name
        val suffix = if (safeName.endsWith(".apk", ignoreCase = true)) ".apk" else ".zip"
        val destFile = File.createTempFile("external_zip_", suffix, context.cacheDir)

        context.contentResolver.openInputStream(uri)?.use { input ->
            destFile.outputStream().use { output -> input.copyTo(output) }
        } ?: return null

        Uri.fromFile(destFile)
    } catch (exception: Exception) {
        Log.w(TAG, "Unable to cache ZIP file: $uri", exception)
        null
    }
}

private fun detectZipType(context: Context, uri: Uri): ZipType {
    val isApk = (uri.getFileName(context) ?: uri.toString()).endsWith(".apk", ignoreCase = true)

    if (isApk) return ZipType.MODULE

    return try {
        context.contentResolver.openInputStream(uri)?.use { inputStream ->
            ZipInputStream(inputStream).use(::detectFromZipStream)
        } ?: defaultType(isApk)
    } catch (exception: Exception) {
        Log.w(TAG, "Unable to inspect ZIP file: $uri", exception)
        defaultType(isApk)
    }
}

private fun defaultType(isApk: Boolean) = if (isApk) ZipType.MODULE else ZipType.UNKNOWN
