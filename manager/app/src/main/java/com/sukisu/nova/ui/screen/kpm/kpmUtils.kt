package com.sukisu.nova.ui.screen.kpm

import android.util.Log
import com.sukisu.nova.ui.screen.susfs.util.SuSFSConfig
import com.sukisu.nova.ui.util.getRootShell
import com.topjohnwu.superuser.Shell
import java.io.File

fun isSafeKpmModuleId(name: String): Boolean = name.isNotBlank() &&
    name != "." && name != ".." && name.none { it == '/' || it == '\\' || it.isISOControl() }

fun extractModuleName(file: File): String? = extractModuleName(file) { getRootShell().newJob() }

internal fun extractModuleName(file: File, newJob: () -> Shell.Job): String? = try {
    val result = newJob()
        .add("strings ${SuSFSConfig.shellQuote(file.absolutePath)}")
        // libsu discards stdout unless an output destination is explicitly supplied.
        .to(ArrayList(), ArrayList())
        .exec()
    if (result.isSuccess) result.out.firstOrNull { it.startsWith("name=") }
        ?.substringAfter("name=")?.trim()?.takeIf(::isSafeKpmModuleId) else null
} catch (e: Exception) {
    Log.e("Kpm", "Failed to extract module name", e)
    null
}

// MIME types are provider supplied; validate the file itself before invoking the loader.
fun isValidKpmFile(file: File): Boolean = isElfFile(file)

fun isElfFile(file: File): Boolean = try {
    file.inputStream().use { input ->
        val bytes = ByteArray(4)
        input.read(bytes) == bytes.size && bytes.contentEquals(byteArrayOf(0x7f, 0x45, 0x4c, 0x46))
    }
} catch (e: Exception) {
    Log.e("Kpm", "Failed to check ELF file", e)
    false
}
