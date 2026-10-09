package com.sukisu.ultra.ui.screen.settings.tools

import android.content.Context
import android.net.Uri
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

fun isSelinuxPermissive(): Boolean {
    val result = Shell.cmd("getenforce").exec()
    val output = result.out.joinToString("\n").trim().lowercase()
    return output == "permissive"
}

fun setSelinuxPermissive(permissive: Boolean): Boolean {
    val target = if (permissive) "0" else "1"
    val result = Shell.cmd("setenforce $target").exec()
    return result.isSuccess
}

suspend fun backupAllowlistToUri(context: Context, targetUri: Uri): Boolean = withContext(Dispatchers.IO) {
    val tempFile = File(context.cacheDir, "allowlist_backup_tmp.bin")
    try {
        if (!copyAllowlistToFile(tempFile)) return@withContext false
        return@withContext runCatching {
            context.contentResolver.openOutputStream(targetUri, "w")?.use { output ->
                tempFile.inputStream().use { input ->
                    input.copyTo(output)
                }
                true
            } ?: false
        }.getOrElse { false }
    } finally {
        tempFile.delete()
    }
}

suspend fun restoreAllowlistFromUri(context: Context, sourceUri: Uri): Boolean = withContext(Dispatchers.IO) {
    val tempFile = File(context.cacheDir, "allowlist_restore_tmp.bin")
    try {
        val downloaded = runCatching {
            context.contentResolver.openInputStream(sourceUri)?.use { input ->
                tempFile.outputStream().use { output ->
                    input.copyTo(output)
                }
                true
            } ?: false
        }.getOrElse { false }
        if (!downloaded) return@withContext false
        return@withContext copyFileToAllowlist(tempFile)
    } finally {
        tempFile.delete()
    }
}

private suspend fun copyAllowlistToFile(targetFile: File): Boolean = withContext(Dispatchers.IO) {
    runCatching {
        targetFile.parentFile?.mkdirs()
        val result = Shell.cmd(
            "cp /data/adb/ksu/.allowlist \"${targetFile.absolutePath}\"",
            "chmod 0644 \"${targetFile.absolutePath}\""
        ).exec()
        result.isSuccess
    }.getOrDefault(false)
}

private suspend fun copyFileToAllowlist(sourceFile: File): Boolean = withContext(Dispatchers.IO) {
    if (!sourceFile.exists()) return@withContext false
    runCatching {
        val result = Shell.cmd(
            "cp \"${sourceFile.absolutePath}\" /data/adb/ksu/.allowlist",
            "chmod 0644 /data/adb/ksu/.allowlist"
        ).exec()
        result.isSuccess
    }.getOrDefault(false)
}

data class CpuInfo(
    val midrHex: String,
    val bogomips: Int,
    val coreCount: Int,
    val hwcap: String,
    val hwcap2: String
)

suspend fun readCurrentCpuIdentity(): CpuInfo? = withContext(Dispatchers.IO) {
    runCatching {
        val cpuInfoResult = Shell.cmd("cat /proc/cpuinfo").exec()
        if (!cpuInfoResult.isSuccess) return@runCatching null

        val lines = cpuInfoResult.out
        var implementer = ""
        var variant = ""
        var part = ""
        var revision = ""
        var bogomips = 0

        for (line in lines) {
            val trimmed = line.trim()
            when {
                trimmed.startsWith("CPU implementer") -> {
                    implementer = trimmed.substringAfter(":").trim()
                }
                trimmed.startsWith("CPU variant") -> {
                    variant = trimmed.substringAfter(":").trim()
                }
                trimmed.startsWith("CPU part") -> {
                    part = trimmed.substringAfter(":").trim()
                }
                trimmed.startsWith("CPU revision") -> {
                    revision = trimmed.substringAfter(":").trim()
                }
                trimmed.startsWith("BogoMIPS") -> {
                    val bogoStr = trimmed.substringAfter(":").trim()
                    bogomips = bogoStr.toFloatOrNull()?.toInt() ?: 0
                }
            }
            if (implementer.isNotEmpty() && part.isNotEmpty() && variant.isNotEmpty() && revision.isNotEmpty()) {
                break
            }
        }

        if (implementer.isEmpty() || part.isEmpty()) {
            return@runCatching null
        }

        val midr = buildString {
            append(implementer.removePrefix("0x"))
            append(variant.removePrefix("0x").padStart(1, '0'))
            append("0")
            append(part.removePrefix("0x").padStart(3, '0'))
            append(revision.removePrefix("0x").padStart(1, '0'))
        }
        val midrHex = "0x$midr"

        val coreCount = Runtime.getRuntime().availableProcessors()

        val hwcapResult = Shell.cmd("getprop ro.hwcap").exec()
        val hwcap = if (hwcapResult.isSuccess && hwcapResult.out.isNotEmpty()) {
            hwcapResult.out.first().trim()
        } else {
            "0x0"
        }

        val hwcap2Result = Shell.cmd("getprop ro.hwcap2").exec()
        val hwcap2 = if (hwcap2Result.isSuccess && hwcap2Result.out.isNotEmpty()) {
            hwcap2Result.out.first().trim()
        } else {
            "0x0"
        }

        CpuInfo(
            midrHex = midrHex,
            bogomips = bogomips,
            coreCount = coreCount,
            hwcap = hwcap,
            hwcap2 = hwcap2
        )
    }.getOrNull()
}