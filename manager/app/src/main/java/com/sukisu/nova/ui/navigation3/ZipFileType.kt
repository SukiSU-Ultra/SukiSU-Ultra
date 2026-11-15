package com.sukisu.nova.ui.navigation3

import java.util.zip.ZipInputStream

enum class ZipType {
    MODULE,
    ANYKERNEL3,
    UNKNOWN,
}

internal fun detectFromZipStream(zipStream: ZipInputStream): ZipType {
    var hasAnyKernelScript = false
    var hasUpdateBinary = false
    var hasModuleEntry = false
    var entry = zipStream.nextEntry
    while (entry != null) {
        // AnyKernel3 must be installable from the ZIP root, not a nested source archive.
        val name = entry.name
        if (!entry.isDirectory) {
            hasAnyKernelScript = hasAnyKernelScript || name == "anykernel.sh"
            hasUpdateBinary = hasUpdateBinary || name == "META-INF/com/google/android/update-binary"
            val lowerName = name.lowercase()
            hasModuleEntry = hasModuleEntry || lowerName == "module.prop" ||
                lowerName.endsWith("/module.prop") || lowerName == "install.sh" ||
                lowerName.endsWith("/install.sh") || lowerName == "action.sh" ||
                lowerName.endsWith("/action.sh") || lowerName.endsWith(".patch") ||
                lowerName == "sepolicy.rule" || lowerName.endsWith("/sepolicy.rule")
        }
        zipStream.closeEntry()
        entry = zipStream.nextEntry
    }
    // Inspect the whole archive: a kernel may contain patches or install scripts too.
    return when {
        hasAnyKernelScript && hasUpdateBinary -> ZipType.ANYKERNEL3
        hasModuleEntry -> ZipType.MODULE
        else -> ZipType.UNKNOWN
    }
}
