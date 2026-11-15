package com.sukisu.nova.ui.kernelFlash.component

import androidx.compose.ui.graphics.vector.ImageVector
import com.sukisu.nova.ui.util.getRootShell
import com.topjohnwu.superuser.ShellUtils

// Data class for slot options
class SlotOption(
    val slot: String,
    val titleText: String,
    val icon: ImageVector
)

// Utility function to get current slot
fun getCurrentSlot(): String? {
    return try {
        val shell = getRootShell()
        val result = ShellUtils.fastCmd(shell, "getprop ro.boot.slot_suffix").trim()
        if (result.startsWith("_")) {
            result.substring(1)
        } else {
            result
        }.takeIf { it.isNotEmpty() }
    } catch (_: Exception) {
        null
    }
}