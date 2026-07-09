package com.sukisu.ultra.ui.screen.umountmanager

import android.content.Context
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R

val SPACING_SMALL = 3.dp
val SPACING_MEDIUM = 8.dp
val SPACING_LARGE = 16.dp

data class UmountPathEntry(
    val path: String,
    val flags: Int
)

// Exclusion entry: stores a path prefix to skip during umount
data class UmountExclusionEntry(
    val pathPrefix: String  // Path prefix to match (e.g., "/data/adb/modules/my_module/")
)

fun parseUmountPaths(output: String): List<UmountPathEntry> {
    val lines = output.lines().filter { it.isNotBlank() }
    if (lines.size < 2) return emptyList()

    return lines.drop(2).mapNotNull { line ->
        val parts = line.trim().split(Regex("\\s+"))
        if (parts.size >= 2) {
            UmountPathEntry(
                path = parts[0],
                flags = parts[1].toIntOrNull() ?: 0
            )
        } else null
    }
}

fun parseUmountExclusions(output: String): List<UmountExclusionEntry> {
    val lines = output.lines().filter { it.isNotBlank() }
    return lines.mapNotNull { line ->
        val trimmed = line.trim()
        if (trimmed.isEmpty()) null
        else UmountExclusionEntry(pathPrefix = trimmed)
    }
}

fun Int.toUmountFlagName(context: Context): String {
    return when (this) {
        2 -> context.getString(R.string.mnt_detach)
        else -> this.toString()
    }
}