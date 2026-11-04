package com.sukisu.ultra.ui.screen.themestore

import java.util.Locale

/** Compact byte count for transfer rows, e.g. `12.4 MB`. */
internal fun formatTransferBytes(bytes: Long): String {
    val safe = bytes.coerceAtLeast(0L)
    if (safe < 1024L) return "$safe B"
    val units = arrayOf("KB", "MB", "GB", "TB")
    var value = safe.toDouble()
    var unit = -1
    while (value >= 1024.0 && unit < units.lastIndex) {
        value /= 1024.0
        unit++
    }
    return if (value >= 100.0) {
        String.format(Locale.ROOT, "%.0f %s", value, units[unit])
    } else {
        String.format(Locale.ROOT, "%.1f %s", value, units[unit])
    }
}

/** `0:42` for short transfers, `12:05` for minutes, `1:02:03` when it runs long. */
internal fun formatTransferEta(seconds: Long): String {
    val total = seconds.coerceAtLeast(0L)
    val hours = total / 3600L
    val minutes = (total % 3600L) / 60L
    val secs = total % 60L
    return if (hours > 0L) {
        String.format(Locale.ROOT, "%d:%02d:%02d", hours, minutes, secs)
    } else {
        String.format(Locale.ROOT, "%d:%02d", minutes, secs)
    }
}
