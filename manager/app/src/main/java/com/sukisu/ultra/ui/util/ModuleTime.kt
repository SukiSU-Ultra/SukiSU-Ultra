package com.sukisu.ultra.ui.util

import android.text.format.DateUtils
import java.time.Instant

/**
 * Epoch millis for an ISO-8601 timestamp from a repository index, or 0 when it is missing or
 * unparseable. [Instant] accepts the offsets and fractional seconds both index formats use, but a
 * hand-written index may carry something else — that must not break the module list.
 */
fun isoToEpochMillis(iso: String): Long {
    if (iso.isBlank()) return 0L
    return runCatching { Instant.parse(iso).toEpochMilli() }.getOrDefault(0L)
}

/**
 * Localized, compact rendering of a repository timestamp: "3 days ago" / "Yesterday" / "3 天前"
 * within the last week, the plain date beyond it. DateUtils already drops the year for the current
 * one, and picks the plural and the wording from the locale. A value we cannot parse is passed
 * through unchanged, so an unexpected format still shows something rather than an epoch date.
 */
fun formatRepoTime(iso: String): String {
    val millis = isoToEpochMillis(iso)
    if (millis <= 0L) return iso
    return DateUtils.getRelativeTimeSpanString(
        millis,
        System.currentTimeMillis(),
        0L,
        DateUtils.FORMAT_SHOW_DATE or DateUtils.FORMAT_ABBREV_RELATIVE or DateUtils.FORMAT_ABBREV_ALL,
    ).toString()
}
