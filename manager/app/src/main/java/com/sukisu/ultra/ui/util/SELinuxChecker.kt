package com.sukisu.ultra.ui.util

import android.content.Context
import com.sukisu.ultra.R
import com.topjohnwu.superuser.io.SuFile

fun getSELinuxStatus(context: Context) = SuFile("/sys/fs/selinux/enforce").run {
    when {
        !exists() -> context.getString(R.string.selinux_status_disabled)
        !isFile -> context.getString(R.string.selinux_status_unknown)
        !canRead() -> context.getString(R.string.selinux_status_enforcing)
        else -> when (runCatching { newInputStream() }.getOrNull()?.bufferedReader()
            ?.use { it.runCatching { readLine() }.getOrNull()?.trim()?.toIntOrNull() }) {
            1 -> context.getString(R.string.selinux_status_enforcing)
            0 -> context.getString(R.string.selinux_status_permissive)
            else -> context.getString(R.string.selinux_status_unknown)
        }
    }
}