package com.sukisu.ultra.ui.util

import android.content.Context
import com.topjohnwu.superuser.Shell
import com.sukisu.ultra.R

fun getSELinuxStatus(context: Context): String {
    val shell = Shell.Builder.create().build("sh")
    val list = ArrayList<String>()

    val result = shell.use {
        it.newJob().add("getenforce").to(list, list).exec()
    }

    val output = list.joinToString("\n").trim()

    return if (result.isSuccess) {
        when (output) {
            "Enforcing" -> context.getString(R.string.selinux_status_enforcing)
            "Permissive" -> context.getString(R.string.selinux_status_permissive)
            "Disabled" -> context.getString(R.string.selinux_status_disabled)
            else -> context.getString(R.string.selinux_status_unknown)
        }
    } else {
        if (output.contains("Permission denied")) {
            context.getString(R.string.selinux_status_enforcing)
        } else {
            context.getString(R.string.selinux_status_unknown)
        }
    }
}