package com.sukisu.ultra.ui.util.module

fun sanitizeVersionString(version: String): String {
    return version.replace(Regex("[^a-zA-Z0-9.\\-_]"), "_")
}
