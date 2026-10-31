package com.sukisu.ultra.ai

import android.content.Context
import com.sukisu.ultra.ai.api.AiHost

/**
 * Process-wide entry point. Call [install] once from `Application.onCreate`
 * before any assistant composable or tool is used.
 */
object AiAssistant {

    @Volatile
    private var installedHost: AiHost? = null

    fun install(host: AiHost) {
        installedHost = host
    }

    fun isInstalled(): Boolean = installedHost != null

    fun requireHost(): AiHost = installedHost ?: error(
        "AiAssistant is not installed. Call AiAssistant.install(host) from Application.onCreate."
    )
}

internal val aiContext: Context
    get() = AiAssistant.requireHost().context
