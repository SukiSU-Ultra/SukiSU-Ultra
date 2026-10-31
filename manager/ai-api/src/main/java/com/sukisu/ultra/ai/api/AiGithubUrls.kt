package com.sukisu.ultra.ai.api

import java.net.URI
import java.net.URLDecoder

/** Shared validation for GitHub release download URLs accepted by module installs. */
object AiGithubUrls {

    private val REPO_PART = Regex("^[A-Za-z0-9._-]+$")

    fun isReleaseDownloadUrl(url: String): Boolean {
        val uri = runCatching { URI(url) }.getOrNull() ?: return false
        if (!uri.isAbsolute || uri.isOpaque) return false
        if (!uri.scheme.equals("https", ignoreCase = true)) return false
        if (!uri.host.equals("github.com", ignoreCase = true)) return false
        if (uri.port != -1 && uri.port != 443) return false
        if (uri.rawUserInfo != null || uri.rawQuery != null || uri.rawFragment != null) return false
        val rawPath = uri.rawPath ?: return false
        if (!rawPath.startsWith("/")) return false
        val segments = rawPath.substring(1).split('/')
        if (segments.size < 6) return false
        for (raw in segments) {
            val decoded = runCatching { URLDecoder.decode(raw, "UTF-8") }.getOrNull() ?: return false
            if (decoded.isEmpty() || decoded == "." || decoded == ".." ||
                decoded.contains('/') || decoded.contains('\\')
            ) return false
        }
        val owner = segments[0]
        val repo = segments[1]
        if (!REPO_PART.matches(owner) || !REPO_PART.matches(repo)) return false
        if (segments[2] != "releases" || segments[3] != "download") return false
        return true
    }
}
