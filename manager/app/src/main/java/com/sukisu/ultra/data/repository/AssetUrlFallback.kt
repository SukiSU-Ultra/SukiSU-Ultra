package com.sukisu.ultra.data.repository

import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/**
 * An MMRL index declares every module zip as an absolute URL, so a repository that moves
 * its assets (a renamed GitHub account, a new domain) can keep serving an index whose
 * download URLs point at the host it used to live on: those 404 while the very same path
 * still resolves on the host serving the index.
 *
 * Returns the same path on the index's own host, or null when there is nothing to fall
 * back to — the declared URL is already on that host, or it does not sit inside the
 * repository's directory, which means it was deliberately hosted elsewhere (a release
 * CDN, for instance) and is not ours to rewrite.
 */
fun sameOriginAssetFallback(declaredUrl: String, indexUrl: String): String? {
    val declared = declaredUrl.trim().toHttpUrlOrNull() ?: return null
    val index = indexUrl.trim().toHttpUrlOrNull() ?: return null
    if (index.host == declared.host) return null

    // The index lives at <repo>/json/modules.json, or at <repo>/modules.json when the
    // repository does not use the json/ directory.
    val indexDir = index.encodedPath.substringBeforeLast('/', "")
    val repoDir = indexDir.removeSuffix("/json").trimEnd('/')
    if (repoDir.isNotEmpty() && !declared.encodedPath.startsWith("$repoDir/")) return null

    val defaultPort = if (index.scheme == "https") 443 else 80
    val port = if (index.port == defaultPort) "" else ":${index.port}"
    val query = declared.encodedQuery?.let { "?$it" }.orEmpty()
    return "${index.scheme}://${index.host}$port${declared.encodedPath}$query"
}
