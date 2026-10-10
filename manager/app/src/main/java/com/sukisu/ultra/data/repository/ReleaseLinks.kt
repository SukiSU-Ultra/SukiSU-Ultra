package com.sukisu.ultra.data.repository

/**
 * Where a module can be looked up on the web, for indexes that publish no page of their own: a
 * KernelSU-array index carries nothing but the newest download address.
 *
 * Both are derived from that address rather than built from a fixed host, so they cannot point at
 * a service that has since gone away. [repositoryUrl] answers for any GitHub download address,
 * including a zip kept in the repository itself; [releasePageUrl] only for a release asset, since
 * nothing else has a release page.
 */
internal fun releasePageUrl(downloadUrl: String): String? {
    val repository = githubRepositoryIn(downloadUrl) ?: return null
    val tag = releaseTagIn(downloadUrl) ?: return null
    return "$repository/releases/tag/$tag"
}

internal fun repositoryUrl(downloadUrl: String): String? = githubRepositoryIn(downloadUrl)

/** `https://github.com/owner/repo/...` to `https://github.com/owner/repo`, or null for anything else. */
private fun githubRepositoryIn(url: String): String? {
    val uri = runCatching { java.net.URI(url) }.getOrNull() ?: return null
    if (uri.host?.lowercase() != "github.com") return null

    val segments = uri.rawPath.orEmpty().trim('/').split('/').filter { it.isNotEmpty() }
    if (segments.size < 2) return null
    val owner = segments[0]
    val repo = segments[1].removeSuffix(".git")
    if (owner.isEmpty() || repo.isEmpty()) return null
    return "https://github.com/$owner/$repo"
}

/**
 * The tag of a GitHub release asset address — `owner/repo/releases/download/<tag>/<file>` — or
 * null when the address is not one. The raw path is used so that an encoded tag survives into the
 * page address unchanged.
 */
private fun releaseTagIn(url: String): String? {
    val uri = runCatching { java.net.URI(url) }.getOrNull() ?: return null

    // A real asset address is owner/repo/releases/download/<tag>/<file>, so the file name is
    // required as well as the tag.
    val segments = uri.rawPath.orEmpty().trim('/').split('/').filter { it.isNotEmpty() }
    if (segments.size < 6 || segments[2] != "releases" || segments[3] != "download") return null
    return segments[4].ifEmpty { null }
}
