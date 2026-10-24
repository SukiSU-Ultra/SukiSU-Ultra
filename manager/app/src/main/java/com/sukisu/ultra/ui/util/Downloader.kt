package com.sukisu.ultra.ui.util

import android.net.Uri
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.withContext
import com.sukisu.ultra.data.registry.ExpectedFile
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.util.module.LatestVersionInfo
import okhttp3.Request

/**
 * @author weishu
 * @date 2023/6/22.
 */
suspend fun download(
    url: String,
    fileName: String,
    onDownloaded: (Uri) -> Unit = {},
    onDownloading: () -> Unit = {},
    onProgress: (Int) -> Unit = {},
    expected: ExpectedFile? = null,
    onFailed: (DownloadManager.DownloadState) -> Unit = {},
) {
    onDownloading()

    val downloadId = DownloadManager.enqueue(
        context = ksuApp,
        url = url,
        fileName = fileName,
        onCompleted = onDownloaded,
        expected = expected,
    )

    val finalState = DownloadManager.downloads
        .onEach { map -> map[downloadId]?.let { onProgress(it.progress) } }
        .first { map ->
            val status = map[downloadId]?.status
            status == DownloadManager.Status.COMPLETED ||
                status == DownloadManager.Status.FAILED
        }[downloadId]
    if (finalState?.status == DownloadManager.Status.FAILED) {
        withContext(Dispatchers.Main) { onFailed(finalState) }
    }
}

internal suspend fun isDownloadAvailable(uri: Uri): Boolean = withContext(Dispatchers.IO) {
    runCatching {
        ksuApp.contentResolver.openFileDescriptor(uri, "r").use { it != null }
    }.getOrDefault(false)
}


fun checkNewVersion(): LatestVersionInfo = checkReleaseVersion("latest", isCi = false)

fun checkNewCiVersion(): LatestVersionInfo = checkReleaseVersion("tags/manager-ci", isCi = true)

private fun checkReleaseVersion(endpoint: String, isCi: Boolean): LatestVersionInfo {
    if (!isNetworkAvailable(ksuApp)) return LatestVersionInfo()
    val url = "https://api.github.com/repos/SukiSU-Ultra/SukiSU-Ultra/releases/$endpoint"
    return runCatching {
        ksuApp.okhttpClient.newCall(Request.Builder().url(url).build()).execute().use { response ->
            if (!response.isSuccessful) {
                android.util.Log.w("UpdateCheck", "$endpoint: HTTP ${response.code}")
                return LatestVersionInfo()
            }
            val json = org.json.JSONObject(response.body.string())
            val assets = json.getJSONArray("assets")
            val changelog = json.optString("body")
            if (isCi) {
                val versionCode = Regex("""\((\d+)\)""").find(json.optString("name"))
                    ?.groupValues?.get(1)?.toLongOrNull() ?: return LatestVersionInfo()
                val abi = Build.SUPPORTED_ABIS.firstOrNull() ?: return LatestVersionInfo()
                val apkPattern = Regex(
                    """^SukiSU_.+_${versionCode}-${Regex.escape(abi)}-release\.apk$"""
                )
                val apk = (0 until assets.length()).asSequence()
                    .mapNotNull { assets.optJSONObject(it) }
                    .firstOrNull { apkPattern.matches(it.optString("name")) }
                    ?: run {
                        android.util.Log.w("UpdateCheck", "CI: no APK for version=$versionCode, abi=$abi")
                        return LatestVersionInfo()
                    }
                val downloadUrl = apk.optString("browser_download_url")
                    .takeIf { it.startsWith("https://github.com/SukiSU-Ultra/SukiSU-Ultra/releases/download/manager-ci/") }
                    ?: return LatestVersionInfo()
                return LatestVersionInfo(versionCode, downloadUrl, changelog)
            }
            val abi = Build.SUPPORTED_ABIS.firstOrNull() ?: return LatestVersionInfo()
            val archPattern = Regex("""^SukiSU_v(.+?)_(\d+)-${Regex.escape(abi)}-release\.apk$""")
            val universalPattern = Regex("""^SukiSU_v(.+?)_(\d+)-release\.apk$""")
            val apkAssets = (0 until assets.length()).map { assets.getJSONObject(it) }
            // Prefer the device-specific asset, falling back to an actual universal APK only.
            for (pattern in listOf(archPattern, universalPattern)) {
                for (asset in apkAssets) {
                    val match = pattern.matchEntire(asset.getString("name")) ?: continue
                    return LatestVersionInfo(
                        match.groupValues[2].toLong(),
                        asset.getString("browser_download_url"),
                        changelog,
                    )
                }
            }
            LatestVersionInfo()
        }
    }.onFailure {
        android.util.Log.w("UpdateCheck", "$endpoint: update check failed", it)
    }.getOrDefault(LatestVersionInfo())
}
