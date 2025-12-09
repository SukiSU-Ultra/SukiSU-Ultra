package com.sukisu.ultra.ui.util.module

import android.os.Parcelable
import android.util.Log
import androidx.compose.runtime.Immutable
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.activity.util.isNetworkAvailable
import kotlinx.parcelize.Parcelize
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject

const val TAG = "ModuleRepoApi"

data class ModuleDetail(
    val readme: String,
    val latestTag: String,
    val latestTime: String,
    val latestAssetName: String?,
    val latestAssetUrl: String?,
    val releases: List<ReleaseInfo>,
    val homepageUrl: String?,
    val sourceUrl: String?,
    val url: String?
)

@Immutable
@Parcelize
data class ReleaseInfo(
    val name: String,
    val tagName: String,
    val publishedAt: String,
    val descriptionHTML: String,
    val assets: List<ReleaseAssetInfo>
) : Parcelable

@Immutable
@Parcelize
data class ReleaseAssetInfo(
    val name: String,
    val downloadUrl: String,
    val size: Long,
    val downloadCount: Int
) : Parcelable

fun fetchModuleDetail(moduleId: String): ModuleDetail? {
    if (!isNetworkAvailable(ksuApp)) return null
    val url = "https://modules.kernelsu.org/module/$moduleId.json"
    return runCatching {
        ksuApp.okhttpClient.newCall(Request.Builder().url(url).build()).execute().use { resp ->
            if (!resp.isSuccessful) return@use null
            val body = resp.body?.string() ?: return@use null
            val obj = JSONObject(body)

            val readme = obj.optString("readmeHTML", "")
            fun stripTicks(s: String): String {
                val t = s.trim()
                return if (t.startsWith("`") && t.endsWith("`") && t.length >= 2) t.substring(1, t.length - 1) else t
            }
            val homepageUrl = stripTicks(obj.optString("homepageUrl", "")).ifBlank { null }
            val sourceUrl = stripTicks(obj.optString("sourceUrl", "")).ifBlank { null }
            val urlRepo = stripTicks(obj.optString("url", "")).ifBlank { null }
            val lr = obj.optJSONObject("latestRelease")
            var latestTag: String
            var latestTime = ""
            var latestAssetName: String? = null
            var latestAssetUrl: String? = null
            if (lr != null) {
                latestTag = lr.optString("name", lr.optString("version", ""))
                latestTime = lr.optString("time", "")
                var urlDl = lr.optString("downloadUrl", "")
                urlDl = stripTicks(urlDl)
                if (urlDl.isNotEmpty()) {
                    latestAssetName = urlDl.substringAfterLast('/')
                    latestAssetUrl = urlDl
                }
            } else {
                latestTag = obj.optString("latestRelease", "")
            }

            val releasesArray = obj.optJSONArray("releases")
            val releases = if (releasesArray != null) {
                (0 until releasesArray.length()).mapNotNull { rIdx ->
                    val r = releasesArray.optJSONObject(rIdx) ?: return@mapNotNull null
                    val rname = r.optString("name", r.optString("tagName", r.optString("version", "")))
                    val publishedAt = r.optString("publishedAt", "")
                    val descHtml = r.optString("descriptionHTML", "")
                    val assetsArray = r.optJSONArray("releaseAssets") ?: JSONArray()
                    val assets = (0 until assetsArray.length()).mapNotNull { aIdx ->
                        val a = assetsArray.optJSONObject(aIdx) ?: return@mapNotNull null
                        val aname = a.optString("name", "")
                        var adl = a.optString("downloadUrl", "")
                        adl = stripTicks(adl)
                        val asz = a.optLong("size", 0L)
                        val dcnt = when (val dcAny = a.opt("downloadCount")) {
                            is Number -> dcAny.toInt()
                            is String -> dcAny.toIntOrNull() ?: 0
                            else -> 0
                        }
                        if (aname.isEmpty() || adl.isEmpty()) null else ReleaseAssetInfo(aname, adl, asz, dcnt)
                    }
                    ReleaseInfo(
                        name = rname,
                        tagName = r.optString("tagName", rname),
                        publishedAt = publishedAt,
                        descriptionHTML = descHtml,
                        assets = assets
                    )
                }
            } else emptyList()

            return@use ModuleDetail(
                readme = readme,
                latestTag = latestTag,
                latestTime = latestTime,
                latestAssetName = latestAssetName,
                latestAssetUrl = latestAssetUrl,
                releases = releases,
                homepageUrl = homepageUrl,
                sourceUrl = sourceUrl,
                url = urlRepo
            )
        }
    }.getOrElse {
        Log.e(TAG,"Module Repo Api Calling FAILED", it)
        null
    }
}