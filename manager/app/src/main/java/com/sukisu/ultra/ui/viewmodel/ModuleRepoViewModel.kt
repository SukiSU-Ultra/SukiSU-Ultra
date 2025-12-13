package com.sukisu.ultra.ui.viewmodel

import android.os.Parcelable
import android.util.Log
import android.widget.Toast
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.R
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.util.module.ReleaseInfo
import com.sukisu.ultra.ui.util.module.fetchModuleDetail
import com.sukisu.ultra.ui.activity.util.isNetworkAvailable
import com.sukisu.ultra.ui.util.HanziToPinyin
import com.topjohnwu.superuser.io.SuFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.parcelize.Parcelize
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject

/**
 * @author AlexLiuDev233
 * @date 2025/12/6.
 */
class ModuleRepoViewModel : ViewModel() {
    companion object {
        private const val TAG = "ModuleRepoViewModel"
        private const val MODULES_URL = "https://modules.kernelsu.org/modules.json"
    }

    var sortStargazerCountFirst by mutableStateOf(false)
    private var _modules = mutableStateOf<List<RepoModule>>(emptyList())
    val modules: List<RepoModule> by derivedStateOf {
        _modules.value
            // 搜索过滤
            .filter { module ->
                module.moduleId.contains(search, true) ||
                        module.moduleName.contains(search, true) ||
                        HanziToPinyin.getInstance().toPinyinString(module.moduleName)?.contains(search, true) == true
            }
            .sortedWith(compareByDescending<RepoModule> { module ->
                // 已安装模块优先：存在文件的记为 true（在 compareByDescending 中 true > false）
                SuFile.open("/data/adb/modules/${module.moduleId}/module.prop").exists()
            }.thenByDescending { module ->
                if (sortStargazerCountFirst) module.stargazerCount else 0
            })
    }

    var isRefreshing by mutableStateOf(false)
    var search by mutableStateOf("")

    @Immutable
    @Parcelize
    data class Author(
        val name: String,
        val link: String,
    ) : Parcelable

    @Immutable
    @Parcelize
    data class RepoModule(
        val moduleId: String,
        val moduleName: String,
        val authors: String,
        val authorList: List<Author>,
        val summary: String,
        val metamodule: Boolean,
        val stargazerCount: Int,
        val updatedAt: String,
        val createdAt: String,
        val latestRelease: String,
        val latestReleaseTime: String,
        val latestVersionCode: Int,
        val latestAsset: ReleaseInfo?,
        val installed: Boolean,
        val readme: String,
        val sourceUrl: String,
        val releases: List<ReleaseInfo>
    ) : Parcelable

    fun refresh(
        onFailure: (() -> Unit)? = null
    ) {
        viewModelScope.launch {
            val netAvailable = isNetworkAvailable(ksuApp)
            withContext(Dispatchers.Main) { isRefreshing = true }
            val parsed = withContext(Dispatchers.IO) { if (!netAvailable) null else fetchModulesInternal(onFailure) }
            withContext(Dispatchers.Main) {
                if (parsed != null) {
                    _modules.value = parsed
                } else {
                    Toast.makeText(
                        ksuApp,
                        ksuApp.getString(R.string.network_offline), Toast.LENGTH_SHORT
                    ).show()
                }
                isRefreshing = false
            }
        }
    }

    private suspend fun fetchModulesInternal(
        onFailure: (() -> Unit)? = null
    ): List<RepoModule> {
        return runCatching {
            val request = Request.Builder().url(MODULES_URL).build()
            ksuApp.okhttpClient.newCall(request).execute().use { resp ->
                if (!resp.isSuccessful) return emptyList()
                val body = resp.body?.string() ?: return emptyList()
                val json = JSONArray(body)
                coroutineScope {
                    val jobs = (0 until json.length()).map { idx ->
                        async {
                            val item = json.optJSONObject(idx)
                            if (item != null) parseRepoModule(item) else null
                        }
                    }

                    jobs.awaitAll().filterNotNull()
                }
            }
        }.onFailure {
            onFailure?.invoke()
        }.getOrElse {
            Log.e(TAG, "fetch modules failed", it)
            emptyList()
        }
    }

    private suspend fun parseRepoModule(item: JSONObject): RepoModule? {
        val moduleId = item.optString("moduleId", "")
        if (moduleId.isEmpty()) return null
        val moduleName = item.optString("moduleName", "")
        val authorsArray = item.optJSONArray("authors")
        val authorList = if (authorsArray != null) {
            (0 until authorsArray.length())
                .mapNotNull { idx ->
                    val authorObj = authorsArray.optJSONObject(idx) ?: return@mapNotNull null
                    val name = authorObj.optString("name", "").trim()
                    var link = authorObj.optString("link", "").trim()
                    if (link.startsWith("`") && link.endsWith("`") && link.length >= 2) {
                        link = link.substring(1, link.length - 1)
                    }
                    if (name.isEmpty()) null else Author(name = name, link = link)
                }
        } else {
            emptyList()
        }
        val authors = if (authorList.isNotEmpty()) authorList.joinToString(", ") { it.name } else item.optString("authors", "")
        val summary = item.optString("summary", "")
        val metamodule = item.optBoolean("metamodule", false)
        val stargazerCount = item.optInt("stargazerCount", 0)
        val updatedAt = item.optString("updatedAt", "")
        val createdAt = item.optString("createdAt", "")

        var latestRelease = ""
        var latestReleaseTime = ""
        var latestVersionCode = 0
        var latestAsset: ReleaseInfo? = null
        val releases: MutableList<ReleaseInfo> = ArrayList()
        val lr = item.optJSONObject("latestRelease")
        if (lr != null) {
            val lrName = lr.optString("name", lr.optString("version", ""))
            val lrTime = lr.optString("time", "")
            val vcAny = lr.opt("versionCode")
            latestVersionCode = when (vcAny) {
                is Number -> vcAny.toInt()
                is String -> vcAny.toIntOrNull() ?: 0
                else -> 0
            }
            latestRelease = lrName
            latestReleaseTime = lrTime
        }
        val detail = withContext(Dispatchers.IO) {
            fetchModuleDetail((moduleId))
        }

        detail?.releases?.forEach { it ->
            releases.add(it)
            if (it.name != latestRelease) return@forEach

            latestAsset = it
        }

        return RepoModule(
            moduleId = moduleId,
            moduleName = moduleName,
            authors = authors,
            authorList = authorList,
            summary = summary,
            metamodule = metamodule,
            stargazerCount = stargazerCount,
            updatedAt = updatedAt,
            createdAt = createdAt,
            latestRelease = latestRelease,
            latestReleaseTime = latestReleaseTime,
            latestVersionCode = latestVersionCode,
            latestAsset = latestAsset,
            installed = SuFile.open("/data/adb/modules/${moduleId}/module.prop").exists(),
            readme = detail?.readme.orEmpty(),
            sourceUrl = detail?.sourceUrl.orEmpty(),
            releases = releases
        )
    }
}