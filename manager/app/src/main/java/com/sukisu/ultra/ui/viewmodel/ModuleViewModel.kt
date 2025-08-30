package com.sukisu.ultra.ui.viewmodel

import android.content.Context
import android.os.SystemClock
import android.util.Log
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.edit
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.dergoogler.mmrl.platform.model.ModuleConfig
import com.dergoogler.mmrl.platform.model.ModuleConfig.Companion.asModuleConfig
import com.sukisu.ultra.ui.util.HanziToPinyin
import com.sukisu.ultra.ui.util.ModuleVerificationManager
import com.sukisu.ultra.ui.util.listModules
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.text.Collator
import java.text.DecimalFormat
import java.util.*
import java.util.concurrent.TimeUnit
import kotlin.math.log10
import kotlin.math.pow

/**
 * @author ShirkNeko
 * @date 2025/5/31.
 */
class ModuleViewModel : ViewModel() {

    companion object {
        private const val TAG = "ModuleViewModel"
        private var modules by mutableStateOf<List<ModuleInfo>>(emptyList())
        private const val CUSTOM_USER_AGENT = "SukiSU-Ultra/2.0"
    }

    // 模块大小缓存管理器
    private lateinit var moduleSizeCache: ModuleSizeCache

    fun initializeCache(context: Context) {
        if (!::moduleSizeCache.isInitialized) {
            moduleSizeCache = ModuleSizeCache(context)
        }
    }

    fun getModuleSize(dirId: String): String {
        if (!::moduleSizeCache.isInitialized) {
            return "0 KB"
        }
        val size = moduleSizeCache.getModuleSize(dirId)
        return formatFileSize(size)
    }

    /**
     * 刷新所有模块的大小缓存
     * 只在安装、卸载、更新模块后调用
     */
    fun refreshModuleSizeCache() {
        if (!::moduleSizeCache.isInitialized) return

        viewModelScope.launch(Dispatchers.IO) {
            Log.d(TAG, "开始刷新模块大小缓存")
            val currentModules = modules.map { it.dirId }
            moduleSizeCache.refreshCache(currentModules)
            Log.d(TAG, "模块大小缓存刷新完成")
        }
    }

    class ModuleInfo(
        val id: String,
        val name: String,
        val author: String,
        val version: String,
        val versionCode: Int,
        val description: String,
        val enabled: Boolean,
        val update: Boolean,
        val remove: Boolean,
        val updateJson: String,
        val hasWebUi: Boolean,
        val hasActionScript: Boolean,
        val dirId: String, // real module id (dir name)
        var config: ModuleConfig? = null,
        var isVerified: Boolean = false, // 添加验证状态字段
        var verificationTimestamp: Long = 0L, // 添加验证时间戳
    )

    var isRefreshing by mutableStateOf(false)
        private set
    var search by mutableStateOf("")

    var sortEnabledFirst by mutableStateOf(false)
    var sortActionFirst by mutableStateOf(false)
    val moduleList by derivedStateOf {
        val comparator =
            compareBy<ModuleInfo>(
                { if (sortEnabledFirst) !it.enabled else 0 },
                { if (sortActionFirst) !it.hasWebUi && !it.hasActionScript else 0 },
            ).thenBy(Collator.getInstance(Locale.getDefault()), ModuleInfo::id)
        modules.filter {
            it.id.contains(search, true) || it.name.contains(search, true) || HanziToPinyin.getInstance()
                .toPinyinString(it.name).contains(search, true)
        }.sortedWith(comparator).also {
            isRefreshing = false
        }
    }

    var isNeedRefresh by mutableStateOf(false)
        private set

    fun markNeedRefresh() {
        isNeedRefresh = true
        // 标记需要刷新时，同时刷新大小缓存
        refreshModuleSizeCache()
    }

    fun fetchModuleList() {
        viewModelScope.launch(Dispatchers.IO) {
            isRefreshing = true

            val oldModuleList = modules

            val start = SystemClock.elapsedRealtime()

            kotlin.runCatching {
                val result = listModules()

                Log.i(TAG, "result: $result")

                val array = JSONArray(result)
                val moduleInfos = (0 until array.length())
                    .asSequence()
                    .map { array.getJSONObject(it) }
                    .map { obj ->
                        ModuleInfo(
                            obj.getString("id"),
                            obj.optString("name"),
                            obj.optString("author", "Unknown"),
                            obj.optString("version", "Unknown"),
                            obj.optInt("versionCode", 0),
                            obj.optString("description"),
                            obj.getBoolean("enabled"),
                            obj.getBoolean("update"),
                            obj.getBoolean("remove"),
                            obj.optString("updateJson"),
                            obj.optBoolean("web"),
                            obj.optBoolean("action"),
                            obj.getString("dir_id")
                        )
                    }.toList()

                // 批量检查所有模块的验证状态
                val moduleIds = moduleInfos.map { it.dirId }
                val verificationStatus = ModuleVerificationManager.batchCheckVerificationStatus(moduleIds)

                // 更新模块验证状态
                modules = moduleInfos.map { moduleInfo ->
                    val isVerified = verificationStatus[moduleInfo.dirId] ?: false
                    val verificationTimestamp = if (isVerified) {
                        ModuleVerificationManager.getVerificationTimestamp(moduleInfo.dirId)
                    } else {
                        0L
                    }

                    moduleInfo.copy(
                        isVerified = isVerified,
                        verificationTimestamp = verificationTimestamp
                    )
                }

                launch {
                    modules.forEach { module ->
                        withContext(Dispatchers.IO) {
                            try {
                                runCatching {
                                    module.config = module.id.asModuleConfig
                                }.onFailure { e ->
                                    Log.e(TAG, "Failed to load config from id for module ${module.id}", e)
                                }
                                if (module.config == null) {
                                    runCatching {
                                        module.config = module.name.asModuleConfig
                                    }.onFailure { e ->
                                        Log.e(TAG, "Failed to load config from name for module ${module.id}", e)
                                    }
                                }
                                if (module.config == null) {
                                    runCatching {
                                        module.config = module.description.asModuleConfig
                                    }.onFailure { e ->
                                        Log.e(TAG, "Failed to load config from description for module ${module.id}", e)
                                    }
                                }
                                if (module.config == null) {
                                    module.config = ModuleConfig()
                                }
                            } catch (e: Exception) {
                                Log.e(TAG, "Failed to load any config for module ${module.id}", e)
                                module.config = ModuleConfig()
                            }
                        }
                    }
                }

                // 首次加载模块列表时，初始化缓存
                if (::moduleSizeCache.isInitialized) {
                    val currentModules = modules.map { it.dirId }
                    moduleSizeCache.initializeCacheIfNeeded(currentModules)
                }

                isNeedRefresh = false
            }.onFailure { e ->
                Log.e(TAG, "fetchModuleList: ", e)
                isRefreshing = false
            }

            // when both old and new is kotlin.collections.EmptyList
            // moduleList update will don't trigger
            if (oldModuleList === modules) {
                isRefreshing = false
            }

            Log.i(TAG, "load cost: ${SystemClock.elapsedRealtime() - start}, modules: $modules")
        }
    }

    private fun sanitizeVersionString(version: String): String {
        return version.replace(Regex("[^a-zA-Z0-9.\\-_]"), "_")
    }

    fun checkUpdate(m: ModuleInfo): Triple<String, String, String> {
        val empty = Triple("", "", "")
        if (m.updateJson.isEmpty() || m.remove || m.update || !m.enabled) {
            return empty
        }
        // download updateJson
        val result = kotlin.runCatching {
            val url = m.updateJson
            Log.i(TAG, "checkUpdate url: $url")

            val client = okhttp3.OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(15, TimeUnit.SECONDS)
                .build()

            val request = okhttp3.Request.Builder()
                .url(url)
                .header("User-Agent", CUSTOM_USER_AGENT)
                .build()

            val response = client.newCall(request).execute()

            Log.d(TAG, "checkUpdate code: ${response.code}")
            if (response.isSuccessful) {
                response.body?.string() ?: ""
            } else {
                Log.d(TAG, "checkUpdate failed: ${response.message}")
                ""
            }
        }.getOrElse { e ->
            Log.e(TAG, "checkUpdate exception", e)
            ""
        }

        Log.i(TAG, "checkUpdate result: $result")

        if (result.isEmpty()) {
            return empty
        }

        val updateJson = kotlin.runCatching {
            JSONObject(result)
        }.getOrNull() ?: return empty

        var version = updateJson.optString("version", "")
        version = sanitizeVersionString(version)
        val versionCode = updateJson.optInt("versionCode", 0)
        val zipUrl = updateJson.optString("zipUrl", "")
        val changelog = updateJson.optString("changelog", "")
        if (versionCode <= m.versionCode || zipUrl.isEmpty()) {
            return empty
        }

        return Triple(zipUrl, version, changelog)
    }
}

fun ModuleViewModel.ModuleInfo.copy(
    id: String = this.id,
    name: String = this.name,
    author: String = this.author,
    version: String = this.version,
    versionCode: Int = this.versionCode,
    description: String = this.description,
    enabled: Boolean = this.enabled,
    update: Boolean = this.update,
    remove: Boolean = this.remove,
    updateJson: String = this.updateJson,
    hasWebUi: Boolean = this.hasWebUi,
    hasActionScript: Boolean = this.hasActionScript,
    dirId: String = this.dirId,
    config: ModuleConfig? = this.config,
    isVerified: Boolean = this.isVerified,
    verificationTimestamp: Long = this.verificationTimestamp
): ModuleViewModel.ModuleInfo {
    return ModuleViewModel.ModuleInfo(
        id, name, author, version, versionCode, description,
        enabled, update, remove, updateJson, hasWebUi, hasActionScript,
        dirId, config, isVerified, verificationTimestamp
    )
}

/**
 * 模块大小缓存管理器
 */
class ModuleSizeCache(context: Context) {
    companion object {
        private const val TAG = "ModuleSizeCache"
        private const val CACHE_PREFS_NAME = "module_size_cache"
        private const val CACHE_VERSION_KEY = "cache_version"
        private const val CACHE_INITIALIZED_KEY = "cache_initialized"
        private const val CURRENT_CACHE_VERSION = 1
    }

    private val cachePrefs = context.getSharedPreferences(CACHE_PREFS_NAME, Context.MODE_PRIVATE)
    private val sizeCache = mutableMapOf<String, Long>()

    init {
        loadCacheFromPrefs()
    }

    /**
     * 从SharedPreferences加载缓存
     */
    private fun loadCacheFromPrefs() {
        try {
            val cacheVersion = cachePrefs.getInt(CACHE_VERSION_KEY, 0)
            if (cacheVersion != CURRENT_CACHE_VERSION) {
                Log.d(TAG, "缓存版本不匹配，清空缓存")
                clearCache()
                return
            }

            val allEntries = cachePrefs.all
            for ((key, value) in allEntries) {
                if (key != CACHE_VERSION_KEY && key != CACHE_INITIALIZED_KEY && value is Long) {
                    sizeCache[key] = value
                }
            }
            Log.d(TAG, "从缓存加载了 ${sizeCache.size} 个模块大小数据")
        } catch (e: Exception) {
            Log.e(TAG, "加载缓存失败", e)
            clearCache()
        }
    }

    /**
     * 保存缓存到SharedPreferences
     */
    private fun saveCacheToPrefs() {
        try {
            cachePrefs.edit {
                putInt(CACHE_VERSION_KEY, CURRENT_CACHE_VERSION)
                putBoolean(CACHE_INITIALIZED_KEY, true)

                for ((dirId, size) in sizeCache) {
                    putLong(dirId, size)
                }

            }
            Log.d(TAG, "保存了 ${sizeCache.size} 个模块大小到缓存")
        } catch (e: Exception) {
            Log.e(TAG, "保存缓存失败", e)
        }
    }

    /**
     * 获取模块大小（从缓存）
     */
    fun getModuleSize(dirId: String): Long {
        return sizeCache[dirId] ?: 0L
    }

    /**
     * 检查缓存是否已初始化，如果没有则初始化
     */
    fun initializeCacheIfNeeded(currentModules: List<String>) {
        val isInitialized = cachePrefs.getBoolean(CACHE_INITIALIZED_KEY, false)
        if (!isInitialized || sizeCache.isEmpty()) {
            Log.d(TAG, "首次初始化缓存，计算所有模块大小")
            refreshCache(currentModules)
        } else {
            // 检查是否有新模块需要计算大小
            val newModules = currentModules.filter { !sizeCache.containsKey(it) }
            if (newModules.isNotEmpty()) {
                Log.d(TAG, "发现 ${newModules.size} 个新模块，计算大小: $newModules")
                for (dirId in newModules) {
                    val size = calculateModuleFolderSize(dirId)
                    sizeCache[dirId] = size
                    Log.d(TAG, "新模块 $dirId 大小: ${formatFileSize(size)}")
                }
                saveCacheToPrefs()
            }
        }
    }

    /**
     * 刷新所有模块的大小缓存
     */
    fun refreshCache(currentModules: List<String>) {
        try {
            // 清理不存在的模块缓存
            val toRemove = sizeCache.keys.filter { it !in currentModules }
            toRemove.forEach { sizeCache.remove(it) }

            if (toRemove.isNotEmpty()) {
                Log.d(TAG, "清理了 ${toRemove.size} 个不存在的模块缓存: $toRemove")
            }

            // 计算所有当前模块的大小
            for (dirId in currentModules) {
                val size = calculateModuleFolderSize(dirId)
                sizeCache[dirId] = size
                Log.d(TAG, "更新模块 $dirId 大小: ${formatFileSize(size)}")
            }

            // 保存到持久化存储
            saveCacheToPrefs()
        } catch (e: Exception) {
            Log.e(TAG, "刷新缓存失败", e)
        }
    }

    /**
     * 清空所有缓存
     */
    private fun clearCache() {
        sizeCache.clear()
        cachePrefs.edit { clear() }
        Log.d(TAG, "清空所有缓存")
    }

    /**
     * 实际计算模块文件夹大小
     */
    private fun calculateModuleFolderSize(dirId: String): Long {
        return try {
            val command = "du -sb /data/adb/modules/$dirId"
            val result = Shell.cmd(command).to(ArrayList(), null).exec()

            if (result.isSuccess && result.out.isNotEmpty()) {
                val sizeStr = result.out.firstOrNull()?.split("\t")?.firstOrNull()
                sizeStr?.toLongOrNull() ?: 0L
            } else {
                0L
            }
        } catch (e: Exception) {
            Log.e(TAG, "计算模块大小失败 $dirId: ${e.message}")
            0L
        }
    }
}

/**
 * 格式化文件大小的工具函数
 */
fun formatFileSize(bytes: Long): String {
    if (bytes <= 0) return "0 KB"

    val units = arrayOf("B", "KB", "MB", "GB", "TB")
    val digitGroups = (log10(bytes.toDouble()) / log10(1024.0)).toInt()

    return DecimalFormat("#,##0.#").format(
        bytes / 1024.0.pow(digitGroups.toDouble())
    ) + " " + units[digitGroups]
}