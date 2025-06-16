package com.sukisu.ultra.ui.viewmodel

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.system.Os
import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.dergoogler.mmrl.platform.Platform.Companion.context
import com.google.gson.Gson
import com.sukisu.ultra.KernelVersion
import com.sukisu.ultra.Natives
import com.sukisu.ultra.getKernelVersion
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.util.*
import com.sukisu.ultra.ui.util.module.LatestVersionInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.core.content.edit
import kotlin.random.Random
import android.os.storage.StorageManager
import android.os.Environment
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.lang.reflect.Method

class HomeViewModel : ViewModel() {
    companion object {
        private const val TAG = "HomeViewModel"
        private const val PREFS_NAME = "home_cache"
        private const val KEY_SYSTEM_STATUS = "system_status"
        private const val KEY_SYSTEM_INFO = "system_info"
        private const val KEY_VERSION_INFO = "version_info"
        private const val KEY_LAST_UPDATE = "last_update_time"
    }

    // 系统状态
    data class SystemStatus(
        val isManager: Boolean = false,
        val ksuVersion: Int? = null,
        val lkmMode: Boolean? = null,
        val kernelVersion: KernelVersion = getKernelVersion(),
        val isRootAvailable: Boolean = false,
        val isKpmConfigured: Boolean = false,
        val requireNewKernel: Boolean = false
    )

    // 系统信息
    data class SystemInfo(
        val kernelRelease: String = "",
        val androidVersion: String = "",
        val deviceModel: String = "",
        val managerVersion: Pair<String, Long> = Pair("", 0L),
        val seLinuxStatus: String = "",
        val kpmVersion: String = "",
        val suSFSStatus: String = "",
        val suSFSVersion: String = "",
        val suSFSVariant: String = "",
        val suSFSFeatures: String = "",
        val susSUMode: String = "",
        val superuserCount: Int = 0,
        val moduleCount: Int = 0,
        val moduleEnabledCount: Int = 0,
        val moduleDisabledCount: Int = 0,
        val moduleUpdatableCount: Int = 0,
        val kpmModuleCount: Int = 0,
        val moduleStorageBytes: Long = 0
    )

    private val gson = Gson()
    private val prefs by lazy { ksuApp.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE) }

    var systemStatus by mutableStateOf(SystemStatus())
        private set

    var systemInfo by mutableStateOf(SystemInfo())
        private set

    var latestVersionInfo by mutableStateOf(LatestVersionInfo())
        private set

    var isSimpleMode by mutableStateOf(false)
        private set
    var isHideVersion by mutableStateOf(false)
        private set
    var isHideOtherInfo by mutableStateOf(false)
        private set
    var isHideSusfsStatus by mutableStateOf(false)
        private set
    var isHideLinkCard by mutableStateOf(false)
        private set
    var showKpmInfo by mutableStateOf(false)
        private set

    fun loadUserSettings(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            isSimpleMode = prefs.getBoolean("is_simple_mode", false)
            isHideVersion = prefs.getBoolean("is_hide_version", false)
            isHideOtherInfo = prefs.getBoolean("is_hide_other_info", false)
            isHideSusfsStatus = prefs.getBoolean("is_hide_susfs_status", false)
            isHideLinkCard = prefs.getBoolean("is_hide_link_card", false)
            showKpmInfo = prefs.getBoolean("show_kpm_info", false)
        }
    }

    fun initializeData() {
        viewModelScope.launch {
            loadCachedData()
        }
    }

    private fun loadCachedData() {
        prefs.getString(KEY_SYSTEM_STATUS, null)?.let {
            systemStatus = gson.fromJson(it, SystemStatus::class.java)
        }
        prefs.getString(KEY_SYSTEM_INFO, null)?.let {
            systemInfo = gson.fromJson(it, SystemInfo::class.java)
        }
        prefs.getString(KEY_VERSION_INFO, null)?.let {
            latestVersionInfo = gson.fromJson(it, LatestVersionInfo::class.java)
        }
    }

    private suspend fun fetchAndSaveData() {
        fetchSystemStatus()
        fetchSystemInfo()
        withContext(Dispatchers.IO) {
            prefs.edit {
                putString(KEY_SYSTEM_STATUS, gson.toJson(systemStatus))
                putString(KEY_SYSTEM_INFO, gson.toJson(systemInfo))
                putString(KEY_VERSION_INFO, gson.toJson(latestVersionInfo))
                putLong(KEY_LAST_UPDATE, System.currentTimeMillis())
            }
        }
    }

    fun checkForUpdates(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val checkUpdate = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
                    .getBoolean("check_update", true)

                if (checkUpdate) {
                    val newVersionInfo = checkNewVersion()
                    latestVersionInfo = newVersionInfo
                    prefs.edit {
                        putString(KEY_VERSION_INFO, gson.toJson(newVersionInfo))
                        putLong(KEY_LAST_UPDATE, System.currentTimeMillis())
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error checking for updates", e)
            }
        }
    }

    fun refreshAllData(context: Context) {
        viewModelScope.launch {
            try {
                fetchAndSaveData()
                checkForUpdates(context)
            } catch (e: Exception) {
                Log.e(TAG, "Error refreshing data", e)
            }
        }
    }

    private suspend fun fetchSystemStatus() {
        withContext(Dispatchers.IO) {
            try {
                val kernelVersion = getKernelVersion()
                val isManager = Natives.becomeManager(ksuApp.packageName)
                val ksuVersion = if (isManager) Natives.version else null
                val lkmMode = ksuVersion?.let {
                    if (it >= Natives.MINIMAL_SUPPORTED_KERNEL_LKM && kernelVersion.isGKI()) Natives.isLkmMode else null
                }

                systemStatus = SystemStatus(
                    isManager = isManager,
                    ksuVersion = ksuVersion,
                    lkmMode = lkmMode,
                    kernelVersion = kernelVersion,
                    isRootAvailable = rootAvailable(),
                    isKpmConfigured = Natives.isKPMEnabled(),
                    requireNewKernel = isManager && Natives.requireNewKernel()
                )
            } catch (e: Exception) {
                Log.e(TAG, "Error fetching system status", e)
            }
        }
    }

    @SuppressLint("RestrictedApi")
    private suspend fun fetchSystemInfo() {
        withContext(Dispatchers.IO) {
            try {
                val uname = Os.uname()
                val kpmVersion = getKpmVersion()
                val suSFS = getSuSFS()
                var suSFSVersion = ""
                var suSFSVariant = ""
                var suSFSFeatures = ""
                var susSUMode = ""

                if (suSFS == "Supported") {
                    suSFSVersion = getSuSFSVersion()
                    if (suSFSVersion.isNotEmpty()) {
                        suSFSVariant = getSuSFSVariant()
                        suSFSFeatures = getSuSFSFeatures()
                        val isSUS_SU = suSFSFeatures == "CONFIG_KSU_SUSFS_SUS_SU"
                        if (isSUS_SU) {
                            susSUMode = try {
                                susfsSUS_SU_Mode().toString()
                            } catch (_: Exception) {
                                ""
                            }
                        }
                    }
                }

                // 获取模块统计信息
                val moduleInfo = getDetailedModuleInfo()

                systemInfo = SystemInfo(
                    kernelRelease = uname.release,
                    androidVersion = Build.VERSION.RELEASE,
                    deviceModel = getDeviceModel(),
                    managerVersion = getManagerVersion(ksuApp.applicationContext),
                    seLinuxStatus = getSELinuxStatus(context),
                    kpmVersion = kpmVersion,
                    suSFSStatus = suSFS,
                    suSFSVersion = suSFSVersion,
                    suSFSVariant = suSFSVariant,
                    suSFSFeatures = suSFSFeatures,
                    susSUMode = susSUMode,
                    superuserCount = getSuperuserCount(),
                    moduleCount = moduleInfo.totalCount,
                    moduleEnabledCount = moduleInfo.enabledCount,
                    moduleDisabledCount = moduleInfo.disabledCount,
                    moduleUpdatableCount = moduleInfo.updatableCount,
                    kpmModuleCount = getKpmModuleCount(),
                    moduleStorageBytes = moduleInfo.storageBytes
                )
            } catch (e: Exception) {
                Log.e(TAG, "Error fetching system info", e)
            }
        }
    }

    /**
     * 获取模块存储空间占设备总存储空间的比例
     */
    fun getStorageUsageRatio(context: Context): Float {
        val totalDeviceStorage = getTotalDeviceStorage(context)
        if (totalDeviceStorage <= 0) return 0f
        
        return (systemInfo.moduleStorageBytes.toFloat() / totalDeviceStorage.toFloat()).coerceIn(0f, 1f)
    }

    /**
     * 格式化存储空间占用比例为百分比字符串
     */
    fun formatStorageRatio(context: Context): String {
        val ratio = getStorageUsageRatio(context)
        return String.format("%.2f%%", ratio * 100)
    }

    /**
     * 模块详细信息数据类
     */
    private data class ModuleInfo(
        val totalCount: Int = 0,
        val enabledCount: Int = 0,
        val disabledCount: Int = 0,
        val updatableCount: Int = 0,
        val storageBytes: Long = 0
    )

    /**
     * 获取详细的模块信息，包括启用/禁用数量、存储空间大小和可更新数量
     */
    private fun getDetailedModuleInfo(): ModuleInfo {
        try {
            // 获取模块列表
            val modulesJson = listModules()
            if (modulesJson.isBlank() || modulesJson == "[]") {
                return ModuleInfo()
            }

            val jsonArray = JSONArray(modulesJson)
            val totalCount = jsonArray.length()
            var enabledCount = 0
            var disabledCount = 0
            var updatableCount = 0
            var totalStorageBytes = 0L

            // 遍历模块列表，统计数据
            for (i in 0 until jsonArray.length()) {
                val module = jsonArray.getJSONObject(i)
                val enabled = module.optBoolean("enabled", false)
                val id = module.optString("id", "")
                
                // 统计启用/禁用模块
                if (enabled) {
                    enabledCount++
                } else {
                    disabledCount++
                }
                
                // 计算模块存储空间
                val modulePath = "/data/adb/modules/$id"
                totalStorageBytes += calculateDirectorySize(modulePath)
                
                // 检测模块是否有更新
                if (hasModuleUpdate(module)) {
                    updatableCount++
                }
            }

            return ModuleInfo(
                totalCount = totalCount,
                enabledCount = enabledCount,
                disabledCount = disabledCount,
                updatableCount = updatableCount,
                storageBytes = totalStorageBytes
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error getting detailed module info", e)
            return ModuleInfo()
        }
    }

    /**
     * 计算目录大小
     */
    private fun calculateDirectorySize(path: String): Long {
        try {
            val file = File(path)
            if (!file.exists() || !file.isDirectory) {
                return 0
            }

            var size = 0L
            val files = file.listFiles() ?: return 0
            
            for (f in files) {
                size += if (f.isDirectory) {
                    calculateDirectorySize(f.absolutePath)
                } else {
                    f.length()
                }
            }
            
            return size
        } catch (e: Exception) {
            Log.e(TAG, "Error calculating directory size: $path", e)
            return 0
        }
    }

    /**
     * 检查模块是否有更新
     */
    private fun hasModuleUpdate(module: JSONObject): Boolean {
        try {
            // 检查模块是否有更新JSON URL
            val updateJson = module.optString("updateJson", "")
            if (updateJson.isNotBlank()) {
                // TODO: 实现实际的更新检查逻辑
                // 此处只是简单示例，真实实现应该获取远程JSON并比较版本
                return false
            }
            return false
        } catch (e: Exception) {
            Log.e(TAG, "Error checking module update", e)
            return false
        }
    }

    /**
     * 获取设备总存储空间
     */
    private fun getTotalDeviceStorage(context: Context): Long {
        try {
            val storageManager = context.getSystemService(Context.STORAGE_SERVICE) as StorageManager
            
            // 使用兼容性方法获取总存储空间
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                // Android 8.0+，使用StorageStatsManager
                val uuid = try {
                    // 使用反射获取UUID方法，避免直接导入StorageStatsManager
                    val uuidMethod = StorageManager::class.java.getMethod("getUuidForPath", File::class.java)
                    uuidMethod.invoke(storageManager, Environment.getDataDirectory()) as? java.util.UUID
                } catch (e: Exception) {
                    Log.e(TAG, "Error getting UUID", e)
                    null
                }

                if (uuid != null) {
                    try {
                        // 通过反射获取StorageStatsManager并调用getTotalBytes
                        val statsManager = context.getSystemService("storagestats") ?: return getStorageSize(context)
                        val statsClass = Class.forName("android.os.storage.StorageStatsManager")
                        val getTotalBytesMethod = statsClass.getMethod("getTotalBytes", java.util.UUID::class.java)
                        val result = getTotalBytesMethod.invoke(statsManager, uuid)
                        if (result is Long) {
                            return result
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Error getting storage stats", e)
                    }
                }
                getStorageSize(context)
            } else {
                // Android 8.0以下，使用StatFs
                getStorageSize(context)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting total device storage", e)
            return getStorageSize(context)
        }
    }
    
    /**
     * 使用StatFs获取存储空间大小（适用于所有Android版本）
     */
    private fun getStorageSize(context: Context): Long {
        try {
            val statFs = android.os.StatFs(Environment.getDataDirectory().path)
            return statFs.blockCountLong * statFs.blockSizeLong
        } catch (e: Exception) {
            Log.e(TAG, "Error getting storage size with StatFs", e)
            return 1024L * 1024L * 1024L * 16L // 默认返回16GB
        }
    }

    /**
     * 格式化存储空间大小为人类可读格式
     */
    fun formatStorageSize(bytes: Long): String {
        if (bytes <= 0) return "0 B"
        
        val units = arrayOf("B", "KB", "MB", "GB", "TB")
        val digitGroups = (Math.log10(bytes.toDouble()) / Math.log10(1024.0)).toInt()
        
        return String.format("%.2f %s", 
            bytes / Math.pow(1024.0, digitGroups.toDouble()), 
            units[digitGroups])
    }

    private fun getDeviceInfo(): String {
        var manufacturer =
            Build.MANUFACTURER[0].uppercaseChar().toString() + Build.MANUFACTURER.substring(1)
        if (!Build.BRAND.equals(Build.MANUFACTURER, ignoreCase = true)) {
            manufacturer += " " + Build.BRAND[0].uppercaseChar() + Build.BRAND.substring(1)
        }
        manufacturer += " " + Build.MODEL + " "
        return manufacturer
    }

    @SuppressLint("PrivateApi")
    private fun getDeviceModel(): String {
        return try {
            val systemProperties = Class.forName("android.os.SystemProperties")
            val getMethod = systemProperties.getMethod("get", String::class.java, String::class.java)
            val marketNameKeys = listOf(
                "ro.product.marketname",          // Xiaomi
                "ro.vendor.oplus.market.name",    // Oppo, OnePlus, Realme
                "ro.vivo.market.name",            // Vivo
                "ro.config.marketing_name"        // Huawei
            )
            var result = getDeviceInfo()
            for (key in marketNameKeys) {
                val marketName = getMethod.invoke(null, key, "") as String
                if (marketName.isNotEmpty()) {
                    result = marketName
                    break
                }
            }
            result
        } catch (e: Exception) {
            Log.e(TAG, "Error getting device model", e)
            getDeviceInfo()
        }
    }

    private fun getManagerVersion(context: Context): Pair<String, Long> {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)!!
            val versionCode = androidx.core.content.pm.PackageInfoCompat.getLongVersionCode(packageInfo)
            Pair(packageInfo.versionName!!, versionCode)
        } catch (e: Exception) {
            Log.e(TAG, "Error getting manager version", e)
            Pair("", 0L)
        }
    }
}