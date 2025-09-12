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
import com.google.gson.JsonSyntaxException
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

class HomeViewModel : ViewModel() {
    companion object {
        private const val TAG = "HomeViewModel"
        private const val PREFS_NAME = "home_cache"
        private const val KEY_SYSTEM_STATUS = "system_status"
        private const val KEY_SYSTEM_INFO = "system_info"
        private const val KEY_VERSION_INFO = "version_info"
        private const val KEY_LAST_UPDATE = "last_update_time"
        private const val KEY_ERROR_COUNT = "error_count"
        private const val MAX_ERROR_COUNT = 2
    }

    // 系统状态
    data class SystemStatus(
        val isManager: Boolean = false,
        val ksuVersion: Int? = null,
        val ksuFullVersion : String? = null,
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
        val kpmModuleCount: Int = 0,
        val managersList: Natives.ManagersList? = null,
        val isDynamicSignEnabled: Boolean = false,
        val zygiskImplement: String = ""
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
    var isKernelSimpleMode by mutableStateOf(false)
        private set
    var isHideVersion by mutableStateOf(false)
        private set
    var isHideOtherInfo by mutableStateOf(false)
        private set
    var isHideSusfsStatus by mutableStateOf(false)
        private set
    var isHideZygiskImplement by mutableStateOf(false)
        private set
    var isHideLinkCard by mutableStateOf(false)
        private set
    var showKpmInfo by mutableStateOf(false)
        private set

    private fun clearAllCache() {
        try {
            prefs.edit { clear() }
            Log.i(TAG, "All cache cleared successfully")
        } catch (e: Exception) {
            Log.e(TAG, "Error clearing cache", e)
        }
    }

    private fun resetToDefaults() {
        systemStatus = SystemStatus()
        systemInfo = SystemInfo()
        latestVersionInfo = LatestVersionInfo()
        isSimpleMode = false
        isKernelSimpleMode = false
        isHideVersion = false
        isHideOtherInfo = false
        isHideSusfsStatus = false
        isHideZygiskImplement = false
        isHideLinkCard = false
        showKpmInfo = false
    }
    
    private fun handleError(error: Exception, operation: String) {
        Log.e(TAG, "Error in $operation", error)

        val errorCount = prefs.getInt(KEY_ERROR_COUNT, 0)
        val newErrorCount = errorCount + 1

        if (newErrorCount >= MAX_ERROR_COUNT) {
            Log.w(TAG, "Too many errors ($newErrorCount), clearing cache and resetting")
            clearAllCache()
            resetToDefaults()
        } else {
            prefs.edit {
                putInt(KEY_ERROR_COUNT, newErrorCount)
            }
        }
    }
    
    private fun String?.orSafe(default: String = ""): String {
        return if (this.isNullOrBlank()) default else this
    }
    
    private fun <T, R> Pair<T?, R?>?.orSafe(default: Pair<T, R>): Pair<T, R> {
        return if (this?.first == null || this.second == null) default else Pair(this.first!!, this.second!!)
    }

    fun loadUserSettings(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val settingsPrefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
                isSimpleMode = settingsPrefs.getBoolean("is_simple_mode", false)
                isKernelSimpleMode = settingsPrefs.getBoolean("is_kernel_simple_mode", false)
                isHideVersion = settingsPrefs.getBoolean("is_hide_version", false)
                isHideOtherInfo = settingsPrefs.getBoolean("is_hide_other_info", false)
                isHideSusfsStatus = settingsPrefs.getBoolean("is_hide_susfs_status", false)
                isHideLinkCard = settingsPrefs.getBoolean("is_hide_link_card", false)
                isHideZygiskImplement = settingsPrefs.getBoolean("is_hide_zygisk_Implement", false)
                showKpmInfo = settingsPrefs.getBoolean("show_kpm_info", false)
            } catch (e: Exception) {
                handleError(e, "loadUserSettings")
            }
        }
    }

    fun initializeData() {
        viewModelScope.launch {
            try {
                loadCachedData()
                // 成功加载后重置错误计数
                prefs.edit {
                    putInt(KEY_ERROR_COUNT, 0)
                }
            } catch(e: Exception) {
                handleError(e, "initializeData")
            }
        }
    }

    private fun loadCachedData() {
        try {
            prefs.getString(KEY_SYSTEM_STATUS, null)?.let { statusJson ->
                try {
                    val cachedStatus = gson.fromJson(statusJson, SystemStatus::class.java)
                    if (cachedStatus != null) {
                        systemStatus = cachedStatus
                    }
                } catch (e: JsonSyntaxException) {
                    Log.w(TAG, "Invalid system status JSON, using defaults", e)
                }
            }

            prefs.getString(KEY_SYSTEM_INFO, null)?.let { infoJson ->
                try {
                    val cachedInfo = gson.fromJson(infoJson, SystemInfo::class.java)
                    if (cachedInfo != null) {
                        systemInfo = cachedInfo
                    }
                } catch (e: JsonSyntaxException) {
                    Log.w(TAG, "Invalid system info JSON, using defaults", e)
                }
            }

            prefs.getString(KEY_VERSION_INFO, null)?.let { versionJson ->
                try {
                    val cachedVersion = gson.fromJson(versionJson, LatestVersionInfo::class.java)
                    if (cachedVersion != null) {
                        latestVersionInfo = cachedVersion
                    }
                } catch (e: JsonSyntaxException) {
                    Log.w(TAG, "Invalid version info JSON, using defaults", e)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error loading cached data", e)
            throw e
        }
    }

    private suspend fun fetchAndSaveData() {
        try {
            fetchSystemStatus()
            fetchSystemInfo()
            withContext(Dispatchers.IO) {
                prefs.edit {
                    putString(KEY_SYSTEM_STATUS, gson.toJson(systemStatus))
                    putString(KEY_SYSTEM_INFO, gson.toJson(systemInfo))
                    putString(KEY_VERSION_INFO, gson.toJson(latestVersionInfo))
                    putLong(KEY_LAST_UPDATE, System.currentTimeMillis())
                    putInt(KEY_ERROR_COUNT, 0)
                }
            }
        } catch (e: Exception) {
            handleError(e, "fetchAndSaveData")
        }
    }

    fun checkForUpdates(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val settingsPrefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
                val checkUpdate = settingsPrefs.getBoolean("check_update", true)

                if (checkUpdate) {
                    val newVersionInfo = checkNewVersion()
                    latestVersionInfo = newVersionInfo
                    prefs.edit {
                        putString(KEY_VERSION_INFO, gson.toJson(newVersionInfo))
                        putLong(KEY_LAST_UPDATE, System.currentTimeMillis())
                    }
                }
            } catch (e: Exception) {
                handleError(e, "checkForUpdates")
            }
        }
    }

    fun refreshAllData(context: Context) {
        viewModelScope.launch {
            try {
                fetchAndSaveData()
                checkForUpdates(context)
            } catch (e: Exception) {
                handleError(e, "refreshAllData")
            }
        }
    }

    private suspend fun fetchSystemStatus() {
        withContext(Dispatchers.IO) {
            try {
                val kernelVersion = getKernelVersion()
                val isManager = try {
                    Natives.becomeManager(ksuApp.packageName.orSafe("com.sukisu.ultra"))
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to become manager", e)
                    false
                }

                val ksuVersion = if (isManager) {
                    try {
                        Natives.version
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to get KSU version", e)
                        null
                    }
                } else null

                val fullVersion = try {
                    Natives.getFullVersion().orSafe("Unknown")
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to get full version", e)
                    "Unknown"
                }

                val ksuFullVersion = if (isKernelSimpleMode) {
                    try {
                        val startIndex = fullVersion.indexOf('v')
                        if (startIndex >= 0) {
                            val endIndex = fullVersion.indexOf('-', startIndex)
                            val versionStr = if (endIndex > startIndex) {
                                fullVersion.substring(startIndex, endIndex)
                            } else {
                                fullVersion.substring(startIndex)
                            }
                            val numericVersion = "v" + (Regex("""\d+(\.\d+)*""").find(versionStr)?.value ?: versionStr)
                            numericVersion
                        } else {
                            fullVersion
                        }
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to process full version", e)
                        fullVersion
                    }
                } else {
                    fullVersion
                }

                val lkmMode = ksuVersion?.let {
                    try {
                        if (it >= Natives.MINIMAL_SUPPORTED_KERNEL_LKM && kernelVersion.isGKI()) {
                            Natives.isLkmMode
                        } else null
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to get LKM mode", e)
                        null
                    }
                }

                val isRootAvailable = try {
                    rootAvailable()
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to check root availability", e)
                    false
                }

                val isKpmConfigured = try {
                    Natives.isKPMEnabled()
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to check KPM status", e)
                    false
                }

                val requireNewKernel = try {
                    isManager && Natives.requireNewKernel()
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to check kernel requirement", e)
                    false
                }

                systemStatus = SystemStatus(
                    isManager = isManager,
                    ksuVersion = ksuVersion,
                    ksuFullVersion = ksuFullVersion,
                    lkmMode = lkmMode,
                    kernelVersion = kernelVersion,
                    isRootAvailable = isRootAvailable,
                    isKpmConfigured = isKpmConfigured,
                    requireNewKernel = requireNewKernel
                )
            } catch (e: Exception) {
                Log.e(TAG, "Error fetching system status", e)
                throw e
            }
        }
    }

    @SuppressLint("RestrictedApi")
    private suspend fun fetchSystemInfo() {
        withContext(Dispatchers.IO) {
            try {
                val uname = try {
                    Os.uname()
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to get uname", e)
                    null
                }

                val kpmVersion = try {
                    getKpmVersion().orSafe("Unknown")
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to get kpm version", e)
                    "Unknown"
                }

                val suSFS = try {
                    getSuSFS().orSafe("Unknown")
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to get SuSFS", e)
                    "Unknown"
                }

                var suSFSVersion = ""
                var suSFSVariant = ""
                var suSFSFeatures = ""
                var susSUMode = ""

                if (suSFS == "Supported") {
                    suSFSVersion = try {
                        getSuSFSVersion().orSafe("")
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to get SuSFS version", e)
                        ""
                    }

                    if (suSFSVersion.isNotEmpty()) {
                        suSFSVariant = try {
                            getSuSFSVariant().orSafe("")
                        } catch (e: Exception) {
                            Log.w(TAG, "Failed to get SuSFS variant", e)
                            ""
                        }

                        suSFSFeatures = try {
                            getSuSFSFeatures().orSafe("")
                        } catch (e: Exception) {
                            Log.w(TAG, "Failed to get SuSFS features", e)
                            ""
                        }

                        val isSUS_SU = suSFSFeatures == "CONFIG_KSU_SUSFS_SUS_SU"
                        if (isSUS_SU) {
                            susSUMode = try {
                                susfsSUS_SU_Mode()
                            } catch (e: Exception) {
                                Log.w(TAG, "Failed to get SUS SU mode", e)
                                ""
                            }
                        }
                    }
                }

                // 获取动态管理器状态和管理器列表
                val dynamicSignConfig = try {
                    Natives.getDynamicManager()
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to get dynamic manager config", e)
                    null
                }

                val isDynamicSignEnabled = try {
                    dynamicSignConfig?.isValid() == true
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to check dynamic manager validity", e)
                    false
                }

                val managersList = if (isDynamicSignEnabled) {
                    try {
                        Natives.getManagersList()
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to get managers list", e)
                        null
                    }
                } else {
                    null
                }

                val deviceModel = try {
                    getDeviceModel().orSafe("Unknown")
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to get device model", e)
                    "Unknown"
                }

                val managerVersion = try {
                    getManagerVersion(ksuApp.applicationContext).orSafe(Pair("Unknown", 0L))
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to get manager version", e)
                    Pair("Unknown", 0L)
                }

                val seLinuxStatus = try {
                    getSELinuxStatus(context).orSafe("Unknown")
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to get SELinux status", e)
                    "Unknown"
                }

                val superuserCount = try {
                    getSuperuserCount()
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to get superuser count", e)
                    0
                }

                val moduleCount = try {
                    getModuleCount()
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to get module count", e)
                    0
                }

                val kpmModuleCount = try {
                    getKpmModuleCount()
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to get kpm module count", e)
                    0
                }

                val zygiskImplement = try {
                    getZygiskImplement().orSafe("None")
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to get Zygisk implement", e)
                    "None"
                }

                systemInfo = SystemInfo(
                    kernelRelease = uname?.release.orSafe("Unknown"),
                    androidVersion = Build.VERSION.RELEASE.orSafe("Unknown"),
                    deviceModel = deviceModel,
                    managerVersion = managerVersion,
                    seLinuxStatus = seLinuxStatus,
                    kpmVersion = kpmVersion,
                    suSFSStatus = suSFS,
                    suSFSVersion = suSFSVersion,
                    suSFSVariant = suSFSVariant,
                    suSFSFeatures = suSFSFeatures,
                    susSUMode = susSUMode,
                    superuserCount = superuserCount,
                    moduleCount = moduleCount,
                    kpmModuleCount = kpmModuleCount,
                    managersList = managersList,
                    isDynamicSignEnabled = isDynamicSignEnabled,
                    zygiskImplement = zygiskImplement
                )
            } catch (e: Exception) {
                Log.e(TAG, "Error fetching system info", e)
                throw e
            }
        }
    }

    private fun getDeviceInfo(): String {
        return try {
            var manufacturer = Build.MANUFACTURER.orSafe("Unknown")
            manufacturer = manufacturer[0].uppercaseChar().toString() + manufacturer.substring(1)

            val brand = Build.BRAND.orSafe("")
            if (brand.isNotEmpty() && !brand.equals(Build.MANUFACTURER, ignoreCase = true)) {
                manufacturer += " " + brand[0].uppercaseChar() + brand.substring(1)
            }

            val model = Build.MODEL.orSafe("")
            if (model.isNotEmpty()) {
                manufacturer += " $model "
            }

            manufacturer
        } catch (e: Exception) {
            Log.w(TAG, "Failed to get device info", e)
            "Unknown Device"
        }
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
                try {
                    val marketName = getMethod.invoke(null, key, "") as String
                    if (marketName.isNotEmpty()) {
                        result = marketName
                        break
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to get market name for key: $key", e)
                }
            }
            result
        } catch (e: Exception) {
            Log.w(TAG, "Error getting device model", e)
            getDeviceInfo()
        }
    }

    private fun getManagerVersion(context: Context): Pair<String, Long> {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            val versionCode = androidx.core.content.pm.PackageInfoCompat.getLongVersionCode(packageInfo)
            val versionName = packageInfo.versionName.orSafe("Unknown")
            Pair(versionName, versionCode)
        } catch (e: Exception) {
            Log.w(TAG, "Error getting manager version", e)
            Pair("Unknown", 0L)
        }
    }
}