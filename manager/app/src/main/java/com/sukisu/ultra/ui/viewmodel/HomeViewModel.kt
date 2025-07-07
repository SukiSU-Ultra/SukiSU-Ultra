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
    var isHideLinkCard by mutableStateOf(false)
        private set
    var showKpmInfo by mutableStateOf(false)
        private set

    fun loadUserSettings(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            isSimpleMode = prefs.getBoolean("is_simple_mode", false)
            isKernelSimpleMode = prefs.getBoolean("is_kernel_simple_mode", false)
            isHideVersion = prefs.getBoolean("is_hide_version", false)
            isHideOtherInfo = prefs.getBoolean("is_hide_other_info", false)
            isHideSusfsStatus = prefs.getBoolean("is_hide_susfs_status", false)
            isHideLinkCard = prefs.getBoolean("is_hide_link_card", false)
            showKpmInfo = prefs.getBoolean("show_kpm_info", false)
        }
    }

    fun initializeData() {
        viewModelScope.launch {
            try {
                loadCachedData()
            } catch(e: Exception) {
                Log.e(TAG, "Error when reading cached data", e)
            }
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
                val fullVersion = Natives.getFullVersion()
                val ksuFullVersion = if (isKernelSimpleMode) {
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
                } else {
                    fullVersion
                }

                val lkmMode = ksuVersion?.let {
                    if (it >= Natives.MINIMAL_SUPPORTED_KERNEL_LKM && kernelVersion.isGKI()) Natives.isLkmMode else null
                }

                systemStatus = SystemStatus(
                    isManager = isManager,
                    ksuVersion = ksuVersion,
                    ksuFullVersion = ksuFullVersion,
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

                // 获取动态签名状态和管理器列表
                val dynamicSignConfig = try {
                    Natives.getDynamicSign()
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to get dynamic sign config", e)
                    null
                }

                val isDynamicSignEnabled = dynamicSignConfig?.isValid() == true
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
                    moduleCount = getModuleCount(),
                    kpmModuleCount = getKpmModuleCount(),
                    managersList = managersList,
                    isDynamicSignEnabled = isDynamicSignEnabled,
                    zygiskImplement = getZygiskImplement()
                )
            } catch (e: Exception) {
                Log.e(TAG, "Error fetching system info", e)
            }
        }
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