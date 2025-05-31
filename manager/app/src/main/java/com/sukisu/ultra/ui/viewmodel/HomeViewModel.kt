package com.sukisu.ultra.ui.viewmodel

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.system.Os
import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.KernelVersion
import com.sukisu.ultra.Natives
import com.sukisu.ultra.getKernelVersion
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.util.checkNewVersion
import com.sukisu.ultra.ui.util.getKpmModuleCount
import com.sukisu.ultra.ui.util.getKpmVersion
import com.sukisu.ultra.ui.util.getModuleCount
import com.sukisu.ultra.ui.util.getSELinuxStatus
import com.sukisu.ultra.ui.util.getSuSFS
import com.sukisu.ultra.ui.util.getSuSFSFeatures
import com.sukisu.ultra.ui.util.getSuSFSVariant
import com.sukisu.ultra.ui.util.getSuSFSVersion
import com.sukisu.ultra.ui.util.getSuperuserCount
import com.sukisu.ultra.ui.util.module.LatestVersionInfo
import com.sukisu.ultra.ui.util.rootAvailable
import com.sukisu.ultra.ui.util.susfsSUS_SU_Mode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.topjohnwu.superuser.internal.Utils.context

/**
 * @author ShirkNeko
 * @date 2025/5/31.
 */
class HomeViewModel : ViewModel() {
    companion object {
        private const val TAG = "HomeViewModel"
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
        val kpmModuleCount: Int = 0
    )

    // UI状态
    var isRefreshing by mutableStateOf(false)
        private set

    // 系统状态信息
    var systemStatus by mutableStateOf(SystemStatus())
        private set

    // 系统详细信息
    var systemInfo by mutableStateOf(SystemInfo())
        private set

    // 更新信息
    var latestVersionInfo by mutableStateOf(LatestVersionInfo())
        private set

    // 用户设置
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
    var showKpmInfo by mutableStateOf(true)
        private set

    // 加载用户设置
    fun loadUserSettings(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            isSimpleMode = prefs.getBoolean("is_simple_mode", false)
            isHideVersion = prefs.getBoolean("is_hide_version", false)
            isHideOtherInfo = prefs.getBoolean("is_hide_other_info", false)
            isHideSusfsStatus = prefs.getBoolean("is_hide_susfs_status", false)
            isHideLinkCard = prefs.getBoolean("is_hide_link_card", false)
            showKpmInfo = prefs.getBoolean("show_kpm_info", true)
        }
    }

    // 初始化数据
    fun initializeData() {
        viewModelScope.launch {
            fetchSystemStatus()
            fetchSystemInfo()
        }
    }

    // 检查更新
    fun checkForUpdates(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val checkUpdate = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
                    .getBoolean("check_update", true)

                if (checkUpdate) {
                    val start = SystemClock.elapsedRealtime()
                    latestVersionInfo = checkNewVersion()
                    Log.i(TAG, "Update check completed in ${SystemClock.elapsedRealtime() - start}ms")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error checking for updates", e)
            }
        }
    }

    // 刷新所有数据
    fun refreshAllData(context: Context) {
        isRefreshing = true
        viewModelScope.launch {
            try {
                fetchSystemStatus()
                fetchSystemInfo()
                checkForUpdates(context)
            } finally {
                isRefreshing = false
            }
        }
    }

    // 获取系统状态
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

    // 获取系统信息
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
                    kpmModuleCount = getKpmModuleCount()
                )
            } catch (e: Exception) {
                Log.e(TAG, "Error fetching system info", e)
            }
        }
    }

    // 获取设备型号
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
            var result = Build.DEVICE
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
            Build.DEVICE
        }
    }

    // 获取管理器版本
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