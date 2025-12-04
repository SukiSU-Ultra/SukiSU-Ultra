package com.sukisu.ultra.ui.viewmodel

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.system.Os
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.KernelVersion
import com.sukisu.ultra.Natives
import com.sukisu.ultra.getKernelVersion
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.util.*
import com.sukisu.ultra.ui.util.module.LatestVersionInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

class HomeViewModel : ViewModel() {

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
        val superuserCount: Int = 0,
        val moduleCount: Int = 0,
        val kpmModuleCount: Int = 0,
        val managersList: Natives.ManagersList? = null,
        val isDynamicSignEnabled: Boolean = false,
        val zygiskImplement: String = "",
        val metaModuleImplement: String = ""
    )

    // 状态变量
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
    var isHideMetaModuleImplement by mutableStateOf(false)
        private set
    var isHideLinkCard by mutableStateOf(false)
        private set
    var showKpmInfo by mutableStateOf(false)
        private set

    var isCoreDataLoaded by mutableStateOf(false)
        private set
    var isExtendedDataLoaded by mutableStateOf(false)
        private set
    var isRefreshing by mutableStateOf(false)
        private set

    // 数据刷新状态流，用于监听变化
    private val _dataRefreshTrigger = MutableStateFlow(0L)
    val dataRefreshTrigger: StateFlow<Long> = _dataRefreshTrigger

    private var loadingJobs = mutableListOf<Job>()
    private var lastRefreshTime = 0L
    private val refreshCooldown = 2000L

    fun loadUserSettings(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            val settingsPrefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            isSimpleMode = settingsPrefs.getBoolean("is_simple_mode", false)
            isKernelSimpleMode = settingsPrefs.getBoolean("is_kernel_simple_mode", false)
            isHideVersion = settingsPrefs.getBoolean("is_hide_version", false)
            isHideOtherInfo = settingsPrefs.getBoolean("is_hide_other_info", false)
            isHideSusfsStatus = settingsPrefs.getBoolean("is_hide_susfs_status", false)
            isHideLinkCard = settingsPrefs.getBoolean("is_hide_link_card", false)
            isHideZygiskImplement = settingsPrefs.getBoolean("is_hide_zygisk_Implement", false)
            isHideMetaModuleImplement = settingsPrefs.getBoolean("is_hide_meta_module_Implement", false)
            showKpmInfo = settingsPrefs.getBoolean("show_kpm_info", false)
        }
    }

    fun loadCoreData() {
        if (isCoreDataLoaded) return

        val job = viewModelScope.launch(Dispatchers.IO) {
            try {
                val kernelVersion = getKernelVersion()
                val isManager = try {
                    Natives.isManager
                } catch (_: Exception) {
                    false
                }

                val ksuVersion = if (isManager) Natives.version else null

                val fullVersion = try {
                    Natives.getFullVersion()
                } catch (_: Exception) {
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
                    } catch (_: Exception) {
                        fullVersion
                    }
                } else {
                    fullVersion
                }

                val lkmMode = ksuVersion?.let {
                    if (kernelVersion.isGKI()) Natives.isLkmMode else null
                }

                val isRootAvailable = try {
                    rootAvailable()
                } catch (_: Exception) {
                    false
                }

                val isKpmConfigured = try {
                    Natives.isKPMEnabled()
                } catch (_: Exception) {
                    false
                }

                val requireNewKernel = try {
                    isManager && Natives.requireNewKernel()
                } catch (_: Exception) {
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

                isCoreDataLoaded = true
            } catch (_: Exception) {
            }
        }
        loadingJobs.add(job)
    }

    fun loadExtendedData(context: Context) {
        if (isExtendedDataLoaded) return

        val job = viewModelScope.launch(Dispatchers.IO) {
            try {
                // 分批加载
                delay(50)

                val basicInfo = loadBasicSystemInfo(context)
                systemInfo = systemInfo.copy(
                    kernelRelease = basicInfo.first,
                    androidVersion = basicInfo.second,
                    deviceModel = basicInfo.third,
                    managerVersion = basicInfo.fourth,
                    seLinuxStatus = basicInfo.fifth
                )

                delay(100)

                // 加载模块信息
                if (!isSimpleMode) {
                    val moduleInfo = loadModuleInfo()
                    systemInfo = systemInfo.copy(
                        kpmVersion = moduleInfo.first,
                        superuserCount = moduleInfo.second,
                        moduleCount = moduleInfo.third,
                        kpmModuleCount = moduleInfo.fourth,
                        zygiskImplement = moduleInfo.fifth,
                        metaModuleImplement = moduleInfo.sixth
                    )
                }

                delay(100)

                // 加载SuSFS信息
                if (!isHideSusfsStatus) {
                    val suSFSInfo = loadSuSFSInfo()
                    systemInfo = systemInfo.copy(
                        suSFSStatus = suSFSInfo.first,
                        suSFSVersion = suSFSInfo.second,
                        suSFSVariant = suSFSInfo.third,
                        suSFSFeatures = suSFSInfo.fourth,
                    )
                }

                delay(100)

                // 加载管理器列表
                val managerInfo = loadManagerInfo()
                systemInfo = systemInfo.copy(
                    managersList = managerInfo.first,
                    isDynamicSignEnabled = managerInfo.second
                )

                isExtendedDataLoaded = true
            } catch (_: Exception) {
                // 静默处理错误
            }
        }
        loadingJobs.add(job)
    }

    fun refreshData(context: Context, forceRefresh: Boolean = false) {
        val currentTime = System.currentTimeMillis()

        // 如果不是强制刷新，检查冷却时间
        if (!forceRefresh && currentTime - lastRefreshTime < refreshCooldown) {
            return
        }

        lastRefreshTime = currentTime

        viewModelScope.launch {
            isRefreshing = true

            try {
                // 取消正在进行的加载任务
                loadingJobs.forEach { it.cancel() }
                loadingJobs.clear()

                // 重置状态
                isCoreDataLoaded = false
                isExtendedDataLoaded = false

                // 触发数据刷新状态流
                _dataRefreshTrigger.value = currentTime

                // 重新加载用户设置
                loadUserSettings(context)

                // 重新加载核心数据
                loadCoreData()
                delay(100)

                // 重新加载扩展数据
                loadExtendedData(context)

                // 检查更新
                val settingsPrefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
                val checkUpdate = settingsPrefs.getBoolean("check_update", true)
                if (checkUpdate) {
                    try {
                        val newVersionInfo = withContext(Dispatchers.IO) {
                            checkNewVersion()
                        }
                        latestVersionInfo = newVersionInfo
                    } catch (_: Exception) {
                    }
                }
            } catch (_: Exception) {
                // 静默处理错误
            } finally {
                isRefreshing = false
            }
        }
    }

    // 手动触发刷新（下拉刷新使用）
    fun onPullRefresh(context: Context) {
        refreshData(context, forceRefresh = true)
    }

    // 自动刷新数据（当检测到变化时）
    fun autoRefreshIfNeeded(context: Context) {
        viewModelScope.launch {
            // 检查是否需要刷新数据
            val needsRefresh = checkIfDataNeedsRefresh()
            if (needsRefresh) {
                refreshData(context)
            }
        }
    }

    private suspend fun checkIfDataNeedsRefresh(): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                // 检查KSU状态是否发生变化
                val currentKsuVersion = try {
                    if (Natives.isManager) {
                        Natives.version
                    } else null
                } catch (_: Exception) {
                    null
                }

                // 如果KSU版本发生变化，需要刷新
                if (currentKsuVersion != systemStatus.ksuVersion) {
                    return@withContext true
                }

                // 检查模块数量是否发生变化
                val currentModuleCount = try {
                    getModuleCount()
                } catch (_: Exception) {
                    systemInfo.moduleCount
                }

                if (currentModuleCount != systemInfo.moduleCount) {
                    return@withContext true
                }

                false
            } catch (_: Exception) {
                false
            }
        }
    }

    private suspend fun loadBasicSystemInfo(context: Context): Tuple5<String, String, String, Pair<String, Long>, String> {
        return withContext(Dispatchers.IO) {
            val uname = try {
                Os.uname()
            } catch (_: Exception) {
                null
            }

            val deviceModel = try {
                getDeviceModel()
            } catch (_: Exception) {
                "Unknown"
            }

            val managerVersion = try {
                getManagerVersion(context)
            } catch (_: Exception) {
                Pair("Unknown", 0L)
            }

            val seLinuxStatus = try {
                getSELinuxStatus(ksuApp.applicationContext)
            } catch (_: Exception) {
                "Unknown"
            }

            Tuple5(
                uname?.release ?: "Unknown",
                Build.VERSION.RELEASE ?: "Unknown",
                deviceModel,
                managerVersion,
                seLinuxStatus
            )
        }
    }

    private suspend fun loadModuleInfo(): Tuple6<String, Int, Int, Int, String, String> {
        return withContext(Dispatchers.IO) {
            val kpmVersion = try {
                getKpmVersion()
            } catch (_: Exception) {
                "Unknown"
            }

            val superuserCount = try {
                getSuperuserCount()
            } catch (_: Exception) {
                0
            }

            val moduleCount = try {
                getModuleCount()
            } catch (_: Exception) {
                0
            }

            val kpmModuleCount = try {
                getKpmModuleCount()
            } catch (_: Exception) {
                0
            }

            val zygiskImplement = try {
                getZygiskImplement()
            } catch (_: Exception) {
                "None"
            }

            val metaModuleImplement = try {
                getMetaModuleImplement()
            } catch (_: Exception) {
                "None"
            }

            Tuple6(kpmVersion, superuserCount, moduleCount, kpmModuleCount, zygiskImplement, metaModuleImplement)
        }
    }

    private suspend fun loadSuSFSInfo(): Tuple4<String, String, String, String> {
        return withContext(Dispatchers.IO) {
            val suSFS = try {
                if (getSuSFSStatus().equals("true", ignoreCase = true)) {
                    "Supported"
                } else {
                    "Unsupported"
                }
            } catch (_: Exception) {
                "Unknown"
            }

            if (suSFS != "Supported") {
                return@withContext Tuple4(suSFS, "", "", "")
            }

            val suSFSVersion = try {
                getSuSFSVersion()
            } catch (_: Exception) {
                ""
            }

            if (suSFSVersion.isEmpty()) {
                return@withContext Tuple4(suSFS, "", "", "")
            }

            val suSFSFeatures = try {
                getSuSFSFeatures()
            } catch (_: Exception) {
                ""
            }

            Tuple4(suSFS, suSFSVersion, "", suSFSFeatures)
        }
    }

    private suspend fun loadManagerInfo(): Pair<Natives.ManagersList?, Boolean> {
        return withContext(Dispatchers.IO) {
            val dynamicSignConfig = try {
                Natives.getDynamicManager()
            } catch (_: Exception) {
                null
            }

            val isDynamicSignEnabled = try {
                dynamicSignConfig?.isValid() == true
            } catch (_: Exception) {
                false
            }

            val managersList = if (isDynamicSignEnabled) {
                try {
                    Natives.getManagersList()
                } catch (_: Exception) {
                    null
                }
            } else {
                null
            }

            Pair(managersList, isDynamicSignEnabled)
        }
    }

    @SuppressLint("PrivateApi")
    private fun getDeviceModel(): String {
        return try {
            val systemProperties = Class.forName("android.os.SystemProperties")
            val getMethod = systemProperties.getMethod("get", String::class.java, String::class.java)
            val marketNameKeys = listOf(
                "ro.product.marketname",
                "ro.vendor.oplus.market.name",
                "ro.vivo.market.name",
                "ro.config.marketing_name"
            )
            var result = getDeviceInfo()
            for (key in marketNameKeys) {
                try {
                    val marketName = getMethod.invoke(null, key, "") as String
                    if (marketName.isNotEmpty()) {
                        result = marketName
                        break
                    }
                } catch (_: Exception) {
                }
            }
            result
        } catch (

            _: Exception) {
            getDeviceInfo()
        }
    }

    private fun getDeviceInfo(): String {
        return try {
            var manufacturer = Build.MANUFACTURER ?: "Unknown"
            manufacturer = manufacturer[0].uppercaseChar().toString() + manufacturer.substring(1)

            val brand = Build.BRAND ?: ""
            if (brand.isNotEmpty() && !brand.equals(Build.MANUFACTURER, ignoreCase = true)) {
                manufacturer += " " + brand[0].uppercaseChar() + brand.substring(1)
            }

            val model = Build.MODEL ?: ""
            if (model.isNotEmpty()) {
                manufacturer += " $model "
            }

            manufacturer
        } catch (_: Exception) {
            "Unknown Device"
        }
    }

    private fun getManagerVersion(context: Context): Pair<String, Long> {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            val versionCode = androidx.core.content.pm.PackageInfoCompat.getLongVersionCode(packageInfo)
            val versionName = packageInfo.versionName ?: "Unknown"
            Pair(versionName, versionCode)
        } catch (_: Exception) {
            Pair("Unknown", 0L)
        }
    }

    data class Tuple6<T1, T2, T3, T4, T5, T6>(
        val first: T1,
        val second: T2,
        val third: T3,
        val fourth: T4,
        val fifth: T5,
        val sixth: T6
    )

    data class Tuple5<T1, T2, T3, T4, T5>(
        val first: T1,
        val second: T2,
        val third: T3,
        val fourth: T4,
        val fifth: T5
    )

    data class Tuple4<T1, T2, T3, T4>(
        val first: T1,
        val second: T2,
        val third: T3,
        val fourth: T4
    )

    override fun onCleared() {
        super.onCleared()
        loadingJobs.forEach { it.cancel() }
        loadingJobs.clear()
    }
}