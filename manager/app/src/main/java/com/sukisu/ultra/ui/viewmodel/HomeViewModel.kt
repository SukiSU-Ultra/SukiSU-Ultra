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
        val lsmStatus: String = "",
        val basebandGuardVersion: String = "",
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
            showKpmInfo = settingsPrefs.getBoolean("show_kpm_info", false)
        }
    }

    fun loadCoreData() {
        if (isCoreDataLoaded) return

        val job = viewModelScope.launch(Dispatchers.IO) {
            try {
                val kernelVersion = getKernelVersion()
                val isManager = try {
                    Natives.becomeManager(ksuApp.packageName ?: "com.sukisu.ultra")
                } catch (_: Exception) {
                    false
                }

                val ksuVersion = if (isManager) {
                    try {
                        Natives.version
                    } catch (_: Exception) {
                        null
                    }
                } else null

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
                    try {
                        if (it >= Natives.MINIMAL_SUPPORTED_KERNEL_LKM && kernelVersion.isGKI()) {
                            Natives.isLkmMode
                        } else null
                    } catch (_: Exception) {
                        null
                    }
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
                    seLinuxStatus = basicInfo.fifth,
                    lsmStatus = basicInfo.sixth,
                    basebandGuardVersion = basicInfo.seventh
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
                        zygiskImplement = moduleInfo.fifth
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
                        susSUMode = suSFSInfo.fifth
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
                    if (Natives.becomeManager(ksuApp.packageName ?: "com.sukisu.ultra")) {
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

    private suspend fun loadBasicSystemInfo(context: Context): Tuple7<String, String, String, Pair<String, Long>, String, String, String> {
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

            val lsmStatus = try {
                getLSMStatus()
            } catch (_: Exception) {
                "Unknown"
            }

            val basebandGuardVersion = try {
                getBasebandGuardVersion()
            } catch (_: Exception) {
                "Not installed"
            }

            Tuple7(
                uname?.release ?: "Unknown",
                Build.VERSION.RELEASE ?: "Unknown",
                deviceModel,
                managerVersion,
                seLinuxStatus,
                lsmStatus,
                basebandGuardVersion
            )
        }
    }

    private suspend fun loadModuleInfo(): Tuple5<String, Int, Int, Int, String> {
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

            Tuple5(kpmVersion, superuserCount, moduleCount, kpmModuleCount, zygiskImplement)
        }
    }

    private suspend fun loadSuSFSInfo(): Tuple5<String, String, String, String, String> {
        return withContext(Dispatchers.IO) {
            val suSFS = try {
                getSuSFS()
            } catch (_: Exception) {
                "Unknown"
            }

            if (suSFS != "Supported") {
                return@withContext Tuple5(suSFS, "", "", "", "")
            }

            val suSFSVersion = try {
                getSuSFSVersion()
            } catch (_: Exception) {
                ""
            }

            if (suSFSVersion.isEmpty()) {
                return@withContext Tuple5(suSFS, "", "", "", "")
            }

            val suSFSVariant = try {
                getSuSFSVariant()
            } catch (_: Exception) {
                ""
            }

            val suSFSFeatures = try {
                getSuSFSFeatures()
            } catch (_: Exception) {
                ""
            }

            val susSUMode = if (suSFSFeatures == "CONFIG_KSU_SUSFS_SUS_SU") {
                try {
                    susfsSUS_SU_Mode()
                } catch (_: Exception) {
                    ""
                }
            } else {
                ""
            }

            Tuple5(suSFS, suSFSVersion, suSFSVariant, suSFSFeatures, susSUMode)
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

    data class Tuple5<T1, T2, T3, T4, T5>(
        val first: T1,
        val second: T2,
        val third: T3,
        val fourth: T4,
        val fifth: T5
    )

    data class Tuple7<T1, T2, T3, T4, T5, T6, T7>(
        val first: T1,
        val second: T2,
        val third: T3,
        val fourth: T4,
        val fifth: T5,
        val sixth: T6,
        val seventh: T7
    )

    private fun getLSMStatus(): String {
        return try {
            val lsmFile = java.io.File("/sys/kernel/security/lsm")
            android.util.Log.d("LSM_DEBUG", "LSM file exists: ${lsmFile.exists()}, canRead: ${lsmFile.canRead()}")
            if (lsmFile.exists() && lsmFile.canRead()) {
                val content = lsmFile.readText().trim()
                android.util.Log.d("LSM_DEBUG", "LSM content: '$content'")
                content
            } else {
                android.util.Log.d("LSM_DEBUG", "LSM file not accessible, returning Unknown")
                "Unknown"
            }
        } catch (e: Exception) {
            android.util.Log.d("LSM_DEBUG", "Exception reading LSM: ${e.message}")
            "Unknown"
        }
    }

    private fun getBasebandGuardVersion(): String {
        return try {
            // Check if Baseband-guard is in the LSM list
            val lsmStatus = getLSMStatus()
            android.util.Log.d("BBG_DEBUG", "LSM Status: $lsmStatus")
            
            // Check for various BBG naming patterns in LSM
            val bbgPatterns = listOf("baseband_guard", "baseband-guard", "bbguard", "bb_guard")
            val hasBBG = bbgPatterns.any { pattern -> lsmStatus.lowercase().contains(pattern.lowercase()) }
            
            if (hasBBG) {
                android.util.Log.d("BBG_DEBUG", "BBG found in LSM list")
                
                // Try to read version from various possible locations
                val versionSources = listOf(
                    "/sys/kernel/security/baseband_guard/version",
                    "/sys/kernel/security/baseband-guard/version",
                    "/proc/sys/kernel/baseband_guard_version",
                    "/proc/sys/kernel/baseband-guard-version",
                    "/sys/module/baseband_guard/version",
                    "/sys/module/baseband-guard/version",
                    "/proc/version_signature"
                )
                
                for (versionPath in versionSources) {
                    try {
                        val versionFile = java.io.File(versionPath)
                        android.util.Log.d("BBG_DEBUG", "Checking path: $versionPath, exists: ${versionFile.exists()}, canRead: ${versionFile.canRead()}")
                        if (versionFile.exists() && versionFile.canRead()) {
                            val version = versionFile.readText().trim()
                            android.util.Log.d("BBG_DEBUG", "Version content: '$version'")
                            if (version.isNotEmpty() && !version.equals("unknown", ignoreCase = true)) {
                                // For /proc/version_signature, extract BBG info if present
                                if (versionPath.contains("version_signature") && version.contains("bbg", ignoreCase = true)) {
                                    val bbgMatch = Regex("bbg[_-]?v?([0-9.]+)", RegexOption.IGNORE_CASE).find(version)
                                    if (bbgMatch != null) {
                                        return "v${bbgMatch.groupValues[1]}"
                                    }
                                }
                                return version
                            }
                        }
                    } catch (e: Exception) {
                        android.util.Log.d("BBG_DEBUG", "Error reading $versionPath: ${e.message}")
                        continue
                    }
                }
                
                // Try to check pstore console logs for baseband_guard version information
                try {
                    android.util.Log.d("BBG_DEBUG", "Checking pstore console logs for baseband_guard version")
                    val pstoreFile = "/sys/fs/pstore/console-ramoops-0"
                    
                    try {
                        // Use head command to read from the beginning of pstore file (most reliable method)
                        android.util.Log.d("BBG_DEBUG", "Reading pstore from beginning with head command")
                        val headProcess = Runtime.getRuntime().exec(arrayOf("su", "-c", "head -n 1000 $pstoreFile"))
                        val headReader = java.io.BufferedReader(java.io.InputStreamReader(headProcess.inputStream))
                        val content = headReader.readText().trim()
                        headReader.close()
                        headProcess.waitFor()
                        
                        android.util.Log.d("BBG_DEBUG", "Pstore content length: ${content.length}")
                        android.util.Log.d("BBG_DEBUG", "Pstore content preview: ${content.take(200)}...")
                        
                        if (content.isNotEmpty()) {
                            // Look for baseband_guard version pattern like: baseband_guard version: a5083366
                            val versionPattern = Regex("baseband_guard\\s+version:\\s*([a-fA-F0-9]+)", RegexOption.IGNORE_CASE)
                            val match = versionPattern.find(content)
                            if (match != null) {
                                val version = match.groupValues[1]
                                android.util.Log.d("BBG_DEBUG", "Found BBG version in pstore: $version")
                                return version
                            }
                            
                            // Also check for general baseband_guard presence
                            if (content.contains("baseband_guard", ignoreCase = true)) {
                                android.util.Log.d("BBG_DEBUG", "Found baseband_guard in pstore but no version")
                                return "Installed"
                            }
                        }
                    } catch (e: Exception) {
                        android.util.Log.d("BBG_DEBUG", "Error reading pstore file $pstoreFile: ${e.message}")
                    }
                } catch (e: Exception) {
                    android.util.Log.d("BBG_DEBUG", "Error checking pstore: ${e.message}")
                }
                
                // Try to check dmesg for baseband_guard version information
                try {
                    android.util.Log.d("BBG_DEBUG", "Checking dmesg for baseband_guard version")
                    val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "dmesg | grep -i baseband_guard"))
                    val reader = java.io.BufferedReader(java.io.InputStreamReader(process.inputStream))
                    val dmesgOutput = reader.readText().trim()
                    reader.close()
                    process.waitFor()
                    
                    android.util.Log.d("BBG_DEBUG", "dmesg output: '$dmesgOutput'")
                    
                    if (dmesgOutput.isNotEmpty()) {
                        // Look for version patterns in dmesg output
                        val versionPatterns = listOf(
                            Regex("baseband_guard\\s+version:\\s*([a-fA-F0-9]+)", RegexOption.IGNORE_CASE),
                            Regex("baseband_guard.*?v?([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)", RegexOption.IGNORE_CASE),
                            Regex("baseband_guard.*?version.*?([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)", RegexOption.IGNORE_CASE),
                            Regex("BBG.*?v?([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)", RegexOption.IGNORE_CASE)
                        )
                        
                        for (pattern in versionPatterns) {
                            val match = pattern.find(dmesgOutput)
                            if (match != null) {
                                val version = match.groupValues[1]
                                android.util.Log.d("BBG_DEBUG", "Found version in dmesg: $version")
                                return version
                            }
                        }
                        
                        // If we found baseband_guard in dmesg but no version, return "Installed"
                        android.util.Log.d("BBG_DEBUG", "Found baseband_guard in dmesg but no version, returning Installed")
                        return "Installed"
                    }
                } catch (e: Exception) {
                    android.util.Log.d("BBG_DEBUG", "Error checking dmesg: ${e.message}")
                }
                
                // If version file not found but LSM is present, return "Installed"
                android.util.Log.d("BBG_DEBUG", "BBG in LSM but no version file found, returning Installed")
                return "Installed"
            } else {
                // Even if not in LSM, try checking pstore and dmesg as fallback
                
                // Check pstore first as fallback
                try {
                    android.util.Log.d("BBG_DEBUG", "BBG not in LSM, checking pstore as fallback")
                    val pstoreFile = "/sys/fs/pstore/console-ramoops-0"
                    
                    try {
                        // Use head command to read from the beginning of pstore file (most reliable method)
                        android.util.Log.d("BBG_DEBUG", "Reading fallback pstore from beginning with head command")
                        val headProcess = Runtime.getRuntime().exec(arrayOf("su", "-c", "head -n 1000 $pstoreFile"))
                        val headReader = java.io.BufferedReader(java.io.InputStreamReader(headProcess.inputStream))
                        val content = headReader.readText().trim()
                        headReader.close()
                        headProcess.waitFor()
                        
                        android.util.Log.d("BBG_DEBUG", "Fallback pstore content length: ${content.length}")
                        android.util.Log.d("BBG_DEBUG", "Fallback pstore content preview: ${content.take(200)}...")
                        
                        if (content.isNotEmpty()) {
                            // Look for baseband_guard version pattern like: baseband_guard version: a5083366
                            val versionPattern = Regex("baseband_guard\\s+version:\\s*([a-fA-F0-9]+)", RegexOption.IGNORE_CASE)
                            val match = versionPattern.find(content)
                            if (match != null) {
                                val version = match.groupValues[1]
                                android.util.Log.d("BBG_DEBUG", "Found BBG version in pstore fallback: $version")
                                return version
                            }
                            
                            // Also check for general baseband_guard presence
                            if (content.contains("baseband_guard", ignoreCase = true)) {
                                android.util.Log.d("BBG_DEBUG", "Found baseband_guard in pstore fallback but no version")
                                return "Installed"
                            }
                        }
                    } catch (e: Exception) {
                        android.util.Log.d("BBG_DEBUG", "Error reading pstore file $pstoreFile as fallback: ${e.message}")
                    }
                } catch (e: Exception) {
                    android.util.Log.d("BBG_DEBUG", "Error checking pstore fallback: ${e.message}")
                }
                
                // Then check dmesg as fallback
                try {
                    android.util.Log.d("BBG_DEBUG", "Checking dmesg as fallback")
                    val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "dmesg | grep -i baseband_guard"))
                    val reader = java.io.BufferedReader(java.io.InputStreamReader(process.inputStream))
                    val dmesgOutput = reader.readText().trim()
                    reader.close()
                    process.waitFor()
                    
                    android.util.Log.d("BBG_DEBUG", "dmesg fallback output: '$dmesgOutput'")
                    
                    if (dmesgOutput.isNotEmpty()) {
                        // Look for version patterns in dmesg output
                        val versionPatterns = listOf(
                            Regex("baseband_guard\\s+version:\\s*([a-fA-F0-9]+)", RegexOption.IGNORE_CASE),
                            Regex("baseband_guard.*?v?([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)", RegexOption.IGNORE_CASE),
                            Regex("baseband_guard.*?version.*?([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)", RegexOption.IGNORE_CASE),
                            Regex("BBG.*?v?([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)", RegexOption.IGNORE_CASE)
                        )
                        
                        for (pattern in versionPatterns) {
                            val match = pattern.find(dmesgOutput)
                            if (match != null) {
                                val version = match.groupValues[1]
                                android.util.Log.d("BBG_DEBUG", "Found version in dmesg fallback: $version")
                                return version
                            }
                        }
                        
                        // If we found baseband_guard in dmesg but no version, return "Installed"
                        android.util.Log.d("BBG_DEBUG", "Found baseband_guard in dmesg fallback but no version, returning Installed")
                        return "Installed"
                    }
                } catch (e: Exception) {
                    android.util.Log.d("BBG_DEBUG", "Error checking dmesg fallback: ${e.message}")
                }
                
                android.util.Log.d("BBG_DEBUG", "BBG not found in LSM list, pstore, or dmesg, returning Not installed")
                return "Not installed"
            }
        } catch (e: Exception) {
            android.util.Log.d("BBG_DEBUG", "Exception in getBasebandGuardVersion: ${e.message}")
            "Unknown"
        }
    }

    override fun onCleared() {
        super.onCleared()
        loadingJobs.forEach { it.cancel() }
        loadingJobs.clear()
    }
}