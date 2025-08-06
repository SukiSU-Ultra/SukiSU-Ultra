package com.sukisu.ultra.ui.util

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.util.Log
import android.widget.Toast
import com.dergoogler.mmrl.platform.Platform.Companion.context
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import androidx.core.content.edit
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.*

/**
 * SuSFS 配置管理器
 * 用于管理SuSFS相关的配置和命令执行
 */
object SuSFSManager {
    private const val PREFS_NAME = "susfs_config"
    private const val KEY_UNAME_VALUE = "uname_value"
    private const val KEY_BUILD_TIME_VALUE = "build_time_value"
    private const val KEY_AUTO_START_ENABLED = "auto_start_enabled"
    private const val KEY_SUS_PATHS = "sus_paths"
    private const val KEY_SUS_LOOP_PATHS = "sus_loop_paths"
    private const val KEY_SUS_MOUNTS = "sus_mounts"
    private const val KEY_TRY_UMOUNTS = "try_umounts"
    private const val KEY_ANDROID_DATA_PATH = "android_data_path"
    private const val KEY_SDCARD_PATH = "sdcard_path"
    private const val KEY_ENABLE_LOG = "enable_log"
    private const val KEY_EXECUTE_IN_POST_FS_DATA = "execute_in_post_fs_data"
    private const val KEY_KSTAT_CONFIGS = "kstat_configs"
    private const val KEY_ADD_KSTAT_PATHS = "add_kstat_paths"
    private const val KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS = "hide_sus_mounts_for_all_procs"
    private const val KEY_ENABLE_CLEANUP_RESIDUE = "enable_cleanup_residue"
    private const val KEY_ENABLE_HIDE_BL = "enable_hide_bl"
    private const val KEY_UMOUNT_FOR_ZYGOTE_ISO_SERVICE = "umount_for_zygote_iso_service"


    // 常量
    private const val SUSFS_BINARY_TARGET_NAME = "ksu_susfs"
    private const val DEFAULT_UNAME = "default"
    private const val DEFAULT_BUILD_TIME = "default"
    private const val MODULE_ID = "susfs_manager"
    private const val MODULE_PATH = "/data/adb/modules/$MODULE_ID"
    private const val MIN_VERSION_FOR_HIDE_MOUNT = "1.5.8"
    private const val MIN_VERSION_FOR_LOOP_PATH = "1.5.9"
    private const val BACKUP_FILE_EXTENSION = ".susfs_backup"
    private const val MEDIA_DATA_PATH = "/data/media/0/Android/data"

    data class SlotInfo(val slotName: String, val uname: String, val buildTime: String)
    data class CommandResult(val isSuccess: Boolean, val output: String, val errorOutput: String = "")
    data class EnabledFeature(
        val name: String,
        val isEnabled: Boolean,
        val statusText: String = if (isEnabled) context.getString(R.string.susfs_feature_enabled) else context.getString(R.string.susfs_feature_disabled),
        val canConfigure: Boolean = false
    )

    /**
     * 应用信息数据类
     */
    data class AppInfo(
        val packageName: String,
        val appName: String,
        val packageInfo: PackageInfo,
        val isSystemApp: Boolean
    )

    /**
     * 备份数据类
     */
    data class BackupData(
        val version: String,
        val timestamp: Long,
        val deviceInfo: String,
        val configurations: Map<String, Any>
    ) {
        fun toJson(): String {
            val jsonObject = JSONObject().apply {
                put("version", version)
                put("timestamp", timestamp)
                put("deviceInfo", deviceInfo)
                put("configurations", JSONObject(configurations))
            }
            return jsonObject.toString(2)
        }

        companion object {
            fun fromJson(jsonString: String): BackupData? {
                return try {
                    val jsonObject = JSONObject(jsonString)
                    val configurationsJson = jsonObject.getJSONObject("configurations")
                    val configurations = mutableMapOf<String, Any>()

                    configurationsJson.keys().forEach { key ->
                        val value = configurationsJson.get(key)
                        configurations[key] = when (value) {
                            is org.json.JSONArray -> {
                                val set = mutableSetOf<String>()
                                for (i in 0 until value.length()) {
                                    set.add(value.getString(i))
                                }
                                set
                            }
                            else -> value
                        }
                    }

                    BackupData(
                        version = jsonObject.getString("version"),
                        timestamp = jsonObject.getLong("timestamp"),
                        deviceInfo = jsonObject.getString("deviceInfo"),
                        configurations = configurations
                    )
                } catch (e: Exception) {
                    e.printStackTrace()
                    null
                }
            }
        }
    }

    /**
     * 模块配置数据类
     */
    data class ModuleConfig(
        val targetPath: String,
        val unameValue: String,
        val buildTimeValue: String,
        val executeInPostFsData: Boolean,
        val susPaths: Set<String>,
        val susLoopPaths: Set<String>,
        val susMounts: Set<String>,
        val tryUmounts: Set<String>,
        val androidDataPath: String,
        val sdcardPath: String,
        val enableLog: Boolean,
        val kstatConfigs: Set<String>,
        val addKstatPaths: Set<String>,
        val hideSusMountsForAllProcs: Boolean,
        val support158: Boolean,
        val enableHideBl: Boolean,
        val enableCleanupResidue: Boolean,
        val umountForZygoteIsoService: Boolean
    ) {
        /**
         * 检查是否有需要自启动的配置
         */
        fun hasAutoStartConfig(): Boolean {
            return unameValue != DEFAULT_UNAME ||
                    buildTimeValue != DEFAULT_BUILD_TIME ||
                    susPaths.isNotEmpty() ||
                    susLoopPaths.isNotEmpty() ||
                    susMounts.isNotEmpty() ||
                    tryUmounts.isNotEmpty() ||
                    kstatConfigs.isNotEmpty() ||
                    addKstatPaths.isNotEmpty()
        }
    }

    // 基础工具方法
    private fun getPrefs(context: Context): SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun getSuSFSVersionUse(): String = try {
        getSuSFSVersion()
    } catch (_: Exception) { MIN_VERSION_FOR_HIDE_MOUNT }

    private fun getSuSFSBinaryName(): String = "${SUSFS_BINARY_TARGET_NAME}_${getSuSFSVersionUse().removePrefix("v")}"

    private fun getSuSFSTargetPath(): String = "/data/adb/ksu/bin/$SUSFS_BINARY_TARGET_NAME"

    private fun runCmd(shell: Shell, cmd: String): String {
        return shell.newJob()
            .add(cmd)
            .to(mutableListOf<String>(), null)
            .exec().out
            .joinToString("\n")
    }

    private fun runCmdWithResult(cmd: String): CommandResult {
        val result = Shell.getShell().newJob().add(cmd).exec()
        return CommandResult(result.isSuccess, result.out.joinToString("\n"), result.err.joinToString("\n"))
    }

    /**
     * 版本比较方法
     */
    private fun compareVersions(version1: String, version2: String): Int {
        val v1Parts = version1.removePrefix("v").split(".").map { it.toIntOrNull() ?: 0 }
        val v2Parts = version2.removePrefix("v").split(".").map { it.toIntOrNull() ?: 0 }

        val maxLength = maxOf(v1Parts.size, v2Parts.size)

        for (i in 0 until maxLength) {
            val v1Part = v1Parts.getOrNull(i) ?: 0
            val v2Part = v2Parts.getOrNull(i) ?: 0

            when {
                v1Part > v2Part -> return 1
                v1Part < v2Part -> return -1
            }
        }
        return 0
    }

    /**
     * 检查是否支持设置sdcard路径等功能（1.5.8+）
     */
    fun isSusVersion158(): Boolean {
        return try {
            val currentVersion = getSuSFSVersion()
            compareVersions(currentVersion, MIN_VERSION_FOR_HIDE_MOUNT) >= 0
        } catch (_: Exception) {
            true
        }
    }

    /**
     * 检查是否支持循环路径功能（1.5.9+）
     */
    fun isSusVersion159(): Boolean {
        return try {
            val currentVersion = getSuSFSVersion()
            compareVersions(currentVersion, MIN_VERSION_FOR_LOOP_PATH) >= 0
        } catch (_: Exception) {
            true
        }
    }

    /**
     * 获取当前模块配置
     */
    private fun getCurrentModuleConfig(context: Context): ModuleConfig {
        return ModuleConfig(
            targetPath = getSuSFSTargetPath(),
            unameValue = getUnameValue(context),
            buildTimeValue = getBuildTimeValue(context),
            executeInPostFsData = getExecuteInPostFsData(context),
            susPaths = getSusPaths(context),
            susLoopPaths = getSusLoopPaths(context),
            susMounts = getSusMounts(context),
            tryUmounts = getTryUmounts(context),
            androidDataPath = getAndroidDataPath(context),
            sdcardPath = getSdcardPath(context),
            enableLog = getEnableLogState(context),
            kstatConfigs = getKstatConfigs(context),
            addKstatPaths = getAddKstatPaths(context),
            hideSusMountsForAllProcs = getHideSusMountsForAllProcs(context),
            support158 = isSusVersion158(),
            enableHideBl = getEnableHideBl(context),
            enableCleanupResidue = getEnableCleanupResidue(context),
            umountForZygoteIsoService = getUmountForZygoteIsoService(context),
        )
    }

    // 配置存取方法
    fun saveUnameValue(context: Context, value: String) =
        getPrefs(context).edit { putString(KEY_UNAME_VALUE, value) }

    fun getUnameValue(context: Context): String =
        getPrefs(context).getString(KEY_UNAME_VALUE, DEFAULT_UNAME) ?: DEFAULT_UNAME

    fun saveBuildTimeValue(context: Context, value: String) =
        getPrefs(context).edit { putString(KEY_BUILD_TIME_VALUE, value)}

    fun getBuildTimeValue(context: Context): String =
        getPrefs(context).getString(KEY_BUILD_TIME_VALUE, DEFAULT_BUILD_TIME) ?: DEFAULT_BUILD_TIME

    fun setAutoStartEnabled(context: Context, enabled: Boolean) =
        getPrefs(context).edit { putBoolean(KEY_AUTO_START_ENABLED, enabled) }

    fun isAutoStartEnabled(context: Context): Boolean =
        getPrefs(context).getBoolean(KEY_AUTO_START_ENABLED, false)

    fun saveEnableLogState(context: Context, enabled: Boolean) =
        getPrefs(context).edit { putBoolean(KEY_ENABLE_LOG, enabled) }

    fun getEnableLogState(context: Context): Boolean =
        getPrefs(context).getBoolean(KEY_ENABLE_LOG, false)

    fun getExecuteInPostFsData(context: Context): Boolean =
        getPrefs(context).getBoolean(KEY_EXECUTE_IN_POST_FS_DATA, false)

    fun saveExecuteInPostFsData(context: Context, executeInPostFsData: Boolean) {
        getPrefs(context).edit { putBoolean(KEY_EXECUTE_IN_POST_FS_DATA, executeInPostFsData) }
        if (isAutoStartEnabled(context)) {
            kotlinx.coroutines.CoroutineScope(Dispatchers.Default).launch {
                updateMagiskModule(context)
            }
        }
    }

    // SUS挂载隐藏控制
    fun saveHideSusMountsForAllProcs(context: Context, hideForAll: Boolean) =
        getPrefs(context).edit { putBoolean(KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS, hideForAll) }

    fun getHideSusMountsForAllProcs(context: Context): Boolean =
        getPrefs(context).getBoolean(KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS, true)

    // 隐藏BL锁脚本
    fun saveEnableHideBl(context: Context, enabled: Boolean) =
        getPrefs(context).edit { putBoolean(KEY_ENABLE_HIDE_BL, enabled) }

    fun getEnableHideBl(context: Context): Boolean =
        getPrefs(context).getBoolean(KEY_ENABLE_HIDE_BL, true)


    // 清理残留配置
    fun saveEnableCleanupResidue(context: Context, enabled: Boolean) =
        getPrefs(context).edit { putBoolean(KEY_ENABLE_CLEANUP_RESIDUE, enabled) }

    fun getEnableCleanupResidue(context: Context): Boolean =
        getPrefs(context).getBoolean(KEY_ENABLE_CLEANUP_RESIDUE, false)

    // Zygote隔离服务卸载控制
    fun saveUmountForZygoteIsoService(context: Context, enabled: Boolean) =
        getPrefs(context).edit { putBoolean(KEY_UMOUNT_FOR_ZYGOTE_ISO_SERVICE, enabled) }

    fun getUmountForZygoteIsoService(context: Context): Boolean =
        getPrefs(context).getBoolean(KEY_UMOUNT_FOR_ZYGOTE_ISO_SERVICE, false)


    // 路径和配置管理
    fun saveSusPaths(context: Context, paths: Set<String>) =
        getPrefs(context).edit { putStringSet(KEY_SUS_PATHS, paths) }

    fun getSusPaths(context: Context): Set<String> =
        getPrefs(context).getStringSet(KEY_SUS_PATHS, emptySet()) ?: emptySet()

    // 循环路径管理
    fun saveSusLoopPaths(context: Context, paths: Set<String>) =
        getPrefs(context).edit { putStringSet(KEY_SUS_LOOP_PATHS, paths) }

    fun getSusLoopPaths(context: Context): Set<String> =
        getPrefs(context).getStringSet(KEY_SUS_LOOP_PATHS, emptySet()) ?: emptySet()

    fun saveSusMounts(context: Context, mounts: Set<String>) =
        getPrefs(context).edit { putStringSet(KEY_SUS_MOUNTS, mounts) }

    fun getSusMounts(context: Context): Set<String> =
        getPrefs(context).getStringSet(KEY_SUS_MOUNTS, emptySet()) ?: emptySet()

    fun saveTryUmounts(context: Context, umounts: Set<String>) =
        getPrefs(context).edit { putStringSet(KEY_TRY_UMOUNTS, umounts) }

    fun getTryUmounts(context: Context): Set<String> =
        getPrefs(context).getStringSet(KEY_TRY_UMOUNTS, emptySet()) ?: emptySet()

    fun saveKstatConfigs(context: Context, configs: Set<String>) =
        getPrefs(context).edit { putStringSet(KEY_KSTAT_CONFIGS, configs) }

    fun getKstatConfigs(context: Context): Set<String> =
        getPrefs(context).getStringSet(KEY_KSTAT_CONFIGS, emptySet()) ?: emptySet()

    fun saveAddKstatPaths(context: Context, paths: Set<String>) =
        getPrefs(context).edit { putStringSet(KEY_ADD_KSTAT_PATHS, paths) }

    fun getAddKstatPaths(context: Context): Set<String> =
        getPrefs(context).getStringSet(KEY_ADD_KSTAT_PATHS, emptySet()) ?: emptySet()

    @SuppressLint("SdCardPath")
    fun saveAndroidDataPath(context: Context, path: String) =
        getPrefs(context).edit { putString(KEY_ANDROID_DATA_PATH, path) }

    @SuppressLint("SdCardPath")
    fun getAndroidDataPath(context: Context): String =
        getPrefs(context).getString(KEY_ANDROID_DATA_PATH, "/sdcard/Android/data") ?: "/sdcard/Android/data"

    @SuppressLint("SdCardPath")
    fun saveSdcardPath(context: Context, path: String) =
        getPrefs(context).edit { putString(KEY_SDCARD_PATH, path) }

    @SuppressLint("SdCardPath")
    fun getSdcardPath(context: Context): String =
        getPrefs(context).getString(KEY_SDCARD_PATH, "/sdcard") ?: "/sdcard"

    /**
     * 获取已安装的应用列表
     */
    @SuppressLint("QueryPermissionsNeeded")
    suspend fun getInstalledApps(): List<AppInfo> = withContext(Dispatchers.IO) {
        try {
            val allApps = mutableMapOf<String, AppInfo>()

            // 从SuperUser中获取应用
            SuperUserViewModel.apps.forEach { superUserApp ->
                try {
                    val isSystemApp = superUserApp.packageInfo.applicationInfo?.let {
                        (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                    } ?: false
                    if (!isSystemApp) {
                        allApps[superUserApp.packageName] = AppInfo(
                            packageName = superUserApp.packageName,
                            appName = superUserApp.label,
                            packageInfo = superUserApp.packageInfo,
                            isSystemApp = false
                        )
                    }
                } catch (_: Exception) {
                }
            }

            // 检查每个应用的数据目录是否存在
            val filteredApps = allApps.values.map { appInfo ->
                async(Dispatchers.IO) {
                    val dataPath = "$MEDIA_DATA_PATH/${appInfo.packageName}"
                    val exists = try {
                        val shell = getRootShell()
                        val outputList = mutableListOf<String>()
                        val errorList = mutableListOf<String>()

                        val result = shell.newJob()
                            .add("[ -d \"$dataPath\" ] && echo 'exists' || echo 'not_exists'")
                            .to(outputList, errorList)
                            .exec()

                        result.isSuccess && outputList.isNotEmpty() && outputList[0].trim() == "exists"
                    } catch (e: Exception) {
                        Log.w("SuSFSManager", "Failed to check directory for ${appInfo.packageName}: ${e.message}")
                        false
                    }
                    if (exists) appInfo else null
                }
            }.awaitAll().filterNotNull()

            filteredApps.sortedBy { it.appName }
        } catch (e: Exception) {
            e.printStackTrace()
            emptyList()
        }
    }


    /**
     * 快捷添加应用路径
     */
    suspend fun addAppPaths(context: Context, packageName: String): Boolean {
        val androidDataPath = getAndroidDataPath(context)
        getSdcardPath(context)

        val path1 = "$androidDataPath/$packageName"
        val path2 = "$MEDIA_DATA_PATH/$packageName"

        var successCount = 0
        var totalCount = 0

        // 添加第一个路径
        totalCount++
        if (addSusPath(context, path1)) {
            successCount++
        }

        // 添加第二个路径
        totalCount++
        if (addSusPath(context, path2)) {
            successCount++
        }

        val success = successCount > 0
        if (success) {
            ""
        } else {
            ""
        }

        return success
    }

    // 获取所有配置的Map
    private fun getAllConfigurations(context: Context): Map<String, Any> {
        return mapOf(
            KEY_UNAME_VALUE to getUnameValue(context),
            KEY_BUILD_TIME_VALUE to getBuildTimeValue(context),
            KEY_AUTO_START_ENABLED to isAutoStartEnabled(context),
            KEY_SUS_PATHS to getSusPaths(context),
            KEY_SUS_LOOP_PATHS to getSusLoopPaths(context),
            KEY_SUS_MOUNTS to getSusMounts(context),
            KEY_TRY_UMOUNTS to getTryUmounts(context),
            KEY_ANDROID_DATA_PATH to getAndroidDataPath(context),
            KEY_SDCARD_PATH to getSdcardPath(context),
            KEY_ENABLE_LOG to getEnableLogState(context),
            KEY_EXECUTE_IN_POST_FS_DATA to getExecuteInPostFsData(context),
            KEY_KSTAT_CONFIGS to getKstatConfigs(context),
            KEY_ADD_KSTAT_PATHS to getAddKstatPaths(context),
            KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS to getHideSusMountsForAllProcs(context),
            KEY_ENABLE_HIDE_BL to getEnableHideBl(context),
            KEY_ENABLE_CLEANUP_RESIDUE to getEnableCleanupResidue(context),
            KEY_UMOUNT_FOR_ZYGOTE_ISO_SERVICE to getUmountForZygoteIsoService(context),
        )
    }

    //生成备份文件名
    private fun generateBackupFileName(): String {
        val dateFormat = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault())
        val timestamp = dateFormat.format(Date())
        return "SuSFS_Config_$timestamp$BACKUP_FILE_EXTENSION"
    }

    //  获取设备信息
    private fun getDeviceInfo(): String {
        return try {
            "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL} (${android.os.Build.VERSION.RELEASE})"
        } catch (_: Exception) {
            "Unknown Device"
        }
    }

    // 创建配置备份
    suspend fun createBackup(context: Context, backupFilePath: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val configurations = getAllConfigurations(context)
            val backupData = BackupData(
                version = getSuSFSVersion(),
                timestamp = System.currentTimeMillis(),
                deviceInfo = getDeviceInfo(),
                configurations = configurations
            )

            val backupFile = File(backupFilePath)
            backupFile.parentFile?.mkdirs()

            backupFile.writeText(backupData.toJson())

            showToast(context, context.getString(R.string.susfs_backup_success, backupFile.name))
            true
        } catch (e: Exception) {
            e.printStackTrace()
            showToast(context, context.getString(R.string.susfs_backup_failed, e.message ?: "Unknown error"))
            false
        }
    }

    //从备份文件还原配置
    suspend fun restoreFromBackup(context: Context, backupFilePath: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val backupFile = File(backupFilePath)
            if (!backupFile.exists()) {
                showToast(context, context.getString(R.string.susfs_backup_file_not_found))
                return@withContext false
            }

            val backupContent = backupFile.readText()
            val backupData = BackupData.fromJson(backupContent)

            if (backupData == null) {
                showToast(context, context.getString(R.string.susfs_backup_invalid_format))
                return@withContext false
            }

            // 检查备份版本兼容性
            if (backupData.version != getSuSFSVersion()) {
                showToast(context, context.getString(R.string.susfs_backup_version_mismatch))
            }

            // 还原所有配置
            restoreConfigurations(context, backupData.configurations)

            // 如果自启动已启用，更新模块
            if (isAutoStartEnabled(context)) {
                updateMagiskModule(context)
            }

            val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
            val backupDate = dateFormat.format(Date(backupData.timestamp))

            showToast(context, context.getString(R.string.susfs_restore_success, backupDate, backupData.deviceInfo))
            true
        } catch (e: Exception) {
            e.printStackTrace()
            showToast(context, context.getString(R.string.susfs_restore_failed, e.message ?: "Unknown error"))
            false
        }
    }


    // 还原配置到SharedPreferences
    private fun restoreConfigurations(context: Context, configurations: Map<String, Any>) {
        val prefs = getPrefs(context)
        prefs.edit {
            configurations.forEach { (key, value) ->
                when (value) {
                    is String -> putString(key, value)
                    is Boolean -> putBoolean(key, value)
                    is Set<*> -> {
                        @Suppress("UNCHECKED_CAST")
                        putStringSet(key, value as Set<String>)
                    }
                    is Int -> putInt(key, value)
                    is Long -> putLong(key, value)
                    is Float -> putFloat(key, value)
                }
            }
        }
    }

    // 验证备份文件
    suspend fun validateBackupFile(backupFilePath: String): BackupData? = withContext(Dispatchers.IO) {
        try {
            val backupFile = File(backupFilePath)
            if (!backupFile.exists()) {
                return@withContext null
            }

            val backupContent = backupFile.readText()
            BackupData.fromJson(backupContent)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    // 获取备份文件路径
    fun getDefaultBackupFileName(): String {
        return generateBackupFileName()
    }

    // 槽位信息获取
    suspend fun getCurrentSlotInfo(): List<SlotInfo> = withContext(Dispatchers.IO) {
        try {
            val slotInfoList = mutableListOf<SlotInfo>()
            val shell = Shell.getShell()

            listOf("boot_a", "boot_b").forEach { slot ->
                val unameCmd =
                    "strings -n 20 /dev/block/by-name/$slot | awk '/Linux version/ && ++c==2 {print $3; exit}'"
                val buildTimeCmd = "strings -n 20 /dev/block/by-name/$slot | sed -n '/Linux version.*#/{s/.*#/#/p;q}'"

                val uname = runCmd(shell, unameCmd).trim()
                val buildTime = runCmd(shell, buildTimeCmd).trim()

                if (uname.isNotEmpty() && buildTime.isNotEmpty()) {
                    slotInfoList.add(SlotInfo(slot, uname.ifEmpty { "unknown" }, buildTime.ifEmpty { "unknown" }))
                }
            }

            slotInfoList
        } catch (e: Exception) {
            e.printStackTrace()
            emptyList()
        }
    }

    suspend fun getCurrentActiveSlot(): String = withContext(Dispatchers.IO) {
        try {
            val shell = Shell.getShell()
            val suffix = runCmd(shell, "getprop ro.boot.slot_suffix").trim()
            when (suffix) {
                "_a" -> "boot_a"
                "_b" -> "boot_b"
                else -> "unknown"
            }
        } catch (_: Exception) {
            "unknown"
        }
    }

    // 二进制文件管理
    private suspend fun copyBinaryFromAssets(context: Context): String? = withContext(Dispatchers.IO) {
        try {
            val binaryName = getSuSFSBinaryName()
            val targetPath = getSuSFSTargetPath()
            val tempFile = File(context.cacheDir, binaryName)

            context.assets.open(binaryName).use { input ->
                FileOutputStream(tempFile).use { output ->
                    input.copyTo(output)
                }
            }

            val success = runCmdWithResult("cp '${tempFile.absolutePath}' '$targetPath' && chmod 755 '$targetPath'").isSuccess
            tempFile.delete()

            if (success && runCmdWithResult("test -f '$targetPath'").isSuccess) targetPath else null
        } catch (e: IOException) {
            e.printStackTrace()
            null
        }
    }

    fun isBinaryAvailable(context: Context): Boolean = try {
        context.assets.open(getSuSFSBinaryName()).use { true }
    } catch (_: IOException) { false }

    // 命令执行
    private suspend fun executeSusfsCommand(context: Context, command: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val binaryPath = copyBinaryFromAssets(context) ?: run {
                showToast(context, context.getString(R.string.susfs_binary_not_found))
                return@withContext false
            }

            val result = runCmdWithResult("$binaryPath $command")

            if (!result.isSuccess) {
                showToast(context, "${context.getString(R.string.susfs_command_failed)}\n${result.output}\n${result.errorOutput}")
            }

            result.isSuccess
        } catch (e: Exception) {
            e.printStackTrace()
            showToast(context, context.getString(R.string.susfs_command_error, e.message ?: "Unknown error"))
            false
        }
    }

    private suspend fun executeSusfsCommandWithOutput(context: Context, command: String): CommandResult = withContext(Dispatchers.IO) {
        try {
            val binaryPath = copyBinaryFromAssets(context) ?: return@withContext CommandResult(
                false, "", context.getString(R.string.susfs_binary_not_found)
            )
            runCmdWithResult("$binaryPath $command")
        } catch (e: Exception) {
            e.printStackTrace()
            CommandResult(false, "", e.message ?: "Unknown error")
        }
    }

    private suspend fun showToast(context: Context, message: String) = withContext(Dispatchers.Main) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
    }

    /**
     * 模块管理
     */
    private suspend fun updateMagiskModule(context: Context): Boolean {
        return removeMagiskModule() && createMagiskModule(context)
    }

    /**
     * 模块创建方法
     */
    private suspend fun createMagiskModule(context: Context): Boolean = withContext(Dispatchers.IO) {
        try {
            val config = getCurrentModuleConfig(context)

            // 创建模块目录
            if (!runCmdWithResult("mkdir -p $MODULE_PATH").isSuccess) return@withContext false

            // 创建module.prop
            val moduleProp = ScriptGenerator.generateModuleProp(MODULE_ID)
            if (!runCmdWithResult("cat > $MODULE_PATH/module.prop << 'EOF'\n$moduleProp\nEOF").isSuccess) return@withContext false

            // 生成并创建所有脚本文件
            val scripts = ScriptGenerator.generateAllScripts(config)

            scripts.all { (filename, content) ->
                runCmdWithResult("cat > $MODULE_PATH/$filename << 'EOF'\n$content\nEOF").isSuccess &&
                        runCmdWithResult("chmod 755 $MODULE_PATH/$filename").isSuccess
            }
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    private suspend fun removeMagiskModule(): Boolean = withContext(Dispatchers.IO) {
        try {
            runCmdWithResult("rm -rf $MODULE_PATH").isSuccess
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    // 功能状态获取
    suspend fun getEnabledFeatures(context: Context): List<EnabledFeature> = withContext(Dispatchers.IO) {
        try {
            val status = Natives.getSusfsFeatureStatus()
            if (status != null) {
                parseEnabledFeaturesFromStatus(context, status)
            } else {
                getDefaultDisabledFeatures(context)
            }
        } catch (e: Exception) {
            e.printStackTrace()
            getDefaultDisabledFeatures(context)
        }
    }

    private fun getDefaultDisabledFeatures(context: Context): List<EnabledFeature> {
        val defaultFeatures = listOf(
            "sus_path_feature_label" to context.getString(R.string.sus_path_feature_label),
            "sus_loop_path_feature_label" to context.getString(R.string.sus_loop_path_feature_label),
            "sus_mount_feature_label" to context.getString(R.string.sus_mount_feature_label),
            "try_umount_feature_label" to context.getString(R.string.try_umount_feature_label),
            "spoof_uname_feature_label" to context.getString(R.string.spoof_uname_feature_label),
            "spoof_cmdline_feature_label" to context.getString(R.string.spoof_cmdline_feature_label),
            "open_redirect_feature_label" to context.getString(R.string.open_redirect_feature_label),
            "enable_log_feature_label" to context.getString(R.string.enable_log_feature_label),
            "auto_default_mount_feature_label" to context.getString(R.string.auto_default_mount_feature_label),
            "auto_bind_mount_feature_label" to context.getString(R.string.auto_bind_mount_feature_label),
            "auto_try_umount_bind_feature_label" to context.getString(R.string.auto_try_umount_bind_feature_label),
            "hide_symbols_feature_label" to context.getString(R.string.hide_symbols_feature_label),
            "sus_kstat_feature_label" to context.getString(R.string.sus_kstat_feature_label),
            "magic_mount_feature_label" to context.getString(R.string.magic_mount_feature_label),
            "sus_su_feature_label" to context.getString(R.string.sus_su_feature_label)
        )

        return defaultFeatures.map { (_, displayName) ->
            EnabledFeature(
                name = displayName,
                isEnabled = false,
                statusText = context.getString(R.string.susfs_feature_disabled),
                canConfigure = displayName == context.getString(R.string.enable_log_feature_label)
            )
        }.sortedBy { it.name }
    }

    private fun parseEnabledFeaturesFromStatus(context: Context, status: Natives.SusfsFeatureStatus): List<EnabledFeature> {
        val featureList = listOf(
            Triple("status_sus_path", context.getString(R.string.sus_path_feature_label), status.statusSusPath),
            Triple("status_sus_mount", context.getString(R.string.sus_mount_feature_label), status.statusSusMount),
            Triple("status_try_umount", context.getString(R.string.try_umount_feature_label), status.statusTryUmount),
            Triple("status_spoof_uname", context.getString(R.string.spoof_uname_feature_label), status.statusSpoofUname),
            Triple("status_spoof_cmdline", context.getString(R.string.spoof_cmdline_feature_label), status.statusSpoofCmdline),
            Triple("status_open_redirect", context.getString(R.string.open_redirect_feature_label), status.statusOpenRedirect),
            Triple("status_enable_log", context.getString(R.string.enable_log_feature_label), status.statusEnableLog),
            Triple("status_auto_default_mount", context.getString(R.string.auto_default_mount_feature_label), status.statusAutoDefaultMount),
            Triple("status_auto_bind_mount", context.getString(R.string.auto_bind_mount_feature_label), status.statusAutoBindMount),
            Triple("status_auto_try_umount_bind", context.getString(R.string.auto_try_umount_bind_feature_label), status.statusAutoTryUmountBind),
            Triple("status_hide_symbols", context.getString(R.string.hide_symbols_feature_label), status.statusHideSymbols),
            Triple("status_sus_kstat", context.getString(R.string.sus_kstat_feature_label), status.statusSusKstat),
            Triple("status_magic_mount", context.getString(R.string.magic_mount_feature_label), status.statusMagicMount),
            Triple("status_sus_su", context.getString(R.string.sus_su_feature_label), status.statusSusSu)
        )

        return featureList.map { (id, displayName, isEnabled) ->
            val statusText = if (isEnabled) context.getString(R.string.susfs_feature_enabled) else context.getString(R.string.susfs_feature_disabled)
            val canConfigure = id == "status_enable_log"
            EnabledFeature(displayName, isEnabled, statusText, canConfigure)
        }.sortedBy { it.name }
    }

    // sus日志开关
    suspend fun setEnableLog(context: Context, enabled: Boolean): Boolean {
        val success = executeSusfsCommand(context, "enable_log ${if (enabled) 1 else 0}")
        if (success) {
            saveEnableLogState(context, enabled)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
            showToast(context, if (enabled) context.getString(R.string.susfs_log_enabled) else context.getString(R.string.susfs_log_disabled))
        }
        return success
    }

    // SUS挂载隐藏控制
    suspend fun setHideSusMountsForAllProcs(context: Context, hideForAll: Boolean): Boolean {
        if (!isSusVersion158()) {
            return false
        }

        val success = executeSusfsCommand(context, "hide_sus_mnts_for_all_procs ${if (hideForAll) 1 else 0}")
        if (success) {
            saveHideSusMountsForAllProcs(context, hideForAll)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
            showToast(context, if (hideForAll)
                context.getString(R.string.susfs_hide_mounts_all_enabled)
            else
                context.getString(R.string.susfs_hide_mounts_all_disabled)
            )
        }
        return success
    }

    // uname和构建时间
    @SuppressLint("StringFormatMatches")
    suspend fun setUname(context: Context, unameValue: String, buildTimeValue: String): Boolean {
        val success = executeSusfsCommand(context, "set_uname '$unameValue' '$buildTimeValue'")
        if (success) {
            saveUnameValue(context, unameValue)
            saveBuildTimeValue(context, buildTimeValue)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
            showToast(context, context.getString(R.string.susfs_uname_set_success, unameValue, buildTimeValue))
        }
        return success
    }

    // 添加SUS路径
    @SuppressLint("StringFormatInvalid")
    suspend fun addSusPath(context: Context, path: String): Boolean {
        // 如果是1.5.8版本，先设置路径配置
        if (isSusVersion158()) {
            // 获取当前配置的路径，如果没有配置则使用默认值
            val androidDataPath = getAndroidDataPath(context)
            val sdcardPath = getSdcardPath(context)

            // 先设置Android Data路径
            val androidDataSuccess = executeSusfsCommand(context, "set_android_data_root_path '$androidDataPath'")
            if (androidDataSuccess) {
                showToast(context, context.getString(R.string.susfs_android_data_path_set, androidDataPath))
            }

            // 再设置SD卡路径
            val sdcardSuccess = executeSusfsCommand(context, "set_sdcard_root_path '$sdcardPath'")
            if (sdcardSuccess) {
                showToast(context, context.getString(R.string.susfs_sdcard_path_set, sdcardPath))
            }

            // 如果路径设置失败，记录但不阻止继续执行
            if (!androidDataSuccess || !sdcardSuccess) {
                showToast(context, context.getString(R.string.susfs_path_setup_warning))
            }
        }

        // 执行添加SUS路径命令
        val result = executeSusfsCommandWithOutput(context, "add_sus_path '$path'")
        val isActuallySuccessful = result.isSuccess && !result.output.contains("not found, skip adding")

        if (isActuallySuccessful) {
            saveSusPaths(context, getSusPaths(context) + path)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
            showToast(context, context.getString(R.string.susfs_sus_path_added_success, path))
        } else {
            val errorMessage = if (result.output.contains("not found, skip adding")) {
                context.getString(R.string.susfs_path_not_found_error, path)
            } else {
                "${context.getString(R.string.susfs_command_failed)}\n${result.output}\n${result.errorOutput}"
            }
            showToast(context, errorMessage)
        }
        return isActuallySuccessful
    }

    suspend fun removeSusPath(context: Context, path: String): Boolean {
        saveSusPaths(context, getSusPaths(context) - path)
        if (isAutoStartEnabled(context)) updateMagiskModule(context)
        showToast(context, "SUS path removed: $path")
        return true
    }

    // 编辑SUS路径
    suspend fun editSusPath(context: Context, oldPath: String, newPath: String): Boolean {
        return try {
            val currentPaths = getSusPaths(context).toMutableSet()
            if (!currentPaths.remove(oldPath)) {
                showToast(context, "Original path not found: $oldPath")
                return false
            }

            saveSusPaths(context, currentPaths)

            val success = addSusPath(context, newPath)

            if (success) {
                showToast(context, "SUS path updated: $oldPath -> $newPath")
                return true
            } else {
                // 如果添加新路径失败，恢复旧路径
                currentPaths.add(oldPath)
                saveSusPaths(context, currentPaths)
                if (isAutoStartEnabled(context)) updateMagiskModule(context)
                showToast(context, "Failed to update path, reverted to original")
                return false
            }
        } catch (e: Exception) {
            e.printStackTrace()
            showToast(context, "Error updating SUS path: ${e.message}")
            false
        }
    }

    // 循环路径相关方法
    @SuppressLint("SdCardPath")
    private fun isValidLoopPath(path: String): Boolean {
        return !path.startsWith("/storage/") && !path.startsWith("/sdcard/")
    }

    @SuppressLint("StringFormatInvalid")
    suspend fun addSusLoopPath(context: Context, path: String): Boolean {
        // 检查路径是否有效
        if (!isValidLoopPath(path)) {
            showToast(context, context.getString(R.string.susfs_loop_path_invalid_location))
            return false
        }

        // 执行添加循环路径命令
        val result = executeSusfsCommandWithOutput(context, "add_sus_path_loop '$path'")
        val isActuallySuccessful = result.isSuccess && !result.output.contains("not found, skip adding")

        if (isActuallySuccessful) {
            saveSusLoopPaths(context, getSusLoopPaths(context) + path)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
            showToast(context, context.getString(R.string.susfs_loop_path_added_success, path))
        } else {
            val errorMessage = if (result.output.contains("not found, skip adding")) {
                context.getString(R.string.susfs_path_not_found_error, path)
            } else {
                "${context.getString(R.string.susfs_command_failed)}\n${result.output}\n${result.errorOutput}"
            }
            showToast(context, errorMessage)
        }
        return isActuallySuccessful
    }

    suspend fun removeSusLoopPath(context: Context, path: String): Boolean {
        saveSusLoopPaths(context, getSusLoopPaths(context) - path)
        if (isAutoStartEnabled(context)) updateMagiskModule(context)
        showToast(context, context.getString(R.string.susfs_loop_path_removed, path))
        return true
    }

    // 编辑循环路径
    suspend fun editSusLoopPath(context: Context, oldPath: String, newPath: String): Boolean {
        // 检查新路径是否有效
        if (!isValidLoopPath(newPath)) {
            showToast(context, context.getString(R.string.susfs_loop_path_invalid_location))
            return false
        }

        return try {
            val currentPaths = getSusLoopPaths(context).toMutableSet()
            if (!currentPaths.remove(oldPath)) {
                showToast(context, "Original loop path not found: $oldPath")
                return false
            }

            saveSusLoopPaths(context, currentPaths)

            val success = addSusLoopPath(context, newPath)

            if (success) {
                showToast(context, context.getString(R.string.susfs_loop_path_updated, oldPath, newPath))
                return true
            } else {
                // 如果添加新路径失败，恢复旧路径
                currentPaths.add(oldPath)
                saveSusLoopPaths(context, currentPaths)
                if (isAutoStartEnabled(context)) updateMagiskModule(context)
                showToast(context, "Failed to update loop path, reverted to original")
                return false
            }
        } catch (e: Exception) {
            e.printStackTrace()
            showToast(context, "Error updating SUS loop path: ${e.message}")
            false
        }
    }

    // 添加SUS挂载
    suspend fun addSusMount(context: Context, mount: String): Boolean {
        val success = executeSusfsCommand(context, "add_sus_mount '$mount'")
        if (success) {
            saveSusMounts(context, getSusMounts(context) + mount)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
        }
        return success
    }

    suspend fun removeSusMount(context: Context, mount: String): Boolean {
        saveSusMounts(context, getSusMounts(context) - mount)
        if (isAutoStartEnabled(context)) updateMagiskModule(context)
        showToast(context, "Removed SUS mount: $mount")
        return true
    }

    // 编辑SUS挂载
    suspend fun editSusMount(context: Context, oldMount: String, newMount: String): Boolean {
        return try {
            val currentMounts = getSusMounts(context).toMutableSet()
            if (!currentMounts.remove(oldMount)) {
                showToast(context, "Original mount not found: $oldMount")
                return false
            }

            saveSusMounts(context, currentMounts)

            val success = addSusMount(context, newMount)

            if (success) {
                showToast(context, "SUS mount updated: $oldMount -> $newMount")
                return true
            } else {
                // 如果添加新挂载点失败，恢复旧挂载点
                currentMounts.add(oldMount)
                saveSusMounts(context, currentMounts)
                if (isAutoStartEnabled(context)) updateMagiskModule(context)
                showToast(context, "Failed to update mount, reverted to original")
                return false
            }
        } catch (e: Exception) {
            e.printStackTrace()
            showToast(context, "Error updating SUS mount: ${e.message}")
            false
        }
    }

    // 添加尝试卸载
    suspend fun addTryUmount(context: Context, path: String, mode: Int): Boolean {
        val commandSuccess = executeSusfsCommand(context, "add_try_umount '$path' $mode")
        saveTryUmounts(context, getTryUmounts(context) + "$path|$mode")
        if (isAutoStartEnabled(context)) updateMagiskModule(context)

        showToast(context, if (commandSuccess) {
            context.getString(R.string.susfs_try_umount_added_success, path)
        } else {
            context.getString(R.string.susfs_try_umount_added_saved, path)
        })
        return true
    }

    suspend fun removeTryUmount(context: Context, umountEntry: String): Boolean {
        saveTryUmounts(context, getTryUmounts(context) - umountEntry)
        if (isAutoStartEnabled(context)) updateMagiskModule(context)
        val path = umountEntry.split("|").firstOrNull() ?: umountEntry
        showToast(context, "Removed Try to uninstall: $path")
        return true
    }

    // 编辑尝试卸载
    suspend fun editTryUmount(context: Context, oldEntry: String, newPath: String, newMode: Int): Boolean {
        return try {
            val currentUmounts = getTryUmounts(context).toMutableSet()
            if (!currentUmounts.remove(oldEntry)) {
                showToast(context, "Original umount entry not found: $oldEntry")
                return false
            }

            saveTryUmounts(context, currentUmounts)

            val success = addTryUmount(context, newPath, newMode)

            if (success) {
                showToast(context, "Try umount updated: $oldEntry -> $newPath|$newMode")
                return true
            } else {
                // 如果添加新条目失败，恢复旧条目
                currentUmounts.add(oldEntry)
                saveTryUmounts(context, currentUmounts)
                if (isAutoStartEnabled(context)) updateMagiskModule(context)
                showToast(context, "Failed to update umount entry, reverted to original")
                return false
            }
        } catch (e: Exception) {
            e.printStackTrace()
            showToast(context, "Error updating try umount: ${e.message}")
            false
        }
    }

    suspend fun runTryUmount(context: Context): Boolean = executeSusfsCommand(context, "run_try_umount")

    // Zygote隔离服务卸载控制
    suspend fun setUmountForZygoteIsoService(context: Context, enabled: Boolean): Boolean {
        if (!isSusVersion158()) {
            return false
        }

        val result = executeSusfsCommandWithOutput(context, "umount_for_zygote_iso_service ${if (enabled) 1 else 0}")
        val success = result.isSuccess && result.output.isEmpty()

        if (success) {
            saveUmountForZygoteIsoService(context, enabled)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
            showToast(context, if (enabled)
                context.getString(R.string.umount_zygote_iso_service_enabled)
            else
                context.getString(R.string.umount_zygote_iso_service_disabled)
            )
        } else {
            showToast(context, context.getString(R.string.susfs_command_failed))
        }
        return success
    }

    // 添加kstat配置
    suspend fun addKstatStatically(context: Context, path: String, ino: String, dev: String, nlink: String,
                                   size: String, atime: String, atimeNsec: String, mtime: String, mtimeNsec: String,
                                   ctime: String, ctimeNsec: String, blocks: String, blksize: String): Boolean {
        val command = "add_sus_kstat_statically '$path' '$ino' '$dev' '$nlink' '$size' '$atime' '$atimeNsec' '$mtime' '$mtimeNsec' '$ctime' '$ctimeNsec' '$blocks' '$blksize'"
        val success = executeSusfsCommand(context, command)
        if (success) {
            val configEntry = "$path|$ino|$dev|$nlink|$size|$atime|$atimeNsec|$mtime|$mtimeNsec|$ctime|$ctimeNsec|$blocks|$blksize"
            saveKstatConfigs(context, getKstatConfigs(context) + configEntry)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
            showToast(context, context.getString(R.string.kstat_static_config_added, path))
        }
        return success
    }

    suspend fun removeKstatConfig(context: Context, config: String): Boolean {
        saveKstatConfigs(context, getKstatConfigs(context) - config)
        if (isAutoStartEnabled(context)) updateMagiskModule(context)
        val path = config.split("|").firstOrNull() ?: config
        showToast(context, context.getString(R.string.kstat_config_removed, path))
        return true
    }

    // 编辑kstat配置
    @SuppressLint("StringFormatInvalid")
    suspend fun editKstatConfig(context: Context, oldConfig: String, path: String, ino: String, dev: String, nlink: String,
                                size: String, atime: String, atimeNsec: String, mtime: String, mtimeNsec: String,
                                ctime: String, ctimeNsec: String, blocks: String, blksize: String): Boolean {
        return try {
            val currentConfigs = getKstatConfigs(context).toMutableSet()
            if (!currentConfigs.remove(oldConfig)) {
                showToast(context, "Original kstat config not found")
                return false
            }

            saveKstatConfigs(context, currentConfigs)

            val success = addKstatStatically(context, path, ino, dev, nlink, size, atime, atimeNsec,
                mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize)

            if (success) {
                showToast(context, context.getString(R.string.kstat_config_updated, path))
                return true
            } else {
                // 如果添加新配置失败，恢复旧配置
                currentConfigs.add(oldConfig)
                saveKstatConfigs(context, currentConfigs)
                if (isAutoStartEnabled(context)) updateMagiskModule(context)
                showToast(context, "Failed to update kstat config, reverted to original")
                return false
            }
        } catch (e: Exception) {
            e.printStackTrace()
            showToast(context, "Error updating kstat config: ${e.message}")
            false
        }
    }

    // 添加kstat路径
    suspend fun addKstat(context: Context, path: String): Boolean {
        val success = executeSusfsCommand(context, "add_sus_kstat '$path'")
        if (success) {
            saveAddKstatPaths(context, getAddKstatPaths(context) + path)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
            showToast(context, context.getString(R.string.kstat_path_added, path))
        }
        return success
    }

    suspend fun removeAddKstat(context: Context, path: String): Boolean {
        saveAddKstatPaths(context, getAddKstatPaths(context) - path)
        if (isAutoStartEnabled(context)) updateMagiskModule(context)
        showToast(context, context.getString(R.string.kstat_path_removed, path))
        return true
    }

    // 编辑kstat路径
    @SuppressLint("StringFormatInvalid")
    suspend fun editAddKstat(context: Context, oldPath: String, newPath: String): Boolean {
        return try {
            val currentPaths = getAddKstatPaths(context).toMutableSet()
            if (!currentPaths.remove(oldPath)) {
                showToast(context, "Original kstat path not found: $oldPath")
                return false
            }

            saveAddKstatPaths(context, currentPaths)

            val success = addKstat(context, newPath)

            if (success) {
                showToast(context, context.getString(R.string.kstat_path_updated, oldPath, newPath))
                return true
            } else {
                // 如果添加新路径失败，恢复旧路径
                currentPaths.add(oldPath)
                saveAddKstatPaths(context, currentPaths)
                if (isAutoStartEnabled(context)) updateMagiskModule(context)
                showToast(context, "Failed to update kstat path, reverted to original")
                return false
            }
        } catch (e: Exception) {
            e.printStackTrace()
            showToast(context, "Error updating kstat path: ${e.message}")
            false
        }
    }

    // 更新kstat
    suspend fun updateKstat(context: Context, path: String): Boolean {
        val success = executeSusfsCommand(context, "update_sus_kstat '$path'")
        if (success) showToast(context, context.getString(R.string.kstat_updated, path))
        return success
    }

    // 更新kstat全克隆
    suspend fun updateKstatFullClone(context: Context, path: String): Boolean {
        val success = executeSusfsCommand(context, "update_sus_kstat_full_clone '$path'")
        if (success) showToast(context, context.getString(R.string.kstat_full_clone_updated, path))
        return success
    }

    // 设置Android数据路径
    suspend fun setAndroidDataPath(context: Context, path: String): Boolean {
        val success = executeSusfsCommand(context, "set_android_data_root_path '$path'")
        if (success) {
            saveAndroidDataPath(context, path)
            if (isAutoStartEnabled(context)) {
                kotlinx.coroutines.CoroutineScope(Dispatchers.Default).launch {
                    updateMagiskModule(context)
                }
            }
        }
        return success
    }

    // 设置SD卡路径
    suspend fun setSdcardPath(context: Context, path: String): Boolean {
        val success = executeSusfsCommand(context, "set_sdcard_root_path '$path'")
        if (success) {
            saveSdcardPath(context, path)
            if (isAutoStartEnabled(context)) {
                kotlinx.coroutines.CoroutineScope(Dispatchers.Default).launch {
                    updateMagiskModule(context)
                }
            }
        }
        return success
    }

    /**
     * 自启动配置检查
     */
    fun hasConfigurationForAutoStart(context: Context): Boolean {
        val config = getCurrentModuleConfig(context)
        return config.hasAutoStartConfig() || runBlocking {
            getEnabledFeatures(context).any { it.isEnabled }
        }
    }

    /**
     * 自启动配置方法
     */
    suspend fun configureAutoStart(context: Context, enabled: Boolean): Boolean = withContext(Dispatchers.IO) {
        try {
            if (enabled) {
                if (!hasConfigurationForAutoStart(context)) {
                    showToast(context, context.getString(R.string.susfs_no_config_to_autostart))
                    return@withContext false
                }

                val targetPath = getSuSFSTargetPath()
                if (!runCmdWithResult("test -f '$targetPath'").isSuccess) {
                    copyBinaryFromAssets(context) ?: run {
                        showToast(context, context.getString(R.string.susfs_binary_not_found))
                        return@withContext false
                    }
                }

                val success = createMagiskModule(context)
                if (success) {
                    setAutoStartEnabled(context, true)
                    showToast(context, context.getString(R.string.susfs_autostart_enabled_success, MODULE_PATH))
                } else {
                    showToast(context, context.getString(R.string.susfs_autostart_enable_failed))
                }
                success
            } else {
                val success = removeMagiskModule()
                if (success) {
                    setAutoStartEnabled(context, false)
                    showToast(context, context.getString(R.string.susfs_autostart_disabled_success))
                } else {
                    showToast(context, context.getString(R.string.susfs_autostart_disable_failed))
                }
                success
            }
        } catch (e: Exception) {
            e.printStackTrace()
            showToast(context, context.getString(R.string.susfs_autostart_error, e.message ?: "Unknown error"))
            false
        }
    }

    suspend fun resetToDefault(context: Context): Boolean {
        val success = setUname(context, DEFAULT_UNAME, DEFAULT_BUILD_TIME)
        if (success && isAutoStartEnabled(context)) {
            configureAutoStart(context, false)
        }
        return success
    }
}