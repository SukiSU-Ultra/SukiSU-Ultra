package com.sukisu.ultra.ui.screen.susfs.util

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.graphics.drawable.Drawable
import android.os.Build
import android.util.Log
import android.widget.Toast
import com.sukisu.ultra.R
import com.topjohnwu.superuser.Shell
import com.topjohnwu.superuser.io.SuFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import androidx.core.content.edit
import com.sukisu.ultra.ui.util.getRootShell
import com.sukisu.ultra.ui.util.getSuSFSVersion
import com.sukisu.ultra.ui.util.getSuSFSFeatures
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.*

object SuSFSManager {
    private const val PREFS_NAME = "susfs_config"
    private const val KEY_UNAME_VALUE = "uname_value"
    private const val KEY_BUILD_TIME_VALUE = "build_time_value"
    private const val KEY_AUTO_START_ENABLED = "auto_start_enabled"
    private const val KEY_SUS_PATHS = "sus_paths"
    private const val KEY_SUS_LOOP_PATHS = "sus_loop_paths"

    private const val KEY_SUS_MAPS = "sus_maps"
    private const val KEY_ENABLE_LOG = "enable_log"
    private const val KEY_EXECUTE_IN_POST_FS_DATA = "execute_in_post_fs_data"
    private const val KEY_KSTAT_CONFIGS = "kstat_configs"
    private const val KEY_ADD_KSTAT_PATHS = "add_kstat_paths"
    private const val KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS = "hide_sus_mounts_for_all_procs"
    private const val KEY_ENABLE_CLEANUP_RESIDUE = "enable_cleanup_residue"
    private const val KEY_ENABLE_HIDE_BL = "enable_hide_bl"
    private const val KEY_ENABLE_AVC_LOG_SPOOFING = "enable_avc_log_spoofing"

    // 常量
    private const val DEFAULT_UNAME = "default"
    private const val DEFAULT_BUILD_TIME = "default"
    @SuppressLint("SdCardPath")
    private const val DEFAULT_ANDROID_DATA_PATH = "/sdcard/Android/data"
    const val MAX_SUSFS_VERSION = "2.1.0"
    private const val BACKUP_FILE_EXTENSION = ".susfs_backup"
    private const val MEDIA_DATA_PATH = "/data/media/0/Android/data"
    private const val CGROUP_BASE_PATH = "/sys/fs/cgroup"
    private const val SUSFS_BINARY_TARGET_NAME = "ksu_susfs"

    data class SlotInfo(val slotName: String, val uname: String, val buildTime: String)
    data class EnabledFeature(
        val name: String,
        val isEnabled: Boolean,
        val statusText: String,
        val canConfigure: Boolean = false
    ) {
        companion object {
            fun create(context: Context, name: String, isEnabled: Boolean): EnabledFeature {
                val statusText = if (isEnabled) {
                    context.getString(R.string.susfs_feature_enabled)
                } else {
                    context.getString(R.string.susfs_feature_disabled)
                }
                return EnabledFeature(name, isEnabled, statusText, false)
            }
        }
    }

    data class AppInfo(
        val packageName: String,
        val appName: String,
        val packageInfo: PackageInfo,
        val isSystemApp: Boolean
    )

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
                            is JSONArray -> {
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

    data class ModuleConfig(
        val targetPath: String,
        val unameValue: String,
        val buildTimeValue: String,
        val executeInPostFsData: Boolean,
        val susPaths: Set<String>,
        val susLoopPaths: Set<String>,
        val susMaps: Set<String>,
        val enableLog: Boolean,
        val kstatConfigs: Set<String>,
        val addKstatPaths: Set<String>,
        val hideSusMountsForAllProcs: Boolean,
        val enableHideBl: Boolean,
        val enableCleanupResidue: Boolean,
        val enableAvcLogSpoofing: Boolean
    ) {
        /**
         * 检查是否有需要自启动的配置
         */
        fun hasAutoStartConfig(): Boolean {
            return unameValue != DEFAULT_UNAME ||
                    buildTimeValue != DEFAULT_BUILD_TIME ||
                    susPaths.isNotEmpty() ||
                    susLoopPaths.isNotEmpty() ||
                    susMaps.isNotEmpty() ||
                    kstatConfigs.isNotEmpty() ||
                    addKstatPaths.isNotEmpty()
        }
    }

    // 基础工具方法
    private fun getPrefs(context: Context): SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun getSuSFSBinaryName(): String {
        val version = try {
            getSuSFSVersion()
        } catch (_: Exception) {
            MAX_SUSFS_VERSION
        }
        val versionSuffix = version.removePrefix("v")
        return "${SUSFS_BINARY_TARGET_NAME}_$versionSuffix"
    }

    fun getSuSFSTargetPath(): String = "/data/adb/ksu/bin/$SUSFS_BINARY_TARGET_NAME"

    suspend fun copyBinaryFromAssets(context: Context): String? = withContext(Dispatchers.IO) {
        try {
            val binaryName = getSuSFSBinaryName()
            val targetPath = getSuSFSTargetPath()
            val tempFile = File(context.cacheDir, binaryName)

            context.assets.open(binaryName).use { input ->
                FileOutputStream(tempFile).use { output ->
                    input.copyTo(output)
                }
            }

            val shell = Shell.getShell()
            val success = shell.newJob()
                .add("cp '${tempFile.absolutePath}' '$targetPath'")
                .add("chmod 755 '$targetPath'")
                .exec().isSuccess
            
            tempFile.delete()

            if (success && shell.newJob().add("test -f '$targetPath'").exec().isSuccess) {
                targetPath
            } else {
                null
            }
        } catch (e: IOException) {
            Log.e("SuSFSManager", "Failed to copy binary", e)
            null
        }
    }


    private fun runCmd(shell: Shell, cmd: String): String {
        return shell.newJob()
            .add(cmd)
            .to(mutableListOf<String>(), null)
            .exec().out
            .joinToString("\n")
    }

    private fun runCmdWithResult(cmd: String): SuSFSModuleManager.CommandResult {
        val result = Shell.getShell().newJob().add(cmd).exec()
        return SuSFSModuleManager.CommandResult(result.isSuccess, result.out.joinToString("\n"), result.err.joinToString("\n"))
    }

    private suspend fun executeSusfsCommandDirect(context: Context, command: String): SuSFSModuleManager.CommandResult = withContext(Dispatchers.IO) {
        try {
            val binaryPath = copyBinaryFromAssets(context) ?: return@withContext SuSFSModuleManager.CommandResult(
                false, "", context.getString(R.string.susfs_binary_not_found)
            )
            val shell = Shell.getShell()
            val result = shell.newJob().add("$binaryPath $command").exec()
            val commandResult = SuSFSModuleManager.CommandResult(
                isSuccess = result.isSuccess,
                output = result.out.joinToString("\n"),
                errorOutput = result.err.joinToString("\n")
            )
            if (!commandResult.isSuccess) {
                Log.e("SuSFSManager", "Command failed: $command, error: ${commandResult.errorOutput}")
            }
            commandResult
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Exception executing command: $command", e)
            SuSFSModuleManager.CommandResult(false, "", e.message ?: "Unknown error")
        }
    }


    fun getCurrentModuleConfig(context: Context): ModuleConfig {
        return ModuleConfig(
            targetPath = getSuSFSTargetPath(),
            unameValue = getUnameValue(context),
            buildTimeValue = getBuildTimeValue(context),
            executeInPostFsData = getExecuteInPostFsData(context),
            susPaths = getSusPaths(context),
            susLoopPaths = getSusLoopPaths(context),
            susMaps = getSusMaps(context),
            enableLog = getEnableLogState(context),
            kstatConfigs = getKstatConfigs(context),
            addKstatPaths = getAddKstatPaths(context),
            hideSusMountsForAllProcs = getHideSusMountsForAllProcs(context),
            enableHideBl = getEnableHideBl(context),
            enableCleanupResidue = getEnableCleanupResidue(context),
            enableAvcLogSpoofing = getEnableAvcLogSpoofing(context)
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

    fun saveExecuteInPostFsData(context: Context, enabled: Boolean) =
        getPrefs(context).edit { putBoolean(KEY_EXECUTE_IN_POST_FS_DATA, enabled) }

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

    // AVC日志欺骗配置
    fun saveEnableAvcLogSpoofing(context: Context, enabled: Boolean) =
        getPrefs(context).edit { putBoolean(KEY_ENABLE_AVC_LOG_SPOOFING, enabled) }

    fun getEnableAvcLogSpoofing(context: Context): Boolean =
        getPrefs(context).getBoolean(KEY_ENABLE_AVC_LOG_SPOOFING, false)


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

    fun saveSusMaps(context: Context, maps: Set<String>) =
        getPrefs(context).edit { putStringSet(KEY_SUS_MAPS, maps) }

    fun getSusMaps(context: Context): Set<String> =
        getPrefs(context).getStringSet(KEY_SUS_MAPS, emptySet()) ?: emptySet()

    fun saveKstatConfigs(context: Context, configs: Set<String>) =
        getPrefs(context).edit { putStringSet(KEY_KSTAT_CONFIGS, configs) }

    fun getKstatConfigs(context: Context): Set<String> =
        getPrefs(context).getStringSet(KEY_KSTAT_CONFIGS, emptySet()) ?: emptySet()

    fun saveAddKstatPaths(context: Context, paths: Set<String>) =
        getPrefs(context).edit { putStringSet(KEY_ADD_KSTAT_PATHS, paths) }

    fun getAddKstatPaths(context: Context): Set<String> =
        getPrefs(context).getStringSet(KEY_ADD_KSTAT_PATHS, emptySet()) ?: emptySet()

    // 获取已安装的应用列表
    @SuppressLint("QueryPermissionsNeeded")
    suspend fun getInstalledApps(): List<AppInfo> = withContext(Dispatchers.IO) {
        try {
            val allApps = mutableMapOf<String, AppInfo>()

            SuperUserViewModel.getAppsSafely().forEach { superUserApp ->
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
                    } catch (_: Exception) {
                        false
                    }
                    if (exists) appInfo else null
                }
            }.awaitAll().filterNotNull()

            filteredApps.sortedBy { it.appName }
        } catch (_: Exception) {
            emptyList()
        }
    }

    // 获取应用的UID
    private suspend fun getAppUid(context: Context, packageName: String): Int? = withContext(Dispatchers.IO) {
        try {
            val superUserApp = SuperUserViewModel.getAppsSafely().find { it.packageName == packageName }
            if (superUserApp != null) {
                return@withContext superUserApp.packageInfo.applicationInfo?.uid
            }

            // 从PackageManager中查找
            val packageManager = context.packageManager
            val packageInfo = packageManager.getPackageInfo(packageName, 0)
            packageInfo.applicationInfo?.uid
        } catch (_: Exception) {
            null
        }
    }

    private fun checkPathExists(path: String): Boolean {
        return try {
            val shell = try {
                getRootShell()
            } catch (_: Exception) {
                null
            }
            
            val file = if (shell != null) {
                SuFile(path).apply { setShell(shell) }
            } else {
                File(path)
            }
            
            file.exists() && file.isDirectory
        } catch (_: Exception) {
            false
        }
    }
    
    private fun buildUidPath(uid: Int): String {
        val possiblePaths = listOf(
            "$CGROUP_BASE_PATH/uid_$uid",
            "$CGROUP_BASE_PATH/apps/uid_$uid",
            "$CGROUP_BASE_PATH/system/uid_$uid",
            "$CGROUP_BASE_PATH/freezer/uid_$uid",
            "$CGROUP_BASE_PATH/memory/uid_$uid",
            "$CGROUP_BASE_PATH/cpuset/uid_$uid",
            "$CGROUP_BASE_PATH/cpu/uid_$uid"
        )
        
        for (path in possiblePaths) {
            if (checkPathExists(path)) {
                return path
            }
        }
        return possiblePaths[0]
    }

    // 快捷添加应用路径
    @SuppressLint("StringFormatMatches")
    suspend fun addAppPaths(context: Context, packageName: String): Boolean {
        val path1 = "$DEFAULT_ANDROID_DATA_PATH/$packageName"
        val path2 = "$MEDIA_DATA_PATH/$packageName"

        val uid = getAppUid(context, packageName) ?: return false

        val path3 = buildUidPath(uid)

        var successCount = 0

        // 添加第一个路径（Android/data路径）
        if (addSusPathInternal(context, path1, showToast = false)) {
            successCount++
        }

        // 添加第二个路径（媒体数据路径）
        if (addSusPathInternal(context, path2, showToast = false)) {
            successCount++
        }

        // 添加第三个路径（UID路径）
        if (addSusPathInternal(context, path3, showToast = false)) {
            successCount++
        }

        return successCount > 0
    }

    // 获取所有配置的Map
    private fun getAllConfigurations(context: Context): Map<String, Any> {
        return mapOf(
            KEY_UNAME_VALUE to getUnameValue(context),
            KEY_BUILD_TIME_VALUE to getBuildTimeValue(context),
            KEY_AUTO_START_ENABLED to isAutoStartEnabled(context),
            KEY_SUS_PATHS to getSusPaths(context),
            KEY_SUS_LOOP_PATHS to getSusLoopPaths(context),
            KEY_SUS_MAPS to getSusMaps(context),
            KEY_ENABLE_LOG to getEnableLogState(context),
            KEY_EXECUTE_IN_POST_FS_DATA to getExecuteInPostFsData(context),
            KEY_KSTAT_CONFIGS to getKstatConfigs(context),
            KEY_ADD_KSTAT_PATHS to getAddKstatPaths(context),
            KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS to getHideSusMountsForAllProcs(context),
            KEY_ENABLE_HIDE_BL to getEnableHideBl(context),
            KEY_ENABLE_CLEANUP_RESIDUE to getEnableCleanupResidue(context),
            KEY_ENABLE_AVC_LOG_SPOOFING to getEnableAvcLogSpoofing(context),
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
            "${Build.MANUFACTURER} ${Build.MODEL} (${Build.VERSION.RELEASE})"
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
        try {
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
        } catch (e: Exception) {
            e.printStackTrace()
            throw e
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

    // 命令执行
    private suspend fun executeSusfsCommand(context: Context, command: String): Boolean {
        val result = executeSusfsCommandDirect(context, command)
        if (!result.isSuccess) {
            showToast(context, "${context.getString(R.string.susfs_command_failed)}\n${result.output}\n${result.errorOutput}")
        }
        return result.isSuccess
    }

    private suspend fun executeSusfsCommandWithOutput(context: Context, command: String): SuSFSModuleManager.CommandResult {
        return executeSusfsCommandDirect(context, command)
    }

    private suspend fun showToast(context: Context, message: String) = withContext(Dispatchers.Main) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
    }

    private suspend fun updateMagiskModule(context: Context): Boolean {
        return SuSFSModuleManager.updateMagiskModule(context)
    }

    // 功能状态获取
    suspend fun getEnabledFeatures(context: Context): List<EnabledFeature> = withContext(Dispatchers.IO) {
        try {
            val featuresOutput = getSuSFSFeatures()

            if (featuresOutput.isNotBlank() && featuresOutput != "Invalid") {
                parseEnabledFeaturesFromOutput(context, featuresOutput)
            } else {
                getDefaultDisabledFeatures(context)
            }
        } catch (e: Exception) {
            e.printStackTrace()
            getDefaultDisabledFeatures(context)
        }
    }

    private fun parseEnabledFeaturesFromOutput(context: Context, featuresOutput: String): List<EnabledFeature> {
        val enabledConfigs = featuresOutput.lines()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toSet()

        val featureMap = mapOf(
            "CONFIG_KSU_SUSFS_SUS_PATH" to context.getString(R.string.sus_path_feature_label),
            "CONFIG_KSU_SUSFS_SUS_MOUNT" to context.getString(R.string.sus_mount_feature_label),
            "CONFIG_KSU_SUSFS_SPOOF_UNAME" to context.getString(R.string.spoof_uname_feature_label),
            "CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG" to context.getString(R.string.spoof_cmdline_feature_label),
            "CONFIG_KSU_SUSFS_OPEN_REDIRECT" to context.getString(R.string.open_redirect_feature_label),
            "CONFIG_KSU_SUSFS_ENABLE_LOG" to context.getString(R.string.enable_log_feature_label),
            "CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS" to context.getString(R.string.hide_symbols_feature_label),
            "CONFIG_KSU_SUSFS_SUS_KSTAT" to context.getString(R.string.sus_kstat_feature_label),
            "CONFIG_KSU_SUSFS_SUS_MAP" to context.getString(R.string.sus_map_feature_label)
        )


        return featureMap.map { (configKey, displayName) ->
            val isEnabled = enabledConfigs.contains(configKey)

            val statusText = if (isEnabled) {
                context.getString(R.string.susfs_feature_enabled)
            } else {
                context.getString(R.string.susfs_feature_disabled)
            }

            val canConfigure = displayName == context.getString(R.string.enable_log_feature_label)

            EnabledFeature(displayName, isEnabled, statusText, canConfigure)
        }.sortedBy { it.name }
    }

    private fun getDefaultDisabledFeatures(context: Context): List<EnabledFeature> {
        val defaultFeatures = listOf(
            "sus_path_feature_label" to context.getString(R.string.sus_path_feature_label),
            "sus_mount_feature_label" to context.getString(R.string.sus_mount_feature_label),
            "spoof_uname_feature_label" to context.getString(R.string.spoof_uname_feature_label),
            "spoof_cmdline_feature_label" to context.getString(R.string.spoof_cmdline_feature_label),
            "open_redirect_feature_label" to context.getString(R.string.open_redirect_feature_label),
            "enable_log_feature_label" to context.getString(R.string.enable_log_feature_label),
            "hide_symbols_feature_label" to context.getString(R.string.hide_symbols_feature_label),
            "sus_kstat_feature_label" to context.getString(R.string.sus_kstat_feature_label),
            "sus_map_feature_label" to context.getString(R.string.sus_map_feature_label)
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

    // sus日志开关
    suspend fun setEnableLog(context: Context, enabled: Boolean): Boolean {
        val success = executeSusfsCommand(context, "enable_log ${if (enabled) 1 else 0}")
        if (success) {
            saveEnableLogState(context, enabled)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
        }
        return success
    }

    // AVC日志欺骗开关
    suspend fun setEnableAvcLogSpoofing(context: Context, enabled: Boolean): Boolean {
        val success = executeSusfsCommand(context, "enable_avc_log_spoofing ${if (enabled) 1 else 0}")
        if (success) {
            saveEnableAvcLogSpoofing(context, enabled)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
        }
        return success
    }

    // SUS挂载隐藏控制
    suspend fun setHideSusMountsForAllProcs(context: Context, hideForAll: Boolean): Boolean {
        val success = executeSusfsCommand(context, "hide_sus_mnts_for_non_su_procs ${if (hideForAll) 1 else 0}")
        if (success) {
            saveHideSusMountsForAllProcs(context, hideForAll)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
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
        }
        return success
    }

    // 添加SUS路径
    @SuppressLint("StringFormatInvalid")
    private suspend fun addSusPathInternal(context: Context, path: String, showToast: Boolean = true): Boolean {
        // 执行添加SUS路径命令
        val result = executeSusfsCommandWithOutput(context, "add_sus_path '$path'")
        val isActuallySuccessful = result.isSuccess && !result.output.contains("not found, skip adding")

        if (isActuallySuccessful) {
            saveSusPaths(context, getSusPaths(context) + path)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
        } else if (showToast) {
            val errorMsg = result.errorOutput.ifEmpty { context.getString(R.string.susfs_command_failed) }
            showToast(context, errorMsg)
        }
        return isActuallySuccessful
    }

    @SuppressLint("StringFormatInvalid")
    suspend fun addSusPath(context: Context, path: String): Boolean {
        return addSusPathInternal(context, path, showToast = true)
    }

    suspend fun removeSusPath(context: Context, path: String): Boolean {
        saveSusPaths(context, getSusPaths(context) - path)
        if (isAutoStartEnabled(context)) updateMagiskModule(context)
        return true
    }

    // 编辑SUS路径
    suspend fun editSusPath(context: Context, oldPath: String, newPath: String): Boolean {
        return try {
            val currentPaths = getSusPaths(context).toMutableSet()
            if (!currentPaths.remove(oldPath)) {
                showToast(context, context.getString(R.string.susfs_command_failed))
                return false
            }

            saveSusPaths(context, currentPaths)

            val success = addSusPathInternal(context, newPath, showToast = false)

            if (!success) {
                // 如果添加新路径失败，恢复旧路径
                currentPaths.add(oldPath)
                saveSusPaths(context, currentPaths)
                if (isAutoStartEnabled(context)) updateMagiskModule(context)
                showToast(context, context.getString(R.string.susfs_command_failed))
            }
            return success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Exception editing SUS path", e)
            showToast(context, context.getString(R.string.susfs_command_failed))
            false
        }
    }

    // 循环路径相关方法
    @SuppressLint("SdCardPath")
    private fun isValidLoopPath(path: String): Boolean {
        return !path.startsWith("/storage/") && !path.startsWith("/sdcard/")
    }

    @SuppressLint("StringFormatInvalid")
    private suspend fun addSusLoopPathInternal(context: Context, path: String, showToast: Boolean = true): Boolean {
        // 检查路径是否有效
        if (!isValidLoopPath(path)) {
            if (showToast) {
                showToast(context, context.getString(R.string.susfs_invalid_loop_path))
            }
            return false
        }

        // 执行添加循环路径命令
        val result = executeSusfsCommandWithOutput(context, "add_sus_path_loop '$path'")
        val isActuallySuccessful = result.isSuccess && !result.output.contains("not found, skip adding")

        if (isActuallySuccessful) {
            saveSusLoopPaths(context, getSusLoopPaths(context) + path)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
        } else if (showToast) {
            val errorMsg = result.errorOutput.ifEmpty { context.getString(R.string.susfs_add_loop_path_failed) }
            showToast(context, errorMsg)
        }
        return isActuallySuccessful
    }

    @SuppressLint("StringFormatInvalid")
    suspend fun addSusLoopPath(context: Context, path: String): Boolean {
        return addSusLoopPathInternal(context, path, showToast = true)
    }

    suspend fun removeSusLoopPath(context: Context, path: String): Boolean {
        saveSusLoopPaths(context, getSusLoopPaths(context) - path)
        if (isAutoStartEnabled(context)) updateMagiskModule(context)
        return true
    }

    // 编辑循环路径
    suspend fun editSusLoopPath(context: Context, oldPath: String, newPath: String): Boolean {
        // 检查新路径是否有效
        if (!isValidLoopPath(newPath)) {
            showToast(context, context.getString(R.string.susfs_invalid_loop_path))
            return false
        }

        return try {
            val currentPaths = getSusLoopPaths(context).toMutableSet()
            if (!currentPaths.remove(oldPath)) {
                showToast(context, context.getString(R.string.susfs_edit_loop_path_failed))
                return false
            }

            saveSusLoopPaths(context, currentPaths)

            val success = addSusLoopPathInternal(context, newPath, showToast = false)

            if (!success) {
                // 如果添加新路径失败，恢复旧路径
                currentPaths.add(oldPath)
                saveSusLoopPaths(context, currentPaths)
                if (isAutoStartEnabled(context)) updateMagiskModule(context)
                showToast(context, context.getString(R.string.susfs_edit_loop_path_failed))
            }
            return success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Exception editing SUS loop path", e)
            showToast(context, context.getString(R.string.susfs_edit_loop_path_failed))
            false
        }
    }

    // 添加 SUS Maps
    private suspend fun addSusMapInternal(context: Context, map: String, showToast: Boolean = true): Boolean {
        val result = executeSusfsCommandWithOutput(context, "add_sus_map '$map'")
        val success = result.isSuccess
        if (success) {
            saveSusMaps(context, getSusMaps(context) + map)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
        } else if (showToast) {
            val errorMsg = result.errorOutput.ifEmpty { context.getString(R.string.susfs_add_map_failed) }
            showToast(context, errorMsg)
        }
        return success
    }

    suspend fun addSusMap(context: Context, map: String): Boolean {
        return addSusMapInternal(context, map, showToast = true)
    }

    suspend fun removeSusMap(context: Context, map: String): Boolean {
        saveSusMaps(context, getSusMaps(context) - map)
        if (isAutoStartEnabled(context)) updateMagiskModule(context)
        return true
    }

    suspend fun editSusMap(context: Context, oldMap: String, newMap: String): Boolean {
        return try {
            val currentMaps = getSusMaps(context).toMutableSet()
            if (!currentMaps.remove(oldMap)) {
                showToast(context, context.getString(R.string.susfs_edit_map_failed))
                return false
            }

            saveSusMaps(context, currentMaps)

            val success = addSusMapInternal(context, newMap, showToast = false)

            if (!success) {
                // 如果添加新映射失败，恢复旧映射
                currentMaps.add(oldMap)
                saveSusMaps(context, currentMaps)
                if (isAutoStartEnabled(context)) updateMagiskModule(context)
                showToast(context, context.getString(R.string.susfs_edit_map_failed))
            }
            return success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Exception editing SUS map", e)
            showToast(context, context.getString(R.string.susfs_edit_map_failed))
            false
        }
    }

    // 添加kstat配置
    private suspend fun addKstatStaticallyInternal(context: Context, path: String, ino: String, dev: String, nlink: String,
                                   size: String, atime: String, atimeNsec: String, mtime: String, mtimeNsec: String,
                                   ctime: String, ctimeNsec: String, blocks: String, blksize: String
    ): Boolean {
        val command = "add_sus_kstat_statically '$path' '$ino' '$dev' '$nlink' '$size' '$atime' '$atimeNsec' '$mtime' '$mtimeNsec' '$ctime' '$ctimeNsec' '$blocks' '$blksize'"
        val success = executeSusfsCommand(context, command)
        if (success) {
            val configEntry = "$path|$ino|$dev|$nlink|$size|$atime|$atimeNsec|$mtime|$mtimeNsec|$ctime|$ctimeNsec|$blocks|$blksize"
            saveKstatConfigs(context, getKstatConfigs(context) + configEntry)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
        }
        return success
    }

    suspend fun addKstatStatically(context: Context, path: String, ino: String, dev: String, nlink: String,
                                   size: String, atime: String, atimeNsec: String, mtime: String, mtimeNsec: String,
                                   ctime: String, ctimeNsec: String, blocks: String, blksize: String): Boolean {
        return addKstatStaticallyInternal(context, path, ino, dev, nlink, size, atime, atimeNsec, mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize)
    }

    suspend fun removeKstatConfig(context: Context, config: String): Boolean {
        saveKstatConfigs(context, getKstatConfigs(context) - config)
        if (isAutoStartEnabled(context)) updateMagiskModule(context)
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
                return false
            }

            saveKstatConfigs(context, currentConfigs)

            val success = addKstatStaticallyInternal(context, path, ino, dev, nlink, size, atime, atimeNsec,
                mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize
            )

            if (!success) {
                // 如果添加新配置失败，恢复旧配置
                currentConfigs.add(oldConfig)
                saveKstatConfigs(context, currentConfigs)
                if (isAutoStartEnabled(context)) updateMagiskModule(context)
            }
            return success
        } catch (
            _: Exception) {
            false
        }
    }

    // 添加kstat路径
    private suspend fun addKstatInternal(context: Context, path: String): Boolean {
        val success = executeSusfsCommand(context, "add_sus_kstat '$path'")
        if (success) {
            saveAddKstatPaths(context, getAddKstatPaths(context) + path)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
        }
        return success
    }

    suspend fun addKstat(context: Context, path: String): Boolean {
        return addKstatInternal(context, path)
    }

    suspend fun removeAddKstat(context: Context, path: String): Boolean {
        saveAddKstatPaths(context, getAddKstatPaths(context) - path)
        if (isAutoStartEnabled(context)) updateMagiskModule(context)
        return true
    }

    // 编辑kstat路径
    @SuppressLint("StringFormatInvalid")
    suspend fun editAddKstat(context: Context, oldPath: String, newPath: String): Boolean {
        return try {
            val currentPaths = getAddKstatPaths(context).toMutableSet()
            if (!currentPaths.remove(oldPath)) {
                return false
            }

            saveAddKstatPaths(context, currentPaths)

            val success = addKstatInternal(context, newPath)

            if (!success) {
                // 如果添加新路径失败，恢复旧路径
                currentPaths.add(oldPath)
                saveAddKstatPaths(context, currentPaths)
                if (isAutoStartEnabled(context)) updateMagiskModule(context)
            }
            return success
        } catch (_: Exception) {
            false
        }
    }

    // 更新kstat
    suspend fun updateKstat(context: Context, path: String): Boolean {
        return executeSusfsCommand(context, "update_sus_kstat '$path'")
    }

    // 更新kstat全克隆
    suspend fun updateKstatFullClone(context: Context, path: String): Boolean {
        return executeSusfsCommand(context, "update_sus_kstat_full_clone '$path'")
    }

    fun hasConfigurationForAutoStart(context: Context): Boolean {
        val config = getCurrentModuleConfig(context)
        return config.hasAutoStartConfig() || runBlocking {
            getEnabledFeatures(context).any { it.isEnabled }
        }
    }

    suspend fun configureAutoStart(context: Context, enabled: Boolean): Boolean = withContext(Dispatchers.IO) {
        try {
            if (enabled) {
                if (!hasConfigurationForAutoStart(context)) {
                    Log.e("SuSFSManager", "No configuration available for auto start")
                    return@withContext false
                }

                val targetPath = getSuSFSTargetPath()
                if (!runCmdWithResult("test -f '$targetPath'").isSuccess) {
                    copyBinaryFromAssets(context) ?: run {
                        Log.e("SuSFSManager", "Failed to copy binary from assets for auto start")
                        return@withContext false
                    }
                }

                val success = SuSFSModuleManager.createMagiskModule(context)
                if (success) {
                    setAutoStartEnabled(context, true)
                } else {
                    Log.e("SuSFSManager", "Failed to create Magisk module for auto start")
                }
                success
            } else {
                val success = SuSFSModuleManager.removeMagiskModule()
                if (success) {
                    setAutoStartEnabled(context, false)
                } else {
                    Log.e("SuSFSManager", "Failed to remove Magisk module")
                }
                success
            }
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Exception configuring auto start: enabled=$enabled", e)
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

object AppInfoCache {
    private val appInfoMap = mutableMapOf<String, CachedAppInfo>()

    data class CachedAppInfo(
        val appName: String,
        val packageInfo: PackageInfo?,
        val drawable: Drawable?,
        val timestamp: Long = System.currentTimeMillis()
    )

    fun getAppInfo(packageName: String): CachedAppInfo? {
        return appInfoMap[packageName]
    }

    fun putAppInfo(packageName: String, appInfo: CachedAppInfo) {
        appInfoMap[packageName] = appInfo
    }

    fun clearCache() {
        appInfoMap.clear()
    }

    fun getAppInfoFromSuperUser(packageName: String): CachedAppInfo? {
        val superUserApp = SuperUserViewModel.getAppsSafely().find { it.packageName == packageName }
        return superUserApp?.let { app ->
            CachedAppInfo(
                appName = app.label,
                packageInfo = app.packageInfo,
                drawable = null
            )
        }
    }
}
