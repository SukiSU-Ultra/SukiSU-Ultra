package com.sukisu.ultra.ui.util

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
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
    private const val KEY_SUS_MOUNTS = "sus_mounts"
    private const val KEY_TRY_UMOUNTS = "try_umounts"
    private const val KEY_ANDROID_DATA_PATH = "android_data_path"
    private const val KEY_SDCARD_PATH = "sdcard_path"
    private const val KEY_ENABLE_LOG = "enable_log"
    private const val KEY_EXECUTE_IN_POST_FS_DATA = "execute_in_post_fs_data"
    private const val KEY_KSTAT_CONFIGS = "kstat_configs"
    private const val KEY_ADD_KSTAT_PATHS = "add_kstat_paths"
    private const val KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS = "hide_sus_mounts_for_all_procs"
    // 常量
    private const val SUSFS_BINARY_BASE_NAME = "ksu_susfs"
    private const val DEFAULT_UNAME = "default"
    private const val DEFAULT_BUILD_TIME = "default"
    private const val MODULE_ID = "susfs_manager"
    private const val MODULE_PATH = "/data/adb/modules/$MODULE_ID"


    data class SlotInfo(val slotName: String, val uname: String, val buildTime: String)
    data class CommandResult(val isSuccess: Boolean, val output: String, val errorOutput: String = "")
    data class EnabledFeature(
        val name: String,
        val isEnabled: Boolean,
        val statusText: String = if (isEnabled) context.getString(R.string.susfs_feature_enabled) else context.getString(R.string.susfs_feature_disabled),
        val canConfigure: Boolean = false
    )

    // 命令执行
    private fun getPrefs(context: Context): SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun getSuSFSVersionUse(): String = try {
        getSuSFSVersion()
    } catch (_: Exception) { "1.5.8" }

    private fun getSuSFSBinaryName(): String = "${SUSFS_BINARY_BASE_NAME}_${getSuSFSVersionUse().removePrefix("v")}"

    private fun getSuSFSTargetPath(): String = "/data/adb/ksu/bin/${getSuSFSBinaryName()}"

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

    // 版本比较
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

    // 检查当前SuSFS版本是否支持SUS挂载隐藏控制功能
    fun isSusVersion_1_5_8(): Boolean {
        return try {
            val currentVersion = getSuSFSVersion()
            compareVersions(currentVersion, "1.5.8") >= 0
        } catch (_: Exception) {
            true
        }
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

    fun getLastAppliedValue(context: Context): String = getUnameValue(context)
    fun getLastAppliedBuildTime(context: Context): String = getBuildTimeValue(context)

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
                removeMagiskModule()
                createMagiskModule(context)
            }
        }
    }

    // SUS挂载隐藏控制
    fun saveHideSusMountsForAllProcs(context: Context, hideForAll: Boolean) =
        getPrefs(context).edit { putBoolean(KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS, hideForAll) }

    fun getHideSusMountsForAllProcs(context: Context): Boolean =
        getPrefs(context).getBoolean(KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS, true)

    // 路径和配置管理
    fun saveSusPaths(context: Context, paths: Set<String>) =
        getPrefs(context).edit { putStringSet(KEY_SUS_PATHS, paths) }

    fun getSusPaths(context: Context): Set<String> =
        getPrefs(context).getStringSet(KEY_SUS_PATHS, emptySet()) ?: emptySet()

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

    private inline fun <reified T> Map<String, Any?>.getSetSafe(key: String): Set<T> {
        return when (val value = this[key]) {
            is Set<*> -> value.filterIsInstance<T>().toSet()
            else -> emptySet()
        }
    }

    // 模块管理
    private suspend fun createMagiskModule(context: Context): Boolean = withContext(Dispatchers.IO) {
        try {
            val targetPath = getSuSFSTargetPath()

            // 创建模块目录
            if (!runCmdWithResult("mkdir -p $MODULE_PATH").isSuccess) return@withContext false

            // 创建module.prop
            val moduleProp = ScriptGenerator.generateModuleProp(MODULE_ID)
            if (!runCmdWithResult("cat > $MODULE_PATH/module.prop << 'EOF'\n$moduleProp\nEOF").isSuccess) return@withContext false

            // 获取配置
            val config = mapOf(
                "unameValue" to getUnameValue(context),
                "buildTimeValue" to getBuildTimeValue(context),
                "executeInPostFsData" to getExecuteInPostFsData(context),
                "susPaths" to getSusPaths(context),
                "susMounts" to getSusMounts(context),
                "tryUmounts" to getTryUmounts(context),
                "androidDataPath" to getAndroidDataPath(context),
                "sdcardPath" to getSdcardPath(context),
                "enableLog" to getEnableLogState(context),
                "kstatConfigs" to getKstatConfigs(context),
                "addKstatPaths" to getAddKstatPaths(context),
                "hideSusMountsForAllProcs" to getHideSusMountsForAllProcs(context)
            )

            // 生成脚本
            val scripts = mapOf(
                "service.sh" to ScriptGenerator.generateServiceScript(
                    targetPath, config["unameValue"] as String, config["buildTimeValue"] as String,
                    config.getSetSafe<String>("susPaths"), config["androidDataPath"] as String,
                    config["sdcardPath"] as String, config["enableLog"] as Boolean,
                    config["executeInPostFsData"] as Boolean, config.getSetSafe<String>("kstatConfigs"),
                    config.getSetSafe<String>("addKstatPaths")
                ),
                "post-fs-data.sh" to ScriptGenerator.generatePostFsDataScript(
                    targetPath, config["unameValue"] as String, config["buildTimeValue"] as String,
                    config["executeInPostFsData"] as Boolean
                ),
                "post-mount.sh" to ScriptGenerator.generatePostMountScript(
                    targetPath, config.getSetSafe<String>("susMounts"), config.getSetSafe<String>("tryUmounts")
                ),
                "boot-completed.sh" to ScriptGenerator.generateBootCompletedScript(
                    targetPath, config["hideSusMountsForAllProcs"] as Boolean
                )
            )

            // 创建脚本文件
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
            Natives.getSusfsFeatureStatus()?.let { status ->
                parseEnabledFeaturesFromStatus(context, status)
            } ?: emptyList()
        } catch (e: Exception) {
            e.printStackTrace()
            emptyList()
        }
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
            if (isAutoStartEnabled(context)) createMagiskModule(context)
            showToast(context, if (enabled) context.getString(R.string.susfs_log_enabled) else context.getString(R.string.susfs_log_disabled))
        }
        return success
    }

    // SUS挂载隐藏控制
    suspend fun setHideSusMountsForAllProcs(context: Context, hideForAll: Boolean): Boolean {
        if (!isSusVersion_1_5_8()) {
            return false
        }

        val success = executeSusfsCommand(context, "hide_sus_mnts_for_all_procs ${if (hideForAll) 1 else 0}")
        if (success) {
            saveHideSusMountsForAllProcs(context, hideForAll)
            if (isAutoStartEnabled(context)) createMagiskModule(context)
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
            if (isAutoStartEnabled(context)) createMagiskModule(context)
            showToast(context, context.getString(R.string.susfs_uname_set_success, unameValue, buildTimeValue))
        }
        return success
    }

    // 添加SUS路径
    @SuppressLint("StringFormatInvalid")
    suspend fun addSusPath(context: Context, path: String): Boolean {
        val result = executeSusfsCommandWithOutput(context, "add_sus_path '$path'")
        val isActuallySuccessful = result.isSuccess && !result.output.contains("not found, skip adding")

        if (isActuallySuccessful) {
            saveSusPaths(context, getSusPaths(context) + path)
            if (isAutoStartEnabled(context)) createMagiskModule(context)
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
        if (isAutoStartEnabled(context)) createMagiskModule(context)
        showToast(context, "SUS path removed: $path")
        return true
    }

    // 添加SUS挂载
    suspend fun addSusMount(context: Context, mount: String): Boolean {
        val success = executeSusfsCommand(context, "add_sus_mount '$mount'")
        if (success) {
            saveSusMounts(context, getSusMounts(context) + mount)
            if (isAutoStartEnabled(context)) createMagiskModule(context)
        }
        return success
    }

    suspend fun removeSusMount(context: Context, mount: String): Boolean {
        saveSusMounts(context, getSusMounts(context) - mount)
        if (isAutoStartEnabled(context)) createMagiskModule(context)
        showToast(context, "Removed SUS mount: $mount")
        return true
    }

    // 添加尝试卸载
    suspend fun addTryUmount(context: Context, path: String, mode: Int): Boolean {
        val commandSuccess = executeSusfsCommand(context, "add_try_umount '$path' $mode")
        saveTryUmounts(context, getTryUmounts(context) + "$path|$mode")
        if (isAutoStartEnabled(context)) createMagiskModule(context)

        showToast(context, if (commandSuccess) {
            context.getString(R.string.susfs_try_umount_added_success, path)
        } else {
            context.getString(R.string.susfs_try_umount_added_saved, path)
        })
        return true
    }

    suspend fun removeTryUmount(context: Context, umountEntry: String): Boolean {
        saveTryUmounts(context, getTryUmounts(context) - umountEntry)
        if (isAutoStartEnabled(context)) createMagiskModule(context)
        val path = umountEntry.split("|").firstOrNull() ?: umountEntry
        showToast(context, "Removed Try to uninstall: $path")
        return true
    }

    suspend fun runTryUmount(context: Context): Boolean = executeSusfsCommand(context, "run_try_umount")

    // 添加kstat配置
    suspend fun addKstatStatically(context: Context, path: String, ino: String, dev: String, nlink: String,
                                   size: String, atime: String, atimeNsec: String, mtime: String, mtimeNsec: String,
                                   ctime: String, ctimeNsec: String, blocks: String, blksize: String): Boolean {
        val command = "add_sus_kstat_statically '$path' '$ino' '$dev' '$nlink' '$size' '$atime' '$atimeNsec' '$mtime' '$mtimeNsec' '$ctime' '$ctimeNsec' '$blocks' '$blksize'"
        val success = executeSusfsCommand(context, command)
        if (success) {
            val configEntry = "$path|$ino|$dev|$nlink|$size|$atime|$atimeNsec|$mtime|$mtimeNsec|$ctime|$ctimeNsec|$blocks|$blksize"
            saveKstatConfigs(context, getKstatConfigs(context) + configEntry)
            if (isAutoStartEnabled(context)) createMagiskModule(context)
            showToast(context, context.getString(R.string.kstat_static_config_added, path))
        }
        return success
    }

    suspend fun removeKstatConfig(context: Context, config: String): Boolean {
        saveKstatConfigs(context, getKstatConfigs(context) - config)
        if (isAutoStartEnabled(context)) createMagiskModule(context)
        val path = config.split("|").firstOrNull() ?: config
        showToast(context, context.getString(R.string.kstat_config_removed, path))
        return true
    }

    // 添加kstat路径
    suspend fun addKstat(context: Context, path: String): Boolean {
        val success = executeSusfsCommand(context, "add_sus_kstat '$path'")
        if (success) {
            saveAddKstatPaths(context, getAddKstatPaths(context) + path)
            if (isAutoStartEnabled(context)) createMagiskModule(context)
            showToast(context, context.getString(R.string.kstat_path_added, path))
        }
        return success
    }

    suspend fun removeAddKstat(context: Context, path: String): Boolean {
        saveAddKstatPaths(context, getAddKstatPaths(context) - path)
        if (isAutoStartEnabled(context)) createMagiskModule(context)
        showToast(context, context.getString(R.string.kstat_path_removed, path))
        return true
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

    // 设置Android数据路径和SD卡路径
    suspend fun setAndroidDataPath(context: Context, path: String): Boolean {
        val success = executeSusfsCommand(context, "set_android_data_root_path '$path'")
        if (success) {
            saveAndroidDataPath(context, path)
            if (isAutoStartEnabled(context)) createMagiskModule(context)
        }
        return success
    }

    // 设置SD卡路径
    suspend fun setSdcardPath(context: Context, path: String): Boolean {
        val success = executeSusfsCommand(context, "set_sdcard_root_path '$path'")
        if (success) {
            saveSdcardPath(context, path)
            if (isAutoStartEnabled(context)) createMagiskModule(context)
        }
        return success
    }

    fun hasConfigurationForAutoStart(context: Context): Boolean {
        val enabledFeatures = runBlocking { getEnabledFeatures(context) }
        return getUnameValue(context) != DEFAULT_UNAME ||
                getBuildTimeValue(context) != DEFAULT_BUILD_TIME ||
                getSusPaths(context).isNotEmpty() ||
                getSusMounts(context).isNotEmpty() ||
                getTryUmounts(context).isNotEmpty() ||
                getKstatConfigs(context).isNotEmpty() ||
                getAddKstatPaths(context).isNotEmpty() ||
                enabledFeatures.any { it.isEnabled }
    }

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