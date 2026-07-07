package com.sukisu.ultra.ui.screen.susfs.util

import android.annotation.SuppressLint
import android.content.Context
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
import com.sukisu.ultra.ui.util.getRootShell
import com.sukisu.ultra.ui.util.getSuSFSVersion
import com.sukisu.ultra.ui.util.getSuSFSFeatures
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

object SuSFSManager {
    // ── config keys (must match Rust susfs_config.rs) ────────────────────────

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

    // ── defaults ─────────────────────────────────────────────────────────────

    private const val DEFAULT_UNAME = "default"
    private const val DEFAULT_BUILD_TIME = "default"
    @SuppressLint("SdCardPath")
    private const val DEFAULT_ANDROID_DATA_PATH = "/sdcard/Android/data"
    private const val BACKUP_FILE_EXTENSION = ".susfs_backup"
    private const val MEDIA_DATA_PATH = "/data/media/0/Android/data"
    private const val CGROUP_BASE_PATH = "/sys/fs/cgroup"

    // ── data classes ─────────────────────────────────────────────────────────

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
            val obj = JSONObject()
            obj.put("version", version)
            obj.put("timestamp", timestamp)
            obj.put("deviceInfo", deviceInfo)
            val confObj = JSONObject()
            configurations.forEach { entry ->
                val k = entry.key
                val v = entry.value
                confObj.put(k, when (v) {
                    is Set<*> -> org.json.JSONArray(v.filterIsInstance<String>().toList())
                    else -> v
                })
            }
            obj.put("configurations", confObj)
            return obj.toString(2)
        }
    }

    data class ModuleConfig(
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

    // ── ksud config shell helpers ───────────────────────────────────────────

    private fun configGet(key: String): String {
        val result = Shell.getShell().newJob().add("/data/adb/ksud susfs config get $key").exec()
        return result.out.joinToString("\n").trim()
    }

    private fun configSet(key: String, value: String): Boolean {
        val result = Shell.getShell().newJob().add("/data/adb/ksud susfs config set $key ${shellQuote(value)}").exec()
        return result.isSuccess
    }

    private fun configSetMulti(key: String, values: Set<String>, separator: String): Boolean {
        val raw = values.joinToString(separator)
        return configSet(key, raw)
    }

    private fun configGetMulti(key: String, separator: String = ";"): Set<String> {
        val raw = configGet(key)
        return if (raw.isBlank()) emptySet() else raw.split(separator).filter { it.isNotBlank() }.toSet()
    }

    private fun shellQuote(value: String): String = "'${value.replace("'", "'\\''")}'"

    private fun isDefaultSpoofValue(value: String): Boolean {
        return value.isBlank() || value == DEFAULT_UNAME
    }

    // ── config accessors (all go through ksud) ───────────────────────────────

    fun getCurrentModuleConfig(context: Context): ModuleConfig = ModuleConfig(
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

    fun getUnameValue(context: Context): String {
        val v = configGet(KEY_UNAME_VALUE)
        return v.ifBlank { DEFAULT_UNAME }
    }

    fun getBuildTimeValue(context: Context): String {
        val v = configGet(KEY_BUILD_TIME_VALUE)
        return v.ifBlank { DEFAULT_BUILD_TIME }
    }

    fun getKernelSpoofRelease(context: Context): String =
        getUnameValue(context).takeUnless(::isDefaultSpoofValue).orEmpty()

    fun getKernelSpoofVersion(context: Context): String =
        getBuildTimeValue(context).takeUnless(::isDefaultSpoofValue).orEmpty()

    fun setAutoStartEnabled(context: Context, enabled: Boolean) =
        configSet(KEY_AUTO_START_ENABLED, if (enabled) "true" else "false")

    fun isAutoStartEnabled(context: Context): Boolean =
        configGet(KEY_AUTO_START_ENABLED) == "true"

    fun getEnableLogState(context: Context): Boolean =
        configGet(KEY_ENABLE_LOG) == "true"

    fun getExecuteInPostFsData(context: Context): Boolean =
        configGet(KEY_EXECUTE_IN_POST_FS_DATA) == "true"

    fun getHideSusMountsForAllProcs(context: Context): Boolean {
        val v = configGet(KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS)
        return v.isBlank() || v == "true" // default true
    }

    fun getEnableHideBl(context: Context): Boolean {
        val v = configGet(KEY_ENABLE_HIDE_BL)
        return v.isBlank() || v == "true" // default true
    }

    fun getEnableCleanupResidue(context: Context): Boolean =
        configGet(KEY_ENABLE_CLEANUP_RESIDUE) == "true"

    fun getEnableAvcLogSpoofing(context: Context): Boolean =
        configGet(KEY_ENABLE_AVC_LOG_SPOOFING) == "true"

    fun getSusPaths(context: Context): Set<String> =
        configGetMulti(KEY_SUS_PATHS)

    fun getSusLoopPaths(context: Context): Set<String> =
        configGetMulti(KEY_SUS_LOOP_PATHS)

    fun getSusMaps(context: Context): Set<String> =
        configGetMulti(KEY_SUS_MAPS)

    fun getKstatConfigs(context: Context): Set<String> =
        configGetMulti(KEY_KSTAT_CONFIGS, ";;")

    fun getAddKstatPaths(context: Context): Set<String> =
        configGetMulti(KEY_ADD_KSTAT_PATHS)

    // ── app / UID helpers ────────────────────────────────────────────────────

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
                } catch (_: Exception) {}
            }

            val filteredApps = allApps.values.map { appInfo ->
                async(Dispatchers.IO) {
                    val dataPath = "$MEDIA_DATA_PATH/${appInfo.packageName}"
                    val exists = try {
                        val shell = getRootShell()
                        val outputList = mutableListOf<String>()
                        shell.newJob()
                            .add("[ -d \"$dataPath\" ] && echo 'exists' || echo 'not_exists'")
                            .to(outputList, null)
                            .exec()
                        outputList.isNotEmpty() && outputList[0].trim() == "exists"
                    } catch (_: Exception) { false }
                    if (exists) appInfo else null
                }
            }.awaitAll().filterNotNull()

            filteredApps.sortedBy { it.appName }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private suspend fun getAppUid(context: Context, packageName: String): Int? = withContext(Dispatchers.IO) {
        try {
            val superUserApp = SuperUserViewModel.getAppsSafely().find { it.packageName == packageName }
            if (superUserApp != null) {
                return@withContext superUserApp.packageInfo.applicationInfo?.uid
            }
            val packageManager = context.packageManager
            val packageInfo = packageManager.getPackageInfo(packageName, 0)
            packageInfo.applicationInfo?.uid
        } catch (_: Exception) { null }
    }

    private fun checkPathExists(path: String): Boolean {
        return try {
            val shell = try { getRootShell() } catch (_: Exception) { null }
            val file = if (shell != null) SuFile(path).apply { setShell(shell) } else File(path)
            file.exists() && file.isDirectory
        } catch (_: Exception) { false }
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
            if (checkPathExists(path)) return path
        }
        return possiblePaths[0]
    }

    @SuppressLint("StringFormatMatches")
    suspend fun addAppPaths(context: Context, packageName: String): Boolean {
        val path1 = "$DEFAULT_ANDROID_DATA_PATH/$packageName"
        val path2 = "$MEDIA_DATA_PATH/$packageName"
        val uid = getAppUid(context, packageName) ?: return false
        val path3 = buildUidPath(uid)

        var successCount = 0
        if (addSusPathInternal(context, path1, showToast = false)) successCount++
        if (addSusPathInternal(context, path2, showToast = false)) successCount++
        if (addSusPathInternal(context, path3, showToast = false)) successCount++
        return successCount > 0
    }

    // ── backup / restore ────────────────────────────────────────────────────

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
            KEY_ENABLE_AVC_LOG_SPOOFING to getEnableAvcLogSpoofing(context)
        )
    }

    private fun generateBackupFileName(): String {
        val df = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault())
        return "SuSFS_Config_${df.format(Date())}$BACKUP_FILE_EXTENSION"
    }

    private fun getDeviceInfo(): String =
        try { "${Build.MANUFACTURER} ${Build.MODEL} (${Build.VERSION.RELEASE})" } catch (_: Exception) { "Unknown Device" }

    suspend fun createBackup(context: Context, backupFilePath: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val backupData = BackupData(
                version = getSuSFSVersion(),
                timestamp = System.currentTimeMillis(),
                deviceInfo = getDeviceInfo(),
                configurations = getAllConfigurations(context)
            )
            val f = File(backupFilePath)
            f.parentFile?.mkdirs()
            f.writeText(backupData.toJson())
            showToast(context, context.getString(R.string.susfs_backup_success, f.name))
            true
        } catch (e: Exception) {
            showToast(context, context.getString(R.string.susfs_backup_failed, e.message ?: "Unknown error"))
            false
        }
    }

    suspend fun restoreFromBackup(context: Context, backupFilePath: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val f = File(backupFilePath)
            if (!f.exists()) {
                showToast(context, context.getString(R.string.susfs_backup_file_not_found))
                return@withContext false
            }
            val obj = JSONObject(f.readText())
            val confObj = obj.getJSONObject("configurations")
            val configurations = mutableMapOf<String, Any>()
            confObj.keys().forEach { key ->
                val value = confObj.get(key)
                configurations[key] = when (value) {
                    is org.json.JSONArray -> {
                        val set = mutableSetOf<String>()
                        for (i in 0 until value.length()) set.add(value.getString(i))
                        set
                    }
                    else -> value
                }
            }

            restoreConfigurations(configurations)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)

            val df = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
            showToast(context, context.getString(
                R.string.susfs_restore_success,
                df.format(Date(obj.getLong("timestamp"))),
                obj.getString("deviceInfo")
            ))
            true
        } catch (e: Exception) {
            showToast(context, context.getString(R.string.susfs_restore_failed, e.message ?: "Unknown error"))
            false
        }
    }

    private fun restoreConfigurations(configurations: Map<String, Any>) {
        configurations.forEach { (key, value) ->
            when (value) {
                is String -> configSet(key, value)
                is Boolean -> configSet(key, if (value) "true" else "false")
                is Set<*> -> {
                    val set = value.filterIsInstance<String>().toSet()
                    val sep = if (key == KEY_KSTAT_CONFIGS) ";;" else ";"
                    configSetMulti(key, set, sep)
                }
            }
        }
    }

    suspend fun validateBackupFile(backupFilePath: String): BackupData? = withContext(Dispatchers.IO) {
        try {
            val f = File(backupFilePath)
            if (!f.exists()) return@withContext null
            val obj = JSONObject(f.readText())
            val confObj = obj.getJSONObject("configurations")
            val configurations = mutableMapOf<String, Any>()
            confObj.keys().forEach { key ->
                val value = confObj.get(key)
                configurations[key] = when (value) {
                    is org.json.JSONArray -> {
                        val set = mutableSetOf<String>()
                        for (i in 0 until value.length()) set.add(value.getString(i))
                        set
                    }
                    else -> value
                }
            }
            BackupData(
                version = obj.getString("version"),
                timestamp = obj.getLong("timestamp"),
                deviceInfo = obj.getString("deviceInfo"),
                configurations = configurations
            )
        } catch (_: Exception) { null }
    }

    fun getDefaultBackupFileName(): String = generateBackupFileName()

    // ── slot info ────────────────────────────────────────────────────────────

    private fun runCmd(shell: Shell, cmd: String): String {
        return shell.newJob().add(cmd).to(mutableListOf<String>(), null).exec().out.joinToString("\n")
    }

    suspend fun getCurrentSlotInfo(): List<SlotInfo> = withContext(Dispatchers.IO) {
        try {
            val shell = Shell.getShell()
            listOf("boot_a", "boot_b").mapNotNull { slot ->
                val uname = runCmd(shell,
                    "strings -n 20 /dev/block/by-name/$slot | awk '/Linux version/ && ++c==2 {print $3; exit}'"
                ).trim()
                val buildTime = runCmd(shell, "strings -n 20 /dev/block/by-name/$slot | sed -n '/Linux version.*#/{s/.*#/#/p;q}'").trim()
                if (uname.isNotEmpty() && buildTime.isNotEmpty()) {
                    SlotInfo(slot, uname.ifEmpty { "unknown" }, buildTime.ifEmpty { "unknown" })
                } else null
            }
        } catch (_: Exception) { emptyList() }
    }

    suspend fun getCurrentActiveSlot(): String = withContext(Dispatchers.IO) {
        try {
            when (Shell.getShell().newJob().add("getprop ro.boot.slot_suffix").to(mutableListOf(), null).exec().out.firstOrNull()?.trim()) {
                "_a" -> "boot_a"
                "_b" -> "boot_b"
                else -> "unknown"
            }
        } catch (_: Exception) { "unknown" }
    }

    // ── ksud susfs command helpers ───────────────────────────────────────────

    private suspend fun executeSusfsCommandDirect(command: String): SuSFSModuleManager.CommandResult = withContext(Dispatchers.IO) {
        try {
            val shell = getRootShell()
            val result = shell.newJob().add("/data/adb/ksud susfs $command").exec()
            SuSFSModuleManager.CommandResult(
                isSuccess = result.isSuccess,
                output = result.out.joinToString("\n"),
                errorOutput = result.err.joinToString("\n")
            )
        } catch (e: Exception) {
            SuSFSModuleManager.CommandResult(false, "", e.message ?: "Unknown error")
        }
    }

    private suspend fun executeSusfsCommand(context: Context, command: String): Boolean {
        val result = executeSusfsCommandDirect(command)
        if (!result.isSuccess) {
            showToast(context, "${context.getString(R.string.susfs_command_failed)}\n${result.output}\n${result.errorOutput}")
        }
        return result.isSuccess
    }

    private suspend fun executeSusfsCommandWithOutput(command: String): SuSFSModuleManager.CommandResult =
        executeSusfsCommandDirect(command)

    private suspend fun showToast(context: Context, message: String) = withContext(Dispatchers.Main) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
    }

    private suspend fun updateMagiskModule(context: Context): Boolean =
        SuSFSModuleManager.updateMagiskModule()

    // ── feature detection ────────────────────────────────────────────────────

    suspend fun getEnabledFeatures(context: Context): List<EnabledFeature> = withContext(Dispatchers.IO) {
        try {
            val featuresOutput = getSuSFSFeatures()
            if (featuresOutput.isNotBlank() && featuresOutput != "Invalid") {
                parseEnabledFeaturesFromOutput(context, featuresOutput)
            } else {
                getDefaultDisabledFeatures(context)
            }
        } catch (_: Exception) {
            getDefaultDisabledFeatures(context)
        }
    }

    private fun parseEnabledFeaturesFromOutput(context: Context, featuresOutput: String): List<EnabledFeature> {
        val enabledConfigs = featuresOutput.lines().map { it.trim() }.filter { it.isNotEmpty() }.toSet()
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
            val statusText = if (isEnabled) context.getString(R.string.susfs_feature_enabled) else context.getString(R.string.susfs_feature_disabled)
            EnabledFeature(displayName, isEnabled, statusText, displayName == context.getString(R.string.enable_log_feature_label))
        }.sortedBy { it.name }
    }

    private fun getDefaultDisabledFeatures(context: Context): List<EnabledFeature> {
        val defaults = listOf(
            R.string.sus_path_feature_label,
            R.string.sus_mount_feature_label,
            R.string.spoof_uname_feature_label,
            R.string.spoof_cmdline_feature_label,
            R.string.open_redirect_feature_label,
            R.string.enable_log_feature_label,
            R.string.hide_symbols_feature_label,
            R.string.sus_kstat_feature_label,
            R.string.sus_map_feature_label
        )
        return defaults.map { resId ->
            val displayName = context.getString(resId)
            EnabledFeature(displayName, false, context.getString(R.string.susfs_feature_disabled), displayName == context.getString(R.string.enable_log_feature_label))
        }.sortedBy { it.name }
    }

    // ── setters (persist via ksud + update module) ───────────────────────────

    fun saveUnameValue(context: Context, value: String) {
        configSet(KEY_UNAME_VALUE, value)
    }

    fun saveBuildTimeValue(context: Context, value: String) {
        configSet(KEY_BUILD_TIME_VALUE, value)
    }

    fun saveEnableLogState(context: Context, enabled: Boolean) {
        configSet(KEY_ENABLE_LOG, if (enabled) "true" else "false")
    }

    fun saveExecuteInPostFsData(context: Context, enabled: Boolean) {
        configSet(KEY_EXECUTE_IN_POST_FS_DATA, if (enabled) "true" else "false")
    }

    fun saveHideSusMountsForAllProcs(context: Context, hideForAll: Boolean) {
        configSet(KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS, if (hideForAll) "true" else "false")
    }

    fun saveEnableHideBl(context: Context, enabled: Boolean) {
        configSet(KEY_ENABLE_HIDE_BL, if (enabled) "true" else "false")
    }

    fun saveEnableCleanupResidue(context: Context, enabled: Boolean) {
        configSet(KEY_ENABLE_CLEANUP_RESIDUE, if (enabled) "true" else "false")
    }

    fun saveEnableAvcLogSpoofing(context: Context, enabled: Boolean) {
        configSet(KEY_ENABLE_AVC_LOG_SPOOFING, if (enabled) "true" else "false")
    }

    fun saveSusPaths(context: Context, paths: Set<String>) {
        configSetMulti(KEY_SUS_PATHS, paths, ";")
    }

    fun saveSusLoopPaths(context: Context, paths: Set<String>) {
        configSetMulti(KEY_SUS_LOOP_PATHS, paths, ";")
    }

    fun saveSusMaps(context: Context, maps: Set<String>) {
        configSetMulti(KEY_SUS_MAPS, maps, ";")
    }

    fun saveKstatConfigs(context: Context, configs: Set<String>) {
        configSetMulti(KEY_KSTAT_CONFIGS, configs, ";;")
    }

    fun saveAddKstatPaths(context: Context, paths: Set<String>) {
        configSetMulti(KEY_ADD_KSTAT_PATHS, paths, ";")
    }

    // ── live kernel commands ────────────────────────────────────────────────

    suspend fun setEnableLog(context: Context, enabled: Boolean): Boolean {
        val success = executeSusfsCommand(context, "enable-log ${if (enabled) 1 else 0}")
        if (success) {
            saveEnableLogState(context, enabled)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
        }
        return success
    }

    suspend fun setEnableAvcLogSpoofing(context: Context, enabled: Boolean): Boolean {
        val success = executeSusfsCommand(context, "enable-avc-log-spoofing ${if (enabled) 1 else 0}")
        if (success) {
            saveEnableAvcLogSpoofing(context, enabled)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
        }
        return success
    }

    suspend fun setHideSusMountsForAllProcs(context: Context, hideForAll: Boolean): Boolean {
        val success = executeSusfsCommand(context, "hide-sus-mnts-for-non-su-procs ${if (hideForAll) 1 else 0}")
        if (success) {
            saveHideSusMountsForAllProcs(context, hideForAll)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
        }
        return success
    }

    @SuppressLint("StringFormatMatches")
    suspend fun setUname(context: Context, unameValue: String, buildTimeValue: String): Boolean {
        val success = executeSusfsCommandWithOutput(
            "set-uname ${shellQuote(unameValue)} ${shellQuote(buildTimeValue)}"
        ).isSuccess
        if (success) {
            saveUnameValue(context, unameValue)
            saveBuildTimeValue(context, buildTimeValue)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
        } else {
            showToast(context, context.getString(R.string.susfs_command_failed))
        }
        return success
    }

    // ── SUS path operations ──────────────────────────────────────────────────

    @SuppressLint("StringFormatInvalid")
    private suspend fun addSusPathInternal(context: Context, path: String, showToast: Boolean = true): Boolean {
        val result = executeSusfsCommandWithOutput("add-sus-path '$path'")
        val isActuallySuccessful = result.isSuccess && !result.output.contains("not found, skip adding")
        if (isActuallySuccessful) {
            saveSusPaths(context, getSusPaths(context) + path)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
        } else if (showToast) {
            showToast(context, result.errorOutput.ifEmpty { context.getString(R.string.susfs_command_failed) })
        }
        return isActuallySuccessful
    }

    suspend fun addSusPath(context: Context, path: String): Boolean =
        addSusPathInternal(context, path, showToast = true)

    suspend fun removeSusPath(context: Context, path: String): Boolean {
        saveSusPaths(context, getSusPaths(context) - path)
        if (isAutoStartEnabled(context)) updateMagiskModule(context)
        return true
    }

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
                currentPaths.add(oldPath)
                saveSusPaths(context, currentPaths)
                if (isAutoStartEnabled(context)) updateMagiskModule(context)
                showToast(context, context.getString(R.string.susfs_command_failed))
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Exception editing SUS path", e)
            showToast(context, context.getString(R.string.susfs_command_failed))
            false
        }
    }

    // ── SUS loop path operations ─────────────────────────────────────────────

    @SuppressLint("SdCardPath")
    private fun isValidLoopPath(path: String): Boolean =
        !path.startsWith("/storage/") && !path.startsWith("/sdcard/")

    @SuppressLint("StringFormatInvalid")
    private suspend fun addSusLoopPathInternal(context: Context, path: String, showToast: Boolean = true): Boolean {
        if (!isValidLoopPath(path)) {
            if (showToast) showToast(context, context.getString(R.string.susfs_invalid_loop_path))
            return false
        }
        val result = executeSusfsCommandWithOutput("add-sus-path-loop '$path'")
        val isActuallySuccessful = result.isSuccess && !result.output.contains("not found, skip adding")
        if (isActuallySuccessful) {
            saveSusLoopPaths(context, getSusLoopPaths(context) + path)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
        } else if (showToast) {
            showToast(context, result.errorOutput.ifEmpty { context.getString(R.string.susfs_add_loop_path_failed) })
        }
        return isActuallySuccessful
    }

    suspend fun addSusLoopPath(context: Context, path: String): Boolean =
        addSusLoopPathInternal(context, path, showToast = true)

    suspend fun removeSusLoopPath(context: Context, path: String): Boolean {
        saveSusLoopPaths(context, getSusLoopPaths(context) - path)
        if (isAutoStartEnabled(context)) updateMagiskModule(context)
        return true
    }

    suspend fun editSusLoopPath(context: Context, oldPath: String, newPath: String): Boolean {
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
                currentPaths.add(oldPath)
                saveSusLoopPaths(context, currentPaths)
                if (isAutoStartEnabled(context)) updateMagiskModule(context)
                showToast(context, context.getString(R.string.susfs_edit_loop_path_failed))
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Exception editing SUS loop path", e)
            showToast(context, context.getString(R.string.susfs_edit_loop_path_failed))
            false
        }
    }

    // ── SUS map operations ───────────────────────────────────────────────────

    private suspend fun addSusMapInternal(context: Context, map: String, showToast: Boolean = true): Boolean {
        val result = executeSusfsCommandWithOutput("add-sus-map '$map'")
        val success = result.isSuccess
        if (success) {
            saveSusMaps(context, getSusMaps(context) + map)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
        } else if (showToast) {
            showToast(context, result.errorOutput.ifEmpty { context.getString(R.string.susfs_add_map_failed) })
        }
        return success
    }

    suspend fun addSusMap(context: Context, map: String): Boolean =
        addSusMapInternal(context, map, showToast = true)

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
                currentMaps.add(oldMap)
                saveSusMaps(context, currentMaps)
                if (isAutoStartEnabled(context)) updateMagiskModule(context)
                showToast(context, context.getString(R.string.susfs_edit_map_failed))
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Exception editing SUS map", e)
            showToast(context, context.getString(R.string.susfs_edit_map_failed))
            false
        }
    }

    // ── kstat operations ─────────────────────────────────────────────────────

    private suspend fun addKstatStaticallyInternal(
        context: Context, path: String, ino: String, dev: String, nlink: String,
        size: String, atime: String, atimeNsec: String, mtime: String, mtimeNsec: String,
        ctime: String, ctimeNsec: String, blocks: String, blksize: String
    ): Boolean {
        val command = "add-sus-kstat-statically '$path' '$ino' '$dev' '$nlink' '$size' '$atime' '$atimeNsec' '$mtime' '$mtimeNsec' '$ctime' '$ctimeNsec' '$blocks' '$blksize'"
        val success = executeSusfsCommand(context, command)
        if (success) {
            val entry = "$path|$ino|$dev|$nlink|$size|$atime|$atimeNsec|$mtime|$mtimeNsec|$ctime|$ctimeNsec|$blocks|$blksize"
            saveKstatConfigs(context, getKstatConfigs(context) + entry)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
        }
        return success
    }

    suspend fun addKstatStatically(context: Context, path: String, ino: String, dev: String, nlink: String,
                                   size: String, atime: String, atimeNsec: String, mtime: String, mtimeNsec: String,
                                   ctime: String, ctimeNsec: String, blocks: String, blksize: String): Boolean =
        addKstatStaticallyInternal(context, path, ino, dev, nlink, size, atime, atimeNsec, mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize)

    suspend fun removeKstatConfig(context: Context, config: String): Boolean {
        saveKstatConfigs(context, getKstatConfigs(context) - config)
        if (isAutoStartEnabled(context)) updateMagiskModule(context)
        return true
    }

    @SuppressLint("StringFormatInvalid")
    suspend fun editKstatConfig(context: Context, oldConfig: String, path: String, ino: String, dev: String, nlink: String,
                                size: String, atime: String, atimeNsec: String, mtime: String, mtimeNsec: String,
                                ctime: String, ctimeNsec: String, blocks: String, blksize: String): Boolean {
        return try {
            val currentConfigs = getKstatConfigs(context).toMutableSet()
            if (!currentConfigs.remove(oldConfig)) return false
            saveKstatConfigs(context, currentConfigs)
            val success = addKstatStaticallyInternal(context, path, ino, dev, nlink, size, atime, atimeNsec, mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize)
            if (!success) {
                currentConfigs.add(oldConfig)
                saveKstatConfigs(context, currentConfigs)
                if (isAutoStartEnabled(context)) updateMagiskModule(context)
            }
            success
        } catch (_: Exception) { false }
    }

    private suspend fun addKstatInternal(context: Context, path: String): Boolean {
        val success = executeSusfsCommand(context, "add-sus-kstat '$path'")
        if (success) {
            saveAddKstatPaths(context, getAddKstatPaths(context) + path)
            if (isAutoStartEnabled(context)) updateMagiskModule(context)
        }
        return success
    }

    suspend fun addKstat(context: Context, path: String): Boolean = addKstatInternal(context, path)

    suspend fun removeAddKstat(context: Context, path: String): Boolean {
        saveAddKstatPaths(context, getAddKstatPaths(context) - path)
        if (isAutoStartEnabled(context)) updateMagiskModule(context)
        return true
    }

    @SuppressLint("StringFormatInvalid")
    suspend fun editAddKstat(context: Context, oldPath: String, newPath: String): Boolean {
        return try {
            val currentPaths = getAddKstatPaths(context).toMutableSet()
            if (!currentPaths.remove(oldPath)) return false
            saveAddKstatPaths(context, currentPaths)
            val success = addKstatInternal(context, newPath)
            if (!success) {
                currentPaths.add(oldPath)
                saveAddKstatPaths(context, currentPaths)
                if (isAutoStartEnabled(context)) updateMagiskModule(context)
            }
            success
        } catch (_: Exception) { false }
    }

    suspend fun updateKstat(context: Context, path: String): Boolean =
        executeSusfsCommand(context, "update-sus-kstat '$path'")

    suspend fun updateKstatFullClone(context: Context, path: String): Boolean =
        executeSusfsCommand(context, "update-sus-kstat-full-clone '$path'")

    // ── auto-start control ──────────────────────────────────────────────────

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
                val success = SuSFSModuleManager.createMagiskModule()
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

// ── AppInfoCache ──────────────────────────────────────────────────────────────

object AppInfoCache {
    private val appInfoMap = mutableMapOf<String, CachedAppInfo>()

    data class CachedAppInfo(
        val appName: String,
        val packageInfo: PackageInfo?,
        val drawable: Drawable?,
        val timestamp: Long = System.currentTimeMillis()
    )

    fun getAppInfo(packageName: String): CachedAppInfo? = appInfoMap[packageName]
    fun putAppInfo(packageName: String, appInfo: CachedAppInfo) { appInfoMap[packageName] = appInfo }
    fun clearCache() { appInfoMap.clear() }

    fun getAppInfoFromSuperUser(packageName: String): CachedAppInfo? {
        return SuperUserViewModel.getAppsSafely().find { it.packageName == packageName }?.let { app ->
            CachedAppInfo(appName = app.label, packageInfo = app.packageInfo, drawable = null)
        }
    }
}
