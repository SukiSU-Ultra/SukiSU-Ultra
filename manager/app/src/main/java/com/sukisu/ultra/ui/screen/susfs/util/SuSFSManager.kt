package com.sukisu.ultra.ui.screen.susfs.util

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageInfo
import android.graphics.drawable.Drawable
import android.os.Build
import android.util.Log
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.execKsud
import com.sukisu.ultra.ui.util.getKsuDaemonPath
import com.sukisu.ultra.ui.util.getRootShell
import com.sukisu.ultra.ui.util.getSuSFSFeatures
import com.sukisu.ultra.ui.util.getSuSFSVersion
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import androidx.core.content.edit
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel.Companion.getAppsSafely
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object SuSFSManager {
    private const val PREFS_NAME = "susfs_config"
    private const val DEFAULT_UNAME = "default"
    private const val DEFAULT_BUILD_TIME = "default"

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
        val packageInfo: PackageInfo? = null
    )

    data class ModuleConfig(
        val unameValue: String,
        val buildTimeValue: String,
        val executeInPostFsData: Boolean,
        val autoStartEnabled: Boolean,
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
    )

    private fun getPrefs(context: Context): SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun runCmd(shell: Shell, cmd: String): String {
        return shell.newJob()
            .add(cmd)
            .to(mutableListOf<String>(), null)
            .exec().out
            .joinToString("\n")
    }

    // 获取当前配置
    suspend fun getCurrentModuleConfig(context: Context): ModuleConfig = withContext(Dispatchers.IO) {
        try {
            val shell = getRootShell()
            val output = runCmd(shell, "${getKsuDaemonPath()} susfs config-get")
            if (output.isNotBlank()) {
                parseConfigFromJson(output)
            } else {
                getDefaultConfig(context)
            }
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to get config", e)
            getDefaultConfig(context)
        }
    }

    private fun getDefaultConfig(context: Context): ModuleConfig {
        return ModuleConfig(
            unameValue = DEFAULT_UNAME,
            buildTimeValue = DEFAULT_BUILD_TIME,
            executeInPostFsData = getPrefs(context).getBoolean("execute_in_post_fs_data", false),
            autoStartEnabled = getPrefs(context).getBoolean("auto_start_enabled", false),
            susPaths = getPrefs(context).getStringSet("sus_paths", emptySet()) ?: emptySet(),
            susLoopPaths = getPrefs(context).getStringSet("sus_loop_paths", emptySet()) ?: emptySet(),
            susMaps = getPrefs(context).getStringSet("sus_maps", emptySet()) ?: emptySet(),
            enableLog = getPrefs(context).getBoolean("enable_log", false),
            kstatConfigs = getPrefs(context).getStringSet("kstat_configs", emptySet()) ?: emptySet(),
            addKstatPaths = getPrefs(context).getStringSet("add_kstat_paths", emptySet()) ?: emptySet(),
            hideSusMountsForAllProcs = getPrefs(context).getBoolean("hide_sus_mounts", true),
            enableHideBl = getPrefs(context).getBoolean("enable_hide_bl", true),
            enableCleanupResidue = getPrefs(context).getBoolean("enable_cleanup_residue", false),
            enableAvcLogSpoofing = getPrefs(context).getBoolean("enable_avc_log_spoofing", false)
        )
    }

    private fun parseConfigFromJson(json: String): ModuleConfig {
        return try {
            val obj = JSONObject(json)
            ModuleConfig(
                unameValue = obj.optString("uname_value", DEFAULT_UNAME),
                buildTimeValue = obj.optString("build_time_value", DEFAULT_BUILD_TIME),
                executeInPostFsData = obj.optBoolean("execute_in_post_fs_data", false),
                autoStartEnabled = obj.optBoolean("auto_start_enabled", false),
                susPaths = obj.optJSONArray("sus_paths")?.let { arr ->
                    (0 until arr.length()).map { arr.getString(it) }.toSet()
                } ?: emptySet(),
                susLoopPaths = obj.optJSONArray("sus_loop_paths")?.let { arr ->
                    (0 until arr.length()).map { arr.getString(it) }.toSet()
                } ?: emptySet(),
                susMaps = obj.optJSONArray("sus_maps")?.let { arr ->
                    (0 until arr.length()).map { arr.getString(it) }.toSet()
                } ?: emptySet(),
                enableLog = obj.optBoolean("enable_log", false),
                kstatConfigs = obj.optJSONArray("kstat_configs")?.let { arr ->
                    (0 until arr.length()).map { arr.getString(it) }.toSet()
                } ?: emptySet(),
                addKstatPaths = obj.optJSONArray("add_kstat_paths")?.let { arr ->
                    (0 until arr.length()).map { arr.getString(it) }.toSet()
                } ?: emptySet(),
                hideSusMountsForAllProcs = obj.optBoolean("hide_sus_mounts_for_all_procs", true),
                enableHideBl = obj.optBoolean("enable_hide_bl", true),
                enableCleanupResidue = obj.optBoolean("enable_cleanup_residue", false),
                enableAvcLogSpoofing = obj.optBoolean("enable_avc_log_spoofing", false)
            )
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to parse config", e)
            throw e
        }
    }

    // 配置存取方法
    fun saveUnameValue(context: Context, value: String) {
        getPrefs(context).edit { putString("uname_value", value) }
        execKsud("susfs config-set-uname '$value'")
    }

    fun getUnameValue(context: Context): String =
        getPrefs(context).getString("uname_value", DEFAULT_UNAME) ?: DEFAULT_UNAME

    fun saveBuildTimeValue(context: Context, value: String) {
        getPrefs(context).edit { putString("build_time_value", value) }
        execKsud("susfs config-set-build-time '$value'")
    }

    fun getBuildTimeValue(context: Context): String =
        getPrefs(context).getString("build_time_value", DEFAULT_BUILD_TIME) ?: DEFAULT_BUILD_TIME

    fun setAutoStartEnabled(context: Context, enabled: Boolean) {
        getPrefs(context).edit { putBoolean("auto_start_enabled", enabled) }
    }

    fun isAutoStartEnabled(context: Context): Boolean =
        getPrefs(context).getBoolean("auto_start_enabled", false)

    fun saveEnableLogState(context: Context, enabled: Boolean) {
        getPrefs(context).edit { putBoolean("enable_log", enabled) }
    }

    fun getEnableLogState(context: Context): Boolean =
        getPrefs(context).getBoolean("enable_log", false)

    fun getExecuteInPostFsData(context: Context): Boolean =
        getPrefs(context).getBoolean("execute_in_post_fs_data", false)

    fun saveExecuteInPostFsData(context: Context, enabled: Boolean) {
        getPrefs(context).edit { putBoolean("execute_in_post_fs_data", enabled) }
        execKsud("susfs config-set-execute-in-post-fs-data ${if (enabled) 1 else 0}")
    }

    fun saveHideSusMountsForAllProcs(context: Context, hideForAll: Boolean) {
        getPrefs(context).edit { putBoolean("hide_sus_mounts", hideForAll) }
        execKsud("susfs hide-sus-mnts ${if (hideForAll) 1 else 0}")
    }

    fun getHideSusMountsForAllProcs(context: Context): Boolean =
        getPrefs(context).getBoolean("hide_sus_mounts", true)

    fun saveEnableHideBl(context: Context, enabled: Boolean) {
        getPrefs(context).edit { putBoolean("enable_hide_bl", enabled) }
        execKsud("susfs config-set-hide-bl ${if (enabled) 1 else 0}")
    }

    fun getEnableHideBl(context: Context): Boolean =
        getPrefs(context).getBoolean("enable_hide_bl", true)

    fun saveEnableCleanupResidue(context: Context, enabled: Boolean) {
        getPrefs(context).edit { putBoolean("enable_cleanup_residue", enabled) }
        execKsud("susfs config-set-cleanup-residue ${if (enabled) 1 else 0}")
    }

    fun getEnableCleanupResidue(context: Context): Boolean =
        getPrefs(context).getBoolean("enable_cleanup_residue", false)

    fun saveEnableAvcLogSpoofing(context: Context, enabled: Boolean) {
        getPrefs(context).edit { putBoolean("enable_avc_log_spoofing", enabled) }
        execKsud("susfs enable-avc-log-spoofing ${if (enabled) 1 else 0}")
    }

    fun getEnableAvcLogSpoofing(context: Context): Boolean =
        getPrefs(context).getBoolean("enable_avc_log_spoofing", false)

    fun saveSusPaths(context: Context, paths: Set<String>) =
        getPrefs(context).edit { putStringSet("sus_paths", paths) }

    fun getSusPaths(context: Context): Set<String> =
        getPrefs(context).getStringSet("sus_paths", emptySet()) ?: emptySet()

    fun saveSusLoopPaths(context: Context, paths: Set<String>) =
        getPrefs(context).edit { putStringSet("sus_loop_paths", paths) }

    fun getSusLoopPaths(context: Context): Set<String> =
        getPrefs(context).getStringSet("sus_loop_paths", emptySet()) ?: emptySet()

    fun saveSusMaps(context: Context, maps: Set<String>) =
        getPrefs(context).edit { putStringSet("sus_maps", maps) }

    fun getSusMaps(context: Context): Set<String> =
        getPrefs(context).getStringSet("sus_maps", emptySet()) ?: emptySet()

    fun saveKstatConfigs(context: Context, configs: Set<String>) =
        getPrefs(context).edit { putStringSet("kstat_configs", configs) }

    fun getKstatConfigs(context: Context): Set<String> =
        getPrefs(context).getStringSet("kstat_configs", emptySet()) ?: emptySet()

    fun saveAddKstatPaths(context: Context, paths: Set<String>) =
        getPrefs(context).edit {putStringSet("add_kstat_paths", paths) }

    fun getAddKstatPaths(context: Context): Set<String> =
        getPrefs(context).getStringSet("add_kstat_paths", emptySet()) ?: emptySet()

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

    // SUS日志开关
    suspend fun setEnableLog(context: Context, enabled: Boolean): Boolean = withContext(Dispatchers.IO) {
        try {
            val success = execKsud("susfs enable-log ${if (enabled) 1 else 0}")
            if (success) {
                saveEnableLogState(context, enabled)
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to set enable log", e)
            false
        }
    }

    // AVC日志欺骗开关
    suspend fun setEnableAvcLogSpoofing(context: Context, enabled: Boolean): Boolean = withContext(Dispatchers.IO) {
        try {
            val success = execKsud("susfs enable-avc-log-spoofing ${if (enabled) 1 else 0}")
            if (success) {
                saveEnableAvcLogSpoofing(context, enabled)
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to set AVC log spoofing", e)
            false
        }
    }

    // SUS挂载隐藏控制
    suspend fun setHideSusMountsForAllProcs(context: Context, hideForAll: Boolean): Boolean = withContext(Dispatchers.IO) {
        try {
            val success = execKsud("susfs hide-sus-mnts ${if (hideForAll) 1 else 0}")
            if (success) {
                saveHideSusMountsForAllProcs(context, hideForAll)
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to set hide sus mounts", e)
            false
        }
    }

    // uname和构建时间
    suspend fun setUname(context: Context, unameValue: String, buildTimeValue: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val success = execKsud("susfs set-uname '$unameValue' '$buildTimeValue'")
            if (success) {
                saveUnameValue(context, unameValue)
                saveBuildTimeValue(context, buildTimeValue)
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to set uname", e)
            false
        }
    }

    // 添加SUS路径
    suspend fun addSusPath(context: Context, path: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val success = execKsud("susfs add-sus-path '$path'")
            if (success) {
                val paths = getSusPaths(context) + path
                saveSusPaths(context, paths)
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to add SUS path", e)
            false
        }
    }

    suspend fun removeSusPath(context: Context, path: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val paths = getSusPaths(context) - path
            saveSusPaths(context, paths)
            execKsud("susfs remove-sus-path '$path'")
            true
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to remove SUS path", e)
            false
        }
    }

    suspend fun editSusPath(context: Context, oldPath: String, newPath: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val paths = getSusPaths(context).toMutableSet()
            if (!paths.remove(oldPath)) {
                return@withContext false
            }
            val success = execKsud("susfs add-sus-path '$newPath'")
            if (success) {
                paths.add(newPath)
                saveSusPaths(context, paths)
            } else {
                paths.add(oldPath)
                saveSusPaths(context, paths)
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to edit SUS path", e)
            false
        }
    }

    // 循环路径
    suspend fun addSusLoopPath(context: Context, path: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val success = execKsud("susfs add-sus-path-loop '$path'")
            if (success) {
                val paths = getSusLoopPaths(context) + path
                saveSusLoopPaths(context, paths)
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to add SUS loop path", e)
            false
        }
    }

    suspend fun removeSusLoopPath(context: Context, path: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val paths = getSusLoopPaths(context) - path
            saveSusLoopPaths(context, paths)
            true
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to remove SUS loop path", e)
            false
        }
    }

    suspend fun editSusLoopPath(context: Context, oldPath: String, newPath: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val paths = getSusLoopPaths(context).toMutableSet()
            if (!paths.remove(oldPath)) {
                return@withContext false
            }
            val success = execKsud("susfs add-sus-path-loop '$newPath'")
            if (success) {
                paths.add(newPath)
                saveSusLoopPaths(context, paths)
            } else {
                paths.add(oldPath)
                saveSusLoopPaths(context, paths)
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to edit SUS loop path", e)
            false
        }
    }

    // SUS Maps
    suspend fun addSusMap(context: Context, map: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val success = execKsud("susfs add-sus-map '$map'")
            if (success) {
                val maps = getSusMaps(context) + map
                saveSusMaps(context, maps)
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to add SUS map", e)
            false
        }
    }

    suspend fun removeSusMap(context: Context, map: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val maps = getSusMaps(context) - map
            saveSusMaps(context, maps)
            execKsud("susfs remove-sus-map '$map'")
            true
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to remove SUS map", e)
            false
        }
    }

    suspend fun editSusMap(context: Context, oldMap: String, newMap: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val maps = getSusMaps(context).toMutableSet()
            if (!maps.remove(oldMap)) {
                return@withContext false
            }
            val success = execKsud("susfs add-sus-map '$newMap'")
            if (success) {
                maps.add(newMap)
                saveSusMaps(context, maps)
            } else {
                maps.add(oldMap)
                saveSusMaps(context, maps)
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to edit SUS map", e)
            false
        }
    }

    // Kstat配置
    suspend fun addKstatStatically(context: Context, path: String, ino: String, dev: String, nlink: String,
                                   size: String, atime: String, atimeNsec: String, mtime: String, mtimeNsec: String,
                                   ctime: String, ctimeNsec: String, blocks: String, blksize: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val success = execKsud("susfs add-kstat-statically '$path' '$ino' '$dev' '$nlink' '$size' '$atime' '$atimeNsec' '$mtime' '$mtimeNsec' '$ctime' '$ctimeNsec' '$blocks' '$blksize'")
            if (success) {
                val configEntry = "$path|$ino|$dev|$nlink|$size|$atime|$atimeNsec|$mtime|$mtimeNsec|$ctime|$ctimeNsec|$blocks|$blksize"
                val configs = getKstatConfigs(context) + configEntry
                saveKstatConfigs(context, configs)
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to add Kstat statically", e)
            false
        }
    }

    suspend fun removeKstatConfig(context: Context, config: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val configs = getKstatConfigs(context) - config
            saveKstatConfigs(context, configs)
            execKsud("susfs remove-kstat-config '$config'")
            true
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to remove Kstat config", e)
            false
        }
    }

    // Kstat路径
    suspend fun addKstat(context: Context, path: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val success = execKsud("susfs add-kstat '$path'")
            if (success) {
                val paths = getAddKstatPaths(context) + path
                saveAddKstatPaths(context, paths)
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to add Kstat", e)
            false
        }
    }

    suspend fun removeAddKstat(context: Context, path: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val paths = getAddKstatPaths(context) - path
            saveAddKstatPaths(context, paths)
            execKsud("susfs remove-kstat '$path'")
            true
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to remove Kstat", e)
            false
        }
    }

    suspend fun editAddKstat(context: Context, oldPath: String, newPath: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val paths = getAddKstatPaths(context).toMutableSet()
            if (!paths.remove(oldPath)) {
                return@withContext false
            }
            val success = execKsud("susfs add-kstat '$newPath'")
            if (success) {
                paths.add(newPath)
                saveAddKstatPaths(context, paths)
            } else {
                paths.add(oldPath)
                saveAddKstatPaths(context, paths)
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to edit Kstat", e)
            false
        }
    }

    suspend fun updateKstat(path: String): Boolean = withContext(Dispatchers.IO) {
        execKsud("susfs update-kstat '$path'")
    }

    suspend fun updateKstatFullClone(path: String): Boolean = withContext(Dispatchers.IO) {
        execKsud("susfs update-kstat-full-clone '$path'")
    }

    fun hasConfigurationForAutoStart(context: Context): Boolean {
        val config = getDefaultConfig(context)
        return config.unameValue != DEFAULT_UNAME ||
                config.buildTimeValue != DEFAULT_BUILD_TIME ||
                config.susPaths.isNotEmpty() ||
                config.susLoopPaths.isNotEmpty() ||
                config.susMaps.isNotEmpty() ||
                config.kstatConfigs.isNotEmpty() ||
                config.addKstatPaths.isNotEmpty() ||
                config.enableLog
    }

    suspend fun configureAutoStart(context: Context, enabled: Boolean): Boolean = withContext(Dispatchers.IO) {
        try {
            if (enabled) {
                if (!hasConfigurationForAutoStart(context)) {
                    Log.e("SuSFSManager", "No configuration available for auto start")
                    return@withContext false
                }
                val success = execKsud("susfs module-create")
                if (success) {
                    setAutoStartEnabled(context, true)
                }
                success
            } else {
                val success = execKsud("susfs module-remove")
                if (success) {
                    setAutoStartEnabled(context, false)
                }
                success
            }
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to configure auto start", e)
            false
        }
    }

    suspend fun resetToDefault(context: Context): Boolean = withContext(Dispatchers.IO) {
        try {
            val success = execKsud("susfs config-reset")
            if (success) {
                saveUnameValue(context, DEFAULT_UNAME)
                saveBuildTimeValue(context, DEFAULT_BUILD_TIME)
                if (isAutoStartEnabled(context)) {
                    configureAutoStart(context, false)
                }
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to reset to default", e)
            false
        }
    }

    // 槽位信息获取
    suspend fun getCurrentSlotInfo(): List<SlotInfo> = withContext(Dispatchers.IO) {
        try {
            val slotInfoList = mutableListOf<SlotInfo>()
            val shell = getRootShell()

            listOf("boot_a", "boot_b").forEach { slot ->
                val unameCmd =
                    $$"strings -n 20 /dev/block/by-name/$$slot | awk '/Linux version/ && ++c==2 {print $3; exit}'"
                val buildTimeCmd = "strings -n 20 /dev/block/by-name/$slot | sed -n '/Linux version.*#/ {s/.*#/#/p;q}'"

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
            val shell = getRootShell()
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

    // Backup data class
    data class BackupData(
        val version: String,
        val timestamp: Long,
        val deviceInfo: String,
        val configurations: Map<String, Any>
    ) {
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

        fun toJson(): String {
            val jsonObject = JSONObject().apply {
                put("version", version)
                put("timestamp", timestamp)
                put("deviceInfo", deviceInfo)
                put("configurations", JSONObject(configurations))
            }
            return jsonObject.toString(2)
        }
    }

    // 获取备份文件名
    fun getDefaultBackupFileName(): String {
        val dateFormat = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault())
        val timestamp = dateFormat.format(Date())
        return "SuSFS_Config_$timestamp.susfs_backup"
    }

    // 创建文件备份
    suspend fun createBackup(context: Context, backupFilePath: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val config = getCurrentModuleConfig(context)
            val backupData = BackupData(
                version = getSuSFSVersion(),
                timestamp = System.currentTimeMillis(),
                deviceInfo = "${Build.MANUFACTURER} ${Build.MODEL} (${Build.VERSION.RELEASE})",
                configurations = mapOf(
                    "uname_value" to config.unameValue,
                    "build_time_value" to config.buildTimeValue,
                    "execute_in_post_fs_data" to config.executeInPostFsData,
                    "sus_paths" to config.susPaths,
                    "sus_loop_paths" to config.susLoopPaths,
                    "sus_maps" to config.susMaps,
                    "enable_log" to config.enableLog,
                    "kstat_configs" to config.kstatConfigs,
                    "add_kstat_paths" to config.addKstatPaths,
                    "hide_sus_mounts_for_all_procs" to config.hideSusMountsForAllProcs,
                    "enable_hide_bl" to config.enableHideBl,
                    "enable_cleanup_residue" to config.enableCleanupResidue,
                    "enable_avc_log_spoofing" to config.enableAvcLogSpoofing
                )
            )

            val backupFile = File(backupFilePath)
            backupFile.parentFile?.mkdirs()
            backupFile.writeText(backupData.toJson())
            true
        } catch (e: Exception) {
            e.printStackTrace()
            false
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

    // 从备份还原
    suspend fun restoreFromBackup(context: Context, backupFilePath: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val backupData = validateBackupFile(backupFilePath) ?: return@withContext false

            val prefs = getPrefs(context)
            prefs.edit {
                backupData.configurations.forEach { (key, value) ->
                    when (value) {
                        is String -> putString(key, value)
                        is Boolean -> putBoolean(key, value)
                        is Set<*> -> {
                            @Suppress("UNCHECKED_CAST")
                            putStringSet(key, value as Set<String>)
                        }
                    }
                }
            }

            true
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    // 获取已安装的应用列表
    suspend fun getInstalledApps(): List<AppInfo> = withContext(Dispatchers.IO) {
        try {
            val shell = getRootShell()
            val output = runCmd(shell, "${getKsuDaemonPath()} susfs list-apps")
            if (output.isNotBlank()) {
                output.lines().mapNotNull { line ->
                    val parts = line.split("|")
                    if (parts.size >= 2) {
                        AppInfo(packageName = parts[0], appName = parts[1])
                    } else null
                }
            } else {
                emptyList()
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    // 编辑Kstat配置
    suspend fun editKstatConfig(
        context: Context,
        oldConfig: String,
        path: String,
        ino: String,
        dev: String,
        nlink: String,
        size: String,
        atime: String,
        atimeNsec: String,
        mtime: String,
        mtimeNsec: String,
        ctime: String,
        ctimeNsec: String,
        blocks: String,
        blksize: String
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            val configs = getKstatConfigs(context).toMutableSet()
            if (!configs.remove(oldConfig)) {
                return@withContext false
            }
            saveKstatConfigs(context, configs)

            val success = addKstatStatically(context, path, ino, dev, nlink, size, atime, atimeNsec, mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize)
            if (!success) {
                configs.add(oldConfig)
                saveKstatConfigs(context, configs)
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to edit Kstat config", e)
            false
        }
    }

    // 添加应用路径快捷方式
    @SuppressLint("SdCardPath")
    suspend fun addAppPaths(context: Context, packageName: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val androidDataPath = "/sdcard/Android/data"
            val mediaDataPath = "/data/media/0/Android/data"

            var successCount = 0

            val path1 = "$androidDataPath/$packageName"
            if (addSusPath(context, path1)) successCount++

            val path2 = "$mediaDataPath/$packageName"
            if (addSusPath(context, path2)) successCount++

            successCount > 0
        } catch (e: Exception) {
            Log.e("SuSFSManager", "Failed to add app paths", e)
            false
        }
    }
}

object AppInfoCache {
    private val appInfoMap = mutableMapOf<String, CachedAppInfo>()

    data class CachedAppInfo(
        val appName: String,
        val packageInfo: PackageInfo?,
        val drawable: Drawable?
    )

    fun getAppInfo(packageName: String): CachedAppInfo? = appInfoMap[packageName]

    fun putAppInfo(packageName: String, appInfo: CachedAppInfo) {
        appInfoMap[packageName] = appInfo
    }

    fun clearCache() = appInfoMap.clear()

    fun getAppInfoFromSuperUser(packageName: String): CachedAppInfo? {
        val superUserApp = getAppsSafely().find { it.packageName == packageName }
        return superUserApp?.let { app ->
            CachedAppInfo(
                appName = app.label,
                packageInfo = app.packageInfo,
                drawable = null
            )
        }
    }
}
