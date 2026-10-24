package com.sukisu.ultra.ui.screen.susfs.util

import android.content.Context
import android.content.pm.PackageInfo
import com.sukisu.ultra.R

data class SlotInfo(
    val slotName: String,
    val uname: String,
    val buildTime: String
)

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
        val obj = org.json.JSONObject()
        obj.put("version", version)
        obj.put("timestamp", timestamp)
        obj.put("deviceInfo", deviceInfo)
        val confObj = org.json.JSONObject()
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
    val enableAvcLogSpoofing: Boolean,
    val cmdlineOrBootconfigPath: String = "",
    val autoStartEnabled: Boolean = false,
) {
    fun hasAutoStartConfig(): Boolean {
        return unameValue != SuSFSConfig.DEFAULT_UNAME ||
                buildTimeValue != SuSFSConfig.DEFAULT_BUILD_TIME ||
                susPaths.isNotEmpty() ||
                susLoopPaths.isNotEmpty() ||
                susMaps.isNotEmpty() ||
                kstatConfigs.isNotEmpty() ||
                addKstatPaths.isNotEmpty() ||
                cmdlineOrBootconfigPath.isNotBlank()
    }
}

internal fun moduleConfigFromValues(values: Map<String, String>): ModuleConfig {
    fun value(key: String): String = values[key].orEmpty().trim()
    fun enabled(key: String): Boolean = value(key) == "true"
    fun entries(key: String, separator: String = ";"): Set<String> =
        values[key].orEmpty().split(separator).filter { it.isNotBlank() }.toSet()

    return ModuleConfig(
        unameValue = value(SuSFSConfig.KEY_UNAME_VALUE).ifBlank { SuSFSConfig.DEFAULT_UNAME },
        buildTimeValue = value(SuSFSConfig.KEY_BUILD_TIME_VALUE).ifBlank { SuSFSConfig.DEFAULT_BUILD_TIME },
        executeInPostFsData = enabled(SuSFSConfig.KEY_EXECUTE_IN_POST_FS_DATA),
        susPaths = entries(SuSFSConfig.KEY_SUS_PATHS),
        susLoopPaths = entries(SuSFSConfig.KEY_SUS_LOOP_PATHS),
        susMaps = entries(SuSFSConfig.KEY_SUS_MAPS),
        enableLog = enabled(SuSFSConfig.KEY_ENABLE_LOG),
        kstatConfigs = entries(SuSFSConfig.KEY_KSTAT_CONFIGS, ";;"),
        addKstatPaths = entries(SuSFSConfig.KEY_ADD_KSTAT_PATHS),
        hideSusMountsForAllProcs = enabled(SuSFSConfig.KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS),
        enableHideBl = enabled(SuSFSConfig.KEY_ENABLE_HIDE_BL),
        enableCleanupResidue = enabled(SuSFSConfig.KEY_ENABLE_CLEANUP_RESIDUE),
        enableAvcLogSpoofing = enabled(SuSFSConfig.KEY_ENABLE_AVC_LOG_SPOOFING),
        cmdlineOrBootconfigPath = value(SuSFSConfig.KEY_CMDLINE_OR_BOOTCONFIG_PATH),
        autoStartEnabled = enabled(SuSFSConfig.KEY_AUTO_START_ENABLED),
    )
}
