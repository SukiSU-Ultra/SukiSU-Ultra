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
    val enableAvcLogSpoofing: Boolean
) {
    fun hasAutoStartConfig(): Boolean {
        return unameValue != SuSFSConfig.DEFAULT_UNAME ||
                buildTimeValue != SuSFSConfig.DEFAULT_BUILD_TIME ||
                susPaths.isNotEmpty() ||
                susLoopPaths.isNotEmpty() ||
                susMaps.isNotEmpty() ||
                kstatConfigs.isNotEmpty() ||
                addKstatPaths.isNotEmpty()
    }
}
