package com.sukisu.ultra.ui.screen.susfs.util

import android.content.Context
import android.os.Build
import android.widget.Toast
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.getSuSFSVersion
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object SuSFSBackupManager {
    private fun getAllConfigurations(): Map<String, Any> = runBlocking(Dispatchers.IO) {
        mapOf(
            SuSFSConfig.KEY_UNAME_VALUE to getUnameValueInternal(),
            SuSFSConfig.KEY_BUILD_TIME_VALUE to getBuildTimeValueInternal(),
            SuSFSConfig.KEY_AUTO_START_ENABLED to isAutoStartEnabledInternal(),
            SuSFSConfig.KEY_SUS_PATHS to getSusPathsInternal(),
            SuSFSConfig.KEY_SUS_LOOP_PATHS to getSusLoopPathsInternal(),
            SuSFSConfig.KEY_SUS_MAPS to getSusMapsInternal(),
            SuSFSConfig.KEY_ENABLE_LOG to getEnableLogStateInternal(),
            SuSFSConfig.KEY_EXECUTE_IN_POST_FS_DATA to getExecuteInPostFsDataInternal(),
            SuSFSConfig.KEY_KSTAT_CONFIGS to getKstatConfigsInternal(),
            SuSFSConfig.KEY_ADD_KSTAT_PATHS to getAddKstatPathsInternal(),
            SuSFSConfig.KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS to getHideSusMountsForAllProcsInternal(),
            SuSFSConfig.KEY_ENABLE_HIDE_BL to getEnableHideBlInternal(),
            SuSFSConfig.KEY_ENABLE_CLEANUP_RESIDUE to getEnableCleanupResidueInternal(),
            SuSFSConfig.KEY_ENABLE_AVC_LOG_SPOOFING to getEnableAvcLogSpoofingInternal()
        )
    }

    private suspend fun getUnameValueInternal(): String {
        val v = SuSFSConfig.get(SuSFSConfig.KEY_UNAME_VALUE)
        return v.ifBlank { SuSFSConfig.DEFAULT_UNAME }
    }

    private suspend fun getBuildTimeValueInternal(): String {
        val v = SuSFSConfig.get(SuSFSConfig.KEY_BUILD_TIME_VALUE)
        return v.ifBlank { SuSFSConfig.DEFAULT_BUILD_TIME }
    }

    private suspend fun isAutoStartEnabledInternal(): Boolean =
        SuSFSConfig.get(SuSFSConfig.KEY_AUTO_START_ENABLED) == "true"

    private suspend fun getSusPathsInternal(): Set<String> =
        SuSFSConfig.getMulti(SuSFSConfig.KEY_SUS_PATHS)

    private suspend fun getSusLoopPathsInternal(): Set<String> =
        SuSFSConfig.getMulti(SuSFSConfig.KEY_SUS_LOOP_PATHS)

    private suspend fun getSusMapsInternal(): Set<String> =
        SuSFSConfig.getMulti(SuSFSConfig.KEY_SUS_MAPS)

    private suspend fun getEnableLogStateInternal(): Boolean =
        SuSFSConfig.get(SuSFSConfig.KEY_ENABLE_LOG) == "true"

    private suspend fun getExecuteInPostFsDataInternal(): Boolean =
        SuSFSConfig.get(SuSFSConfig.KEY_EXECUTE_IN_POST_FS_DATA) == "true"

    private suspend fun getKstatConfigsInternal(): Set<String> =
        SuSFSConfig.getMulti(SuSFSConfig.KEY_KSTAT_CONFIGS, ";;")

    private suspend fun getAddKstatPathsInternal(): Set<String> =
        SuSFSConfig.getMulti(SuSFSConfig.KEY_ADD_KSTAT_PATHS)

    private suspend fun getHideSusMountsForAllProcsInternal(): Boolean {
        val v = SuSFSConfig.get(SuSFSConfig.KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS)
        return v.isBlank() || v == "true"
    }

    private suspend fun getEnableHideBlInternal(): Boolean {
        val v = SuSFSConfig.get(SuSFSConfig.KEY_ENABLE_HIDE_BL)
        return v.isBlank() || v == "true"
    }

    private suspend fun getEnableCleanupResidueInternal(): Boolean =
        SuSFSConfig.get(SuSFSConfig.KEY_ENABLE_CLEANUP_RESIDUE) == "true"

    private suspend fun getEnableAvcLogSpoofingInternal(): Boolean =
        SuSFSConfig.get(SuSFSConfig.KEY_ENABLE_AVC_LOG_SPOOFING) == "true"

    private fun generateBackupFileName(): String {
        val df = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault())
        return "SuSFS_Config_${df.format(Date())}${SuSFSConfig.BACKUP_FILE_EXTENSION}"
    }

    private fun getDeviceInfo(): String =
        try { "${Build.MANUFACTURER} ${Build.MODEL} (${Build.VERSION.RELEASE})" } catch (_: Exception) { "Unknown Device" }

    private suspend fun showToast(context: Context, message: String) = withContext(Dispatchers.Main) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
    }

    suspend fun createBackup(context: Context, backupFilePath: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val backupData = BackupData(
                version = getSuSFSVersion(),
                timestamp = System.currentTimeMillis(),
                deviceInfo = getDeviceInfo(),
                configurations = getAllConfigurations()
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
            val obj = org.json.JSONObject(f.readText())
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
            if (SuSFSRepository.isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()

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

    private suspend fun restoreConfigurations(configurations: Map<String, Any>) {
        configurations.forEach { (key, value) ->
            when (value) {
                is String -> SuSFSConfig.set(key, value)
                is Boolean -> SuSFSConfig.set(key, if (value) "true" else "false")
                is Set<*> -> {
                    val set = value.filterIsInstance<String>().toSet()
                    val sep = if (key == SuSFSConfig.KEY_KSTAT_CONFIGS) ";;" else ";"
                    SuSFSConfig.setMulti(key, set, sep)
                }
            }
        }
    }

    suspend fun validateBackupFile(backupFilePath: String): BackupData? = withContext(Dispatchers.IO) {
        try {
            val f = File(backupFilePath)
            if (!f.exists()) return@withContext null
            val obj = org.json.JSONObject(f.readText())
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
}
