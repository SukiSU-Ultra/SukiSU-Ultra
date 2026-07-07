package com.sukisu.ultra.ui.screen.susfs.util

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext

object SuSFSManager {
    fun getCurrentModuleConfig(): ModuleConfig = SuSFSRepository.getCurrentModuleConfig()

    fun getKernelSpoofRelease(): String = SuSFSRepository.getKernelSpoofRelease()
    fun getKernelSpoofVersion(): String = SuSFSRepository.getKernelSpoofVersion()

    suspend fun isAutoStartEnabled(): Boolean = SuSFSRepository.isAutoStartEnabled()
    suspend fun setAutoStartEnabled(enabled: Boolean) = SuSFSRepository.setAutoStartEnabled(enabled)

    suspend fun getEnableLogState(): Boolean = SuSFSRepository.getEnableLogState()
    suspend fun getEnabledFeatures(context: Context): List<EnabledFeature> = SuSFSCommands.getEnabledFeatures(context)

    suspend fun getInstalledApps(): List<AppInfo> = SuSFSPathManager.getInstalledApps()
    suspend fun getCurrentSlotInfo(): List<SlotInfo> = SuSFSCommands.getCurrentSlotInfo()
    suspend fun getCurrentActiveSlot(): String = SuSFSCommands.getCurrentActiveSlot()

    suspend fun saveUnameValue(value: String) = SuSFSRepository.saveUnameValue(value)
    suspend fun saveBuildTimeValue(value: String) = SuSFSRepository.saveBuildTimeValue(value)
    suspend fun saveEnableLogState(enabled: Boolean) = SuSFSRepository.saveEnableLogState(enabled)
    suspend fun saveExecuteInPostFsData(enabled: Boolean) = SuSFSRepository.saveExecuteInPostFsData(enabled)
    suspend fun saveHideSusMountsForAllProcs(hideForAll: Boolean) = SuSFSRepository.saveHideSusMountsForAllProcs(hideForAll)
    suspend fun saveEnableHideBl(enabled: Boolean) = SuSFSRepository.saveEnableHideBl(enabled)
    suspend fun saveEnableCleanupResidue(enabled: Boolean) = SuSFSRepository.saveEnableCleanupResidue(enabled)
    suspend fun saveEnableAvcLogSpoofing(enabled: Boolean) = SuSFSRepository.saveEnableAvcLogSpoofing(enabled)
    suspend fun saveSusPaths(paths: Set<String>) = SuSFSRepository.saveSusPaths(paths)
    suspend fun saveSusLoopPaths(paths: Set<String>) = SuSFSRepository.saveSusLoopPaths(paths)
    suspend fun saveSusMaps(maps: Set<String>) = SuSFSRepository.saveSusMaps(maps)
    suspend fun saveKstatConfigs(configs: Set<String>) = SuSFSRepository.saveKstatConfigs(configs)
    suspend fun saveAddKstatPaths(paths: Set<String>) = SuSFSRepository.saveAddKstatPaths(paths)

    suspend fun setEnableLog(context: Context, enabled: Boolean): Boolean = SuSFSRepository.setEnableLog(context, enabled)
    suspend fun setEnableAvcLogSpoofing(context: Context, enabled: Boolean): Boolean = SuSFSRepository.setEnableAvcLogSpoofing(context, enabled)
    suspend fun setHideSusMountsForAllProcs(context: Context, hideForAll: Boolean): Boolean = SuSFSRepository.setHideSusMountsForAllProcs(context, hideForAll)
    suspend fun setUname(context: Context, unameValue: String, buildTimeValue: String): Boolean = SuSFSRepository.setUname(context, unameValue, buildTimeValue)

    suspend fun addSusPath(context: Context, path: String): Boolean = SuSFSPathManager.addSusPath(context, path)
    suspend fun removeSusPath(path: String): Boolean = SuSFSPathManager.removeSusPath(path)
    suspend fun editSusPath(context: Context, oldPath: String, newPath: String): Boolean = SuSFSPathManager.editSusPath(context, oldPath, newPath)
    suspend fun addSusLoopPath(context: Context, path: String): Boolean = SuSFSPathManager.addSusLoopPath(context, path)
    suspend fun removeSusLoopPath(path: String): Boolean = SuSFSPathManager.removeSusLoopPath(path)
    suspend fun editSusLoopPath(context: Context, oldPath: String, newPath: String): Boolean = SuSFSPathManager.editSusLoopPath(context, oldPath, newPath)
    suspend fun addSusMap(context: Context, map: String): Boolean = SuSFSPathManager.addSusMap(context, map)
    suspend fun removeSusMap(map: String): Boolean = SuSFSPathManager.removeSusMap(map)
    suspend fun editSusMap(context: Context, oldMap: String, newMap: String): Boolean = SuSFSPathManager.editSusMap(context, oldMap, newMap)
    suspend fun addAppPaths(context: Context, packageName: String): Boolean = SuSFSPathManager.addAppPaths(context, packageName)

    suspend fun addKstatStatically(context: Context, path: String, ino: String, dev: String, nlink: String,
                                  size: String, atime: String, atimeNsec: String, mtime: String, mtimeNsec: String,
                                  ctime: String, ctimeNsec: String, blocks: String, blksize: String): Boolean =
        SuSFSPathManager.addKstatStatically(context, path, ino, dev, nlink, size, atime, atimeNsec, mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize)

    suspend fun removeKstatConfig(config: String): Boolean = SuSFSPathManager.removeKstatConfig(config)
    suspend fun editKstatConfig(context: Context, oldConfig: String, path: String, ino: String, dev: String, nlink: String,
                               size: String, atime: String, atimeNsec: String, mtime: String, mtimeNsec: String,
                               ctime: String, ctimeNsec: String, blocks: String, blksize: String): Boolean =
        SuSFSPathManager.editKstatConfig(context, oldConfig, path, ino, dev, nlink, size, atime, atimeNsec, mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize)

    suspend fun addKstat(context: Context, path: String): Boolean = SuSFSPathManager.addKstat(context, path)
    suspend fun removeAddKstat(path: String): Boolean = SuSFSPathManager.removeAddKstat(path)
    suspend fun editAddKstat(context: Context, oldPath: String, newPath: String): Boolean = SuSFSPathManager.editAddKstat(context, oldPath, newPath)
    suspend fun updateKstat(context: Context, path: String): Boolean = SuSFSPathManager.updateKstat(context, path)
    suspend fun updateKstatFullClone(context: Context, path: String): Boolean = SuSFSPathManager.updateKstatFullClone(context, path)

    fun createBackup(context: Context, backupFilePath: String): Boolean = runBlocking { SuSFSBackupManager.createBackup(context, backupFilePath) }
    suspend fun restoreFromBackup(context: Context, backupFilePath: String): Boolean = SuSFSBackupManager.restoreFromBackup(context, backupFilePath)
    suspend fun validateBackupFile(backupFilePath: String): BackupData? = SuSFSBackupManager.validateBackupFile(backupFilePath)
    fun getDefaultBackupFileName(): String = SuSFSBackupManager.getDefaultBackupFileName()

    suspend fun hasConfigurationForAutoStart(context: Context): Boolean {
        val config = getCurrentModuleConfig()
        return config.hasAutoStartConfig() || SuSFSCommands.getEnabledFeatures(context).any { it.isEnabled }
    }

    suspend fun configureAutoStart(context: Context, enabled: Boolean): Boolean = withContext(Dispatchers.IO) {
        try {
            if (enabled) {
                if (!hasConfigurationForAutoStart(context)) {
                    Log.e("SuSFSManager", "No configuration available for auto start")
                    return@withContext false
                }
                val success = SuSFSCommands.updateMagiskModule()
                if (success) {
                    setAutoStartEnabled(true)
                } else {
                    Log.e("SuSFSManager", "Failed to create Magisk module for auto start")
                }
                success
            } else {
                val success = SuSFSCommands.removeMagiskModule()
                if (success) {
                    setAutoStartEnabled(false)
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
        val success = setUname(context, SuSFSConfig.DEFAULT_UNAME, SuSFSConfig.DEFAULT_BUILD_TIME)
        if (success) {
            saveEnableHideBl(false)
            saveEnableCleanupResidue(false)
            saveEnableAvcLogSpoofing(false)
            saveHideSusMountsForAllProcs(false)
            saveEnableLogState(false)
            saveExecuteInPostFsData(false)
            if (isAutoStartEnabled()) {
                configureAutoStart(context, false)
            }
        }
        return success
    }
}
