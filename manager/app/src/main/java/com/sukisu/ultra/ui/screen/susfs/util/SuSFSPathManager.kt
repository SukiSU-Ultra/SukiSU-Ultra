package com.sukisu.ultra.ui.screen.susfs.util

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.ApplicationInfo
import android.util.Log
import android.widget.Toast
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.getRootShell
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import com.topjohnwu.superuser.io.SuFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.withContext
import java.io.File

object SuSFSPathManager {
    private suspend fun showToast(context: Context, message: String) = withContext(Dispatchers.Main) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
    }

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
                    val dataPath = "${SuSFSConfig.MEDIA_DATA_PATH}/${appInfo.packageName}"
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
        val base = SuSFSConfig.CGROUP_BASE_PATH
        val possiblePaths = listOf(
            "$base/uid_$uid",
            "$base/apps/uid_$uid",
            "$base/system/uid_$uid",
            "$base/freezer/uid_$uid",
            "$base/memory/uid_$uid",
            "$base/cpuset/uid_$uid",
            "$base/cpu/uid_$uid"
        )
        for (path in possiblePaths) {
            if (checkPathExists(path)) return path
        }
        return possiblePaths[0]
    }

    @SuppressLint("StringFormatMatches")
    suspend fun addAppPaths(context: Context, packageName: String): Boolean {
        val path1 = "${SuSFSConfig.DEFAULT_ANDROID_DATA_PATH}/$packageName"
        val path2 = "${SuSFSConfig.MEDIA_DATA_PATH}/$packageName"
        val uid = getAppUid(context, packageName) ?: return false
        val path3 = buildUidPath(uid)

        var successCount = 0
        if (addSusPathInternal(context, path1, showToast = false)) successCount++
        if (addSusPathInternal(context, path2, showToast = false)) successCount++
        if (addSusPathInternal(context, path3, showToast = false)) successCount++
        return successCount > 0
    }

    @SuppressLint("StringFormatInvalid")
    private suspend fun addSusPathInternal(context: Context, path: String, showToast: Boolean = true): Boolean {
        val result = SuSFSCommands.executeSusfsCommandWithOutput("add-sus-path '$path'")
        val isActuallySuccessful = result.isSuccess && !result.output.contains("not found, skip adding")
        if (isActuallySuccessful) {
            SuSFSRepository.saveSusPaths(SuSFSRepository.getSusPaths() + path)
            if (SuSFSRepository.isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
        } else if (showToast) {
            showToast(context, result.errorOutput.ifEmpty { context.getString(R.string.susfs_command_failed) })
        }
        return isActuallySuccessful
    }

    suspend fun addSusPath(context: Context, path: String): Boolean = addSusPathInternal(context, path, showToast = true)

    suspend fun removeSusPath(path: String): Boolean {
        SuSFSRepository.saveSusPaths(SuSFSRepository.getSusPaths() - path)
        if (SuSFSRepository.isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
        return true
    }

    suspend fun editSusPath(context: Context, oldPath: String, newPath: String): Boolean {
        return try {
            val currentPaths = SuSFSRepository.getSusPaths().toMutableSet()
            if (!currentPaths.remove(oldPath)) {
                showToast(context, context.getString(R.string.susfs_command_failed))
                return false
            }
            SuSFSRepository.saveSusPaths(currentPaths)
            val success = addSusPathInternal(context, newPath, showToast = false)
            if (!success) {
                currentPaths.add(oldPath)
                SuSFSRepository.saveSusPaths(currentPaths)
                if (SuSFSRepository.isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
                showToast(context, context.getString(R.string.susfs_command_failed))
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSPathManager", "Exception editing SUS path", e)
            showToast(context, context.getString(R.string.susfs_command_failed))
            false
        }
    }

    @SuppressLint("SdCardPath")
    private fun isValidLoopPath(path: String): Boolean =
        !path.startsWith("/storage/") && !path.startsWith("/sdcard/")

    @SuppressLint("StringFormatInvalid")
    private suspend fun addSusLoopPathInternal(context: Context, path: String, showToast: Boolean = true): Boolean {
        if (!isValidLoopPath(path)) {
            if (showToast) showToast(context, context.getString(R.string.susfs_invalid_loop_path))
            return false
        }
        val result = SuSFSCommands.executeSusfsCommandWithOutput("add-sus-path-loop '$path'")
        val isActuallySuccessful = result.isSuccess && !result.output.contains("not found, skip adding")
        if (isActuallySuccessful) {
            SuSFSRepository.saveSusLoopPaths(SuSFSRepository.getSusLoopPaths() + path)
            if (SuSFSRepository.isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
        } else if (showToast) {
            showToast(context, result.errorOutput.ifEmpty { context.getString(R.string.susfs_add_loop_path_failed) })
        }
        return isActuallySuccessful
    }

    suspend fun addSusLoopPath(context: Context, path: String): Boolean = addSusLoopPathInternal(context, path, showToast = true)

    suspend fun removeSusLoopPath(path: String): Boolean {
        SuSFSRepository.saveSusLoopPaths(SuSFSRepository.getSusLoopPaths() - path)
        if (SuSFSRepository.isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
        return true
    }

    suspend fun editSusLoopPath(context: Context, oldPath: String, newPath: String): Boolean {
        if (!isValidLoopPath(newPath)) {
            showToast(context, context.getString(R.string.susfs_invalid_loop_path))
            return false
        }
        return try {
            val currentPaths = SuSFSRepository.getSusLoopPaths().toMutableSet()
            if (!currentPaths.remove(oldPath)) {
                showToast(context, context.getString(R.string.susfs_edit_loop_path_failed))
                return false
            }
            SuSFSRepository.saveSusLoopPaths(currentPaths)
            val success = addSusLoopPathInternal(context, newPath, showToast = false)
            if (!success) {
                currentPaths.add(oldPath)
                SuSFSRepository.saveSusLoopPaths(currentPaths)
                if (SuSFSRepository.isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
                showToast(context, context.getString(R.string.susfs_edit_loop_path_failed))
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSPathManager", "Exception editing SUS loop path", e)
            showToast(context, context.getString(R.string.susfs_edit_loop_path_failed))
            false
        }
    }

    private suspend fun addSusMapInternal(context: Context, map: String, showToast: Boolean = true): Boolean {
        val result = SuSFSCommands.executeSusfsCommandWithOutput("add-sus-map '$map'")
        val success = result.isSuccess
        if (success) {
            SuSFSRepository.saveSusMaps(SuSFSRepository.getSusMaps() + map)
            if (SuSFSRepository.isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
        } else if (showToast) {
            showToast(context, result.errorOutput.ifEmpty { context.getString(R.string.susfs_add_map_failed) })
        }
        return success
    }

    suspend fun addSusMap(context: Context, map: String): Boolean = addSusMapInternal(context, map, showToast = true)

    suspend fun removeSusMap(map: String): Boolean {
        SuSFSRepository.saveSusMaps(SuSFSRepository.getSusMaps() - map)
        if (SuSFSRepository.isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
        return true
    }

    suspend fun editSusMap(context: Context, oldMap: String, newMap: String): Boolean {
        return try {
            val currentMaps = SuSFSRepository.getSusMaps().toMutableSet()
            if (!currentMaps.remove(oldMap)) {
                showToast(context, context.getString(R.string.susfs_edit_map_failed))
                return false
            }
            SuSFSRepository.saveSusMaps(currentMaps)
            val success = addSusMapInternal(context, newMap, showToast = false)
            if (!success) {
                currentMaps.add(oldMap)
                SuSFSRepository.saveSusMaps(currentMaps)
                if (SuSFSRepository.isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
                showToast(context, context.getString(R.string.susfs_edit_map_failed))
            }
            success
        } catch (e: Exception) {
            Log.e("SuSFSPathManager", "Exception editing SUS map", e)
            showToast(context, context.getString(R.string.susfs_edit_map_failed))
            false
        }
    }

    private suspend fun addKstatStaticallyInternal(
        context: Context, path: String, ino: String, dev: String, nlink: String,
        size: String, atime: String, atimeNsec: String, mtime: String, mtimeNsec: String,
        ctime: String, ctimeNsec: String, blocks: String, blksize: String
    ): Boolean {
        val command = "add-sus-kstat-statically '$path' '$ino' '$dev' '$nlink' '$size' '$atime' '$atimeNsec' '$mtime' '$mtimeNsec' '$ctime' '$ctimeNsec' '$blocks' '$blksize'"
        val success = SuSFSCommands.executeSusfsCommand(context, command)
        if (success) {
            val entry = "$path|$ino|$dev|$nlink|$size|$atime|$atimeNsec|$mtime|$mtimeNsec|$ctime|$ctimeNsec|$blocks|$blksize"
            SuSFSRepository.saveKstatConfigs(SuSFSRepository.getKstatConfigs() + entry)
            if (SuSFSRepository.isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
        }
        return success
    }

    suspend fun addKstatStatically(context: Context, path: String, ino: String, dev: String, nlink: String,
                                   size: String, atime: String, atimeNsec: String, mtime: String, mtimeNsec: String,
                                   ctime: String, ctimeNsec: String, blocks: String, blksize: String): Boolean =
        addKstatStaticallyInternal(context, path, ino, dev, nlink, size, atime, atimeNsec, mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize)

    suspend fun removeKstatConfig(config: String): Boolean {
        SuSFSRepository.saveKstatConfigs(SuSFSRepository.getKstatConfigs() - config)
        if (SuSFSRepository.isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
        return true
    }

    @SuppressLint("StringFormatInvalid")
    suspend fun editKstatConfig(context: Context, oldConfig: String, path: String, ino: String, dev: String, nlink: String,
                                size: String, atime: String, atimeNsec: String, mtime: String, mtimeNsec: String,
                                ctime: String, ctimeNsec: String, blocks: String, blksize: String): Boolean {
        return try {
            val currentConfigs = SuSFSRepository.getKstatConfigs().toMutableSet()
            if (!currentConfigs.remove(oldConfig)) return false
            SuSFSRepository.saveKstatConfigs(currentConfigs)
            val success = addKstatStaticallyInternal(context, path, ino, dev, nlink, size, atime, atimeNsec, mtime, mtimeNsec, ctime, ctimeNsec, blocks, blksize)
            if (!success) {
                currentConfigs.add(oldConfig)
                SuSFSRepository.saveKstatConfigs(currentConfigs)
                if (SuSFSRepository.isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
            }
            success
        } catch (_: Exception) { false }
    }

    private suspend fun addKstatInternal(context: Context, path: String): Boolean {
        val success = SuSFSCommands.executeSusfsCommand(context, "add-sus-kstat '$path'")
        if (success) {
            SuSFSRepository.saveAddKstatPaths(SuSFSRepository.getAddKstatPaths() + path)
            if (SuSFSRepository.isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
        }
        return success
    }

    suspend fun addKstat(context: Context, path: String): Boolean = addKstatInternal(context, path)

    suspend fun removeAddKstat(path: String): Boolean {
        SuSFSRepository.saveAddKstatPaths(SuSFSRepository.getAddKstatPaths() - path)
        if (SuSFSRepository.isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
        return true
    }

    @SuppressLint("StringFormatInvalid")
    suspend fun editAddKstat(context: Context, oldPath: String, newPath: String): Boolean {
        return try {
            val currentPaths = SuSFSRepository.getAddKstatPaths().toMutableSet()
            if (!currentPaths.remove(oldPath)) return false
            SuSFSRepository.saveAddKstatPaths(currentPaths)
            val success = addKstatInternal(context, newPath)
            if (!success) {
                currentPaths.add(oldPath)
                SuSFSRepository.saveAddKstatPaths(currentPaths)
                if (SuSFSRepository.isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
            }
            success
        } catch (_: Exception) { false }
    }

    suspend fun updateKstat(context: Context, path: String): Boolean =
        SuSFSCommands.executeSusfsCommand(context, "update-sus-kstat '$path'")

    suspend fun updateKstatFullClone(context: Context, path: String): Boolean =
        SuSFSCommands.executeSusfsCommand(context, "update-sus-kstat-full-clone '$path'")
}
