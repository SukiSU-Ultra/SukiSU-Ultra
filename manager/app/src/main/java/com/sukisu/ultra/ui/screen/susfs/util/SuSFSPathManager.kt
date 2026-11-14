package com.sukisu.ultra.ui.screen.susfs.util

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.util.Log
import android.widget.Toast
import androidx.annotation.RequiresApi
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.getRootShell
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import com.topjohnwu.superuser.io.SuFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

object SuSFSPathManager {
    private suspend fun showToast(context: Context, message: String) = withContext(Dispatchers.Main) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    @SuppressLint("QueryPermissionsNeeded")
    suspend fun getInstalledApps(): List<AppInfo> = withContext(Dispatchers.IO) {
        try {
            val allApps = mutableMapOf<String, AppInfo>()

            val cachedApps = SuperUserViewModel.getAppsSafely()
            val sourceApps = cachedApps.ifEmpty {
                com.sukisu.ultra.data.repository.SuperUserRepositoryImpl().getAppList().getOrThrow().first
            }
            sourceApps.forEach { superUserApp ->
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

            val directories = mutableListOf<String>()
            val result = getRootShell().newJob()
                .add("find ${SuSFSConfig.MEDIA_DATA_PATH} -mindepth 1 -maxdepth 1 -type d")
                .to(directories, null).exec()
            check(result.isSuccess) { "Unable to read app data directories" }
            val packagesWithData = directories.map { it.trimEnd('/').substringAfterLast('/') }.toSet()
            allApps.values.filter { it.packageName in packagesWithData }.sortedBy { it.appName.lowercase() }
        } catch (e: Exception) {
            throw e
        }
    }

    @RequiresApi(Build.VERSION_CODES.Q)
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

    @RequiresApi(Build.VERSION_CODES.Q)
    @SuppressLint("StringFormatMatches")
    suspend fun getAppPaths(context: Context, packageName: String): List<String> {
        val uid = getAppUid(context, packageName) ?: return emptyList()
        return listOf(
            "${SuSFSConfig.DEFAULT_ANDROID_DATA_PATH}/$packageName",
            "${SuSFSConfig.MEDIA_DATA_PATH}/$packageName",
            buildUidPath(uid)
        )
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    suspend fun addAppPaths(context: Context, packageName: String): Boolean {
        val paths = getAppPaths(context, packageName)
        val results = paths.map { addSusPathInternal(context, it, showToast = false) }
        return results.isNotEmpty() && results.all { it }
    }

    suspend fun addSusPathWithResult(path: String): SuSFSCommands.CommandResult {
        val result = SuSFSCommands.executeSusfsCommandWithOutput("add-sus-path ${SuSFSConfig.shellQuote(path)}")
        val success = result.isSuccess && !result.output.contains("not found, skip adding")
        if (success) {
            SuSFSRepository.saveSusPaths(SuSFSRepository.getSusPaths() + path)
            if (SuSFSRepository.isAutoStartEnabled()) {
                check(SuSFSCommands.updateMagiskModule()) { "Failed to update SUSFS boot module" }
            }
        }
        return result.copy(isSuccess = success)
    }

    private suspend fun addSusPathInternal(context: Context, path: String, showToast: Boolean = true): Boolean {
        val result = addSusPathWithResult(path)
        if (!result.isSuccess && showToast) {
            showToast(context, result.errorOutput.ifBlank { result.output }.ifBlank {
                context.getString(R.string.susfs_command_failed)
            })
        }
        return result.isSuccess
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
        val args = listOf(
            ino, dev, nlink, size, atime, atimeNsec, mtime, mtimeNsec,
            ctime, ctimeNsec, blocks, blksize
        ).joinToString(" ", transform = SuSFSConfig::shellQuote)
        val command = "add-sus-kstat-statically ${SuSFSConfig.shellQuote(path)} $args"
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
