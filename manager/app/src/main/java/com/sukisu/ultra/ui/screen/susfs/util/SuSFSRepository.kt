package com.sukisu.ultra.ui.screen.susfs.util

import android.annotation.SuppressLint
import android.content.Context
import android.net.Uri
import android.util.Log
import android.widget.Toast
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.getSuSFSStatus
import com.sukisu.ultra.ui.util.spoofKernelUname
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext

object SuSFSRepository {
    fun getCurrentModuleConfig(): ModuleConfig = runBlocking(Dispatchers.IO) {
        ModuleConfig(
            unameValue = getUnameValue(),
            buildTimeValue = getBuildTimeValue(),
            executeInPostFsData = getExecuteInPostFsData(),
            susPaths = getSusPaths(),
            susLoopPaths = getSusLoopPaths(),
            susMaps = getSusMaps(),
            enableLog = getEnableLogState(),
            kstatConfigs = getKstatConfigs(),
            addKstatPaths = getAddKstatPaths(),
            hideSusMountsForAllProcs = getHideSusMountsForAllProcs(),
            enableHideBl = getEnableHideBl(),
            enableCleanupResidue = getEnableCleanupResidue(),
            enableAvcLogSpoofing = getEnableAvcLogSpoofing(),
            cmdlineOrBootconfigPath = getCmdlineOrBootconfigPath()
        )
    }

    private suspend fun getUnameValue(): String {
        val v = SuSFSConfig.get(SuSFSConfig.KEY_UNAME_VALUE)
        return v.ifBlank { SuSFSConfig.DEFAULT_UNAME }
    }

    private suspend fun getBuildTimeValue(): String {
        val v = SuSFSConfig.get(SuSFSConfig.KEY_BUILD_TIME_VALUE)
        return v.ifBlank { SuSFSConfig.DEFAULT_BUILD_TIME }
    }

    fun getKernelSpoofRelease(): String =
        runBlocking(Dispatchers.IO) { getUnameValue() }.takeUnless { SuSFSConfig.isDefaultSpoofValue(it) }.orEmpty()

    fun getKernelSpoofVersion(): String =
        runBlocking(Dispatchers.IO) { getBuildTimeValue() }.takeUnless { SuSFSConfig.isDefaultSpoofValue(it) }.orEmpty()

    suspend fun setAutoStartEnabled(enabled: Boolean) =
        SuSFSConfig.set(SuSFSConfig.KEY_AUTO_START_ENABLED, if (enabled) "true" else "false")

    suspend fun isAutoStartEnabled(): Boolean =
        SuSFSConfig.get(SuSFSConfig.KEY_AUTO_START_ENABLED) == "true"

    suspend fun getEnableLogState(): Boolean =
        SuSFSConfig.get(SuSFSConfig.KEY_ENABLE_LOG) == "true"

    suspend fun getExecuteInPostFsData(): Boolean =
        SuSFSConfig.get(SuSFSConfig.KEY_EXECUTE_IN_POST_FS_DATA) == "true"

    suspend fun getHideSusMountsForAllProcs(): Boolean =
        SuSFSConfig.get(SuSFSConfig.KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS) == "true"

    suspend fun getEnableHideBl(): Boolean =
        SuSFSConfig.get(SuSFSConfig.KEY_ENABLE_HIDE_BL)  == "true"

    suspend fun getEnableCleanupResidue(): Boolean =
        SuSFSConfig.get(SuSFSConfig.KEY_ENABLE_CLEANUP_RESIDUE) == "true"

    suspend fun getEnableAvcLogSpoofing(): Boolean =
        SuSFSConfig.get(SuSFSConfig.KEY_ENABLE_AVC_LOG_SPOOFING) == "true"

    suspend fun getCmdlineOrBootconfigPath(): String =
        SuSFSConfig.get(SuSFSConfig.KEY_CMDLINE_OR_BOOTCONFIG_PATH)

    suspend fun getSusPaths(): Set<String> =
        SuSFSConfig.getMulti(SuSFSConfig.KEY_SUS_PATHS)

    suspend fun getSusLoopPaths(): Set<String> =
        SuSFSConfig.getMulti(SuSFSConfig.KEY_SUS_LOOP_PATHS)

    suspend fun getSusMaps(): Set<String> =
        SuSFSConfig.getMulti(SuSFSConfig.KEY_SUS_MAPS)

    suspend fun getKstatConfigs(): Set<String> =
        SuSFSConfig.getMulti(SuSFSConfig.KEY_KSTAT_CONFIGS, ";;")

    suspend fun getAddKstatPaths(): Set<String> =
        SuSFSConfig.getMulti(SuSFSConfig.KEY_ADD_KSTAT_PATHS)

    suspend fun saveUnameValue(value: String) {
        SuSFSConfig.set(SuSFSConfig.KEY_UNAME_VALUE, value)
    }

    suspend fun saveBuildTimeValue(value: String) {
        SuSFSConfig.set(SuSFSConfig.KEY_BUILD_TIME_VALUE, value)
    }

    suspend fun saveEnableLogState(enabled: Boolean) {
        SuSFSConfig.set(SuSFSConfig.KEY_ENABLE_LOG, if (enabled) "true" else "false")
    }

    suspend fun saveExecuteInPostFsData(enabled: Boolean) {
        SuSFSConfig.set(SuSFSConfig.KEY_EXECUTE_IN_POST_FS_DATA, if (enabled) "true" else "false")
    }

    suspend fun saveHideSusMountsForAllProcs(hideForAll: Boolean) {
        SuSFSConfig.set(SuSFSConfig.KEY_HIDE_SUS_MOUNTS_FOR_ALL_PROCS, if (hideForAll) "true" else "false")
    }

    suspend fun saveEnableHideBl(enabled: Boolean) {
        SuSFSConfig.set(SuSFSConfig.KEY_ENABLE_HIDE_BL, if (enabled) "true" else "false")
    }

    suspend fun saveEnableCleanupResidue(enabled: Boolean) {
        SuSFSConfig.set(SuSFSConfig.KEY_ENABLE_CLEANUP_RESIDUE, if (enabled) "true" else "false")
    }

    suspend fun saveEnableAvcLogSpoofing(enabled: Boolean) {
        SuSFSConfig.set(SuSFSConfig.KEY_ENABLE_AVC_LOG_SPOOFING, if (enabled) "true" else "false")
    }

    suspend fun saveSusPaths(paths: Set<String>) {
        SuSFSConfig.setMulti(SuSFSConfig.KEY_SUS_PATHS, paths, ";")
    }

    suspend fun saveSusLoopPaths(paths: Set<String>) {
        SuSFSConfig.setMulti(SuSFSConfig.KEY_SUS_LOOP_PATHS, paths, ";")
    }

    suspend fun saveSusMaps(maps: Set<String>) {
        SuSFSConfig.setMulti(SuSFSConfig.KEY_SUS_MAPS, maps, ";")
    }

    suspend fun saveKstatConfigs(configs: Set<String>) {
        SuSFSConfig.setMulti(SuSFSConfig.KEY_KSTAT_CONFIGS, configs, ";;")
    }

    suspend fun saveAddKstatPaths(paths: Set<String>) {
        SuSFSConfig.setMulti(SuSFSConfig.KEY_ADD_KSTAT_PATHS, paths, ";")
    }

    suspend fun setEnableLog(context: Context, enabled: Boolean): Boolean {
        val success = SuSFSCommands.executeSusfsCommand(context, "enable-log ${if (enabled) 1 else 0}")
        if (success) {
            saveEnableLogState(enabled)
            if (isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
        }
        return success
    }

    suspend fun setEnableAvcLogSpoofing(context: Context, enabled: Boolean): Boolean {
        val success = SuSFSCommands.executeSusfsCommand(context, "enable-avc-log-spoofing ${if (enabled) 1 else 0}")
        if (success) {
            saveEnableAvcLogSpoofing(enabled)
            if (isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
        }
        return success
    }

    suspend fun setHideSusMountsForAllProcs(context: Context, hideForAll: Boolean): Boolean {
        val success = SuSFSCommands.executeSusfsCommand(context, "hide-sus-mnts-for-non-su-procs ${if (hideForAll) 1 else 0}")
        if (success) {
            saveHideSusMountsForAllProcs(hideForAll)
            if (isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
        }
        return success
    }

    @SuppressLint("StringFormatMatches")
    suspend fun setUname(context: Context, unameValue: String, buildTimeValue: String): Boolean {
        val useSusfs = try {
            getSuSFSStatus().equals("true", ignoreCase = true)
        } catch (_: Exception) {
            false
        }
        val success = if (useSusfs) {
            val susfsResult = SuSFSCommands.executeSusfsCommandWithOutput(
                "set-uname ${SuSFSConfig.shellQuote(unameValue)} ${SuSFSConfig.shellQuote(buildTimeValue)}"
            )
            susfsResult.isSuccess || spoofKernelUname(unameValue, buildTimeValue)
        } else {
            spoofKernelUname(unameValue, buildTimeValue)
        }
        if (!success) {
            withContext(Dispatchers.Main) {
                Toast.makeText(context, context.getString(R.string.susfs_command_failed), Toast.LENGTH_SHORT).show()
            }
        }
        if (success) {
            saveUnameValue(unameValue)
            saveBuildTimeValue(buildTimeValue)
            if (isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
        }
        return success
    }

    @SuppressLint("SdCardPath")
    suspend fun setCmdlineOrBootconfigFile(context: Context, sourceUri: String): Boolean {
        val shell = Shell.getShell()
        val targetPath = SuSFSConfig.CMDLINE_OR_BOOTCONFIG_FILE
        val targetDir = targetPath.substringBeforeLast('/')

        // Pull the file bytes out via ContentResolver. We can't bypass this
        // by directly using the URI in `sh` because content:// URIs aren't
        // visible to the kernel-side SuFile reader.
        val bytes: ByteArray = try {
            context.contentResolver.openInputStream(Uri.parse(sourceUri)).use { input ->
                input?.readBytes() ?: return false
            }
        } catch (e: Exception) {
            Log.e("SuSFSRepository", "Failed to read cmdline source uri", e)
            return false
        }

        // Make sure /data/adb/ksu exists and the perms are sane.
        shell.newJob()
            .add("mkdir -p '$targetDir' && chmod 755 '$targetDir'")
            .exec()

        // Single-quote the payload + pipe through base64 → avoid any
        // shell-quoting edge cases (cmdline files can contain spaces,
        // quotes, NUL bytes, etc.).
        val b64 = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
        val writeOk = shell.newJob()
            .add("echo '$b64' | base64 -d > '$targetPath' && chmod 644 '$targetPath'")
            .exec()
            .isSuccess
        if (!writeOk) {
            Log.e("SuSFSRepository", "Failed to write cmdline file to '$targetPath'")
            return false
        }

        // Hand the file off to the kernel.
        val result = SuSFSCommands.executeSusfsCommandDirect(
            "set-cmdline-or-bootconfig '${SuSFSConfig.shellQuote(targetPath)}'"
        )
        if (!result.isSuccess) {
            withContext(Dispatchers.Main) {
                Toast.makeText(
                    context,
                    context.getString(R.string.susfs_command_failed),
                    Toast.LENGTH_SHORT
                ).show()
            }
            return false
        }

        // Persist the chosen path so AutoStart can re-apply it at boot.
        SuSFSConfig.set(SuSFSConfig.KEY_CMDLINE_OR_BOOTCONFIG_PATH, targetPath)
        if (isAutoStartEnabled()) SuSFSCommands.updateMagiskModule()
        return true
    }
}
