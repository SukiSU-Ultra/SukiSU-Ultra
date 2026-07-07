package com.sukisu.ultra.ui.screen.susfs.util

import android.content.Context
import android.util.Log
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.getKsuDaemonPath
import com.sukisu.ultra.ui.util.getRootShell
import com.sukisu.ultra.ui.util.getSuSFSFeatures
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object SuSFSCommands {
    private const val TAG = "SuSFSCommands"

    data class CommandResult(
        val isSuccess: Boolean,
        val output: String,
        val errorOutput: String = ""
    )

    private fun runCmd(shell: Shell, cmd: String): String {
        return shell.newJob().add(cmd).to(mutableListOf<String>(), null).exec().out.joinToString("\n")
    }

    suspend fun executeSusfsCommandDirect(command: String): CommandResult = withContext(Dispatchers.IO) {
        try {
            val shell = getRootShell()
            val result = shell.newJob().add("${getKsuDaemonPath()} susfs $command").exec()
            CommandResult(
                isSuccess = result.isSuccess,
                output = result.out.joinToString("\n"),
                errorOutput = result.err.joinToString("\n")
            )
        } catch (e: Exception) {
            CommandResult(false, "", e.message ?: "Unknown error")
        }
    }

    suspend fun executeSusfsCommand(context: Context, command: String): Boolean {
        val result = executeSusfsCommandDirect(command)
        if (!result.isSuccess) {
            showToast(context, "${context.getString(R.string.susfs_command_failed)}\n${result.output}\n${result.errorOutput}")
        }
        return result.isSuccess
    }

    suspend fun executeSusfsCommandWithOutput(command: String): CommandResult = executeSusfsCommandDirect(command)

    suspend fun createMagiskModule(): Boolean = withContext(Dispatchers.IO) {
        try {
            val result = runCmdWithResult("${getKsuDaemonPath()} susfs module install")
            if (!result.isSuccess) {
                Log.e(TAG, "Module install failed: ${result.errorOutput}")
            }
            result.isSuccess
        } catch (e: Exception) {
            Log.e(TAG, "Failed to update module", e)
            false
        }
    }

    suspend fun removeMagiskModule(): Boolean = withContext(Dispatchers.IO) {
        try {
            val result = runCmdWithResult("${getKsuDaemonPath()} susfs module remove")
            if (!result.isSuccess) {
                Log.e(TAG, "Module remove failed: ${result.errorOutput}")
            }
            result.isSuccess
        } catch (e: Exception) {
            Log.e(TAG, "Failed to remove module", e)
            false
        }
    }

    suspend fun updateMagiskModule(): Boolean {
        return removeMagiskModule() && createMagiskModule()
    }

    private fun runCmdWithResult(cmd: String): CommandResult {
        val result = Shell.getShell().newJob().add(cmd).exec()
        return CommandResult(
            isSuccess = result.isSuccess,
            output = result.out.joinToString("\n"),
            errorOutput = result.err.joinToString("\n")
        )
    }

    suspend fun getCurrentSlotInfo(): List<SlotInfo> = withContext(Dispatchers.IO) {
        try {
            val shell = Shell.getShell()
            listOf("boot_a", "boot_b").mapNotNull { slot ->
                val uname = runCmd(shell,
                    $$"strings -n 20 /dev/block/by-name/$$slot | awk '/Linux version/ && ++c==2 {print $3; exit}'"
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

    private suspend fun showToast(context: Context, message: String) = withContext(Dispatchers.Main) {
        android.widget.Toast.makeText(context, message, android.widget.Toast.LENGTH_SHORT).show()
    }
}
