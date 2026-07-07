package com.sukisu.ultra.ui.screen.susfs.util

import android.util.Log
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object SuSFSModuleManager {
    private const val TAG = "SuSFSModuleManager"

    data class CommandResult(
        val isSuccess: Boolean,
        val output: String,
        val errorOutput: String = ""
    )

    private fun runCmdWithResult(cmd: String): CommandResult {
        val result = Shell.getShell().newJob().add(cmd).exec()
        return CommandResult(
            isSuccess = result.isSuccess,
            output = result.out.joinToString("\n"),
            errorOutput = result.err.joinToString("\n")
        )
    }

    suspend fun createMagiskModule(): Boolean = withContext(Dispatchers.IO) {
        try {
            val result = runCmdWithResult("/data/adb/ksud susfs module install")
            if (!result.isSuccess) {
                Log.e(TAG, "Module install failed: ${result.errorOutput}")
            }
            result.isSuccess
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create module", e)
            false
        }
    }

    suspend fun removeMagiskModule(): Boolean = withContext(Dispatchers.IO) {
        try {
            val result = runCmdWithResult("/data/adb/ksud susfs module remove")
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
}
