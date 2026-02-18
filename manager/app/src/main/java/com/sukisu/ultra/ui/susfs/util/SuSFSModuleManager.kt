package com.sukisu.ultra.ui.susfs.util

import android.content.Context
import android.util.Log
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object SuSFSModuleManager {
    private const val TAG = "SuSFSModuleManager"
    private const val MODULE_ID = "susfs_manager"
    private const val MODULE_PATH = "/data/adb/modules/$MODULE_ID"

    data class CommandResult(val isSuccess: Boolean, val output: String, val errorOutput: String = "")

    private fun runCmdWithResult(cmd: String): CommandResult {
        val result = Shell.getShell().newJob().add(cmd).exec()
        return CommandResult(
            isSuccess = result.isSuccess,
            output = result.out.joinToString("\n"),
            errorOutput = result.err.joinToString("\n")
        )
    }

    private fun getCurrentModuleConfig(context: Context): SuSFSManager.ModuleConfig {
        return SuSFSManager.getCurrentModuleConfig(context)
    }


    suspend fun createMagiskModule(context: Context): Boolean = withContext(Dispatchers.IO) {
        try {
            val config = getCurrentModuleConfig(context)

            // 创建模块目录
            if (!runCmdWithResult("mkdir -p $MODULE_PATH").isSuccess) {
                return@withContext false
            }

            // 创建 module.prop
            val moduleProp = ScriptGenerator.generateModuleProp(MODULE_ID)
            val modulePropCmd = "cat > $MODULE_PATH/module.prop << 'EOF'\n$moduleProp\nEOF"
            if (!runCmdWithResult(modulePropCmd).isSuccess) {
                return@withContext false
            }

            // 生成并创建所有脚本文件
            val scripts = ScriptGenerator.generateAllScripts(config)
            scripts.all { (filename, content) ->
                val writeCmd = "cat > $MODULE_PATH/$filename << 'EOF'\n$content\nEOF"
                runCmdWithResult(writeCmd).isSuccess &&
                        runCmdWithResult("chmod 755 $MODULE_PATH/$filename").isSuccess
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create module", e)
            false
        }
    }

    suspend fun removeMagiskModule(): Boolean = withContext(Dispatchers.IO) {
        try {
            runCmdWithResult("rm -rf $MODULE_PATH").isSuccess
        } catch (e: Exception) {
            Log.e(TAG, "Failed to remove module", e)
            false
        }
    }

    suspend fun updateMagiskModule(context: Context): Boolean {
        return removeMagiskModule() && createMagiskModule(context)
    }
}

