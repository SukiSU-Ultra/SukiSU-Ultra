package com.sukisu.ultra.ui.screen.kpm

import android.content.Context
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSConfig
import com.sukisu.ultra.ui.util.getRootShell
import com.sukisu.ultra.ui.util.listKpmModules
import com.sukisu.ultra.ui.util.loadKpmModule
import com.sukisu.ultra.ui.util.unloadKpmModule
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Shared KPM install/uninstall used by the KPM screen and the AI assistant. */
object KpmOperations {

    fun isLoaded(moduleId: String): Boolean? = try {
        listKpmModules().lineSequence().any { it.trim() == moduleId }
    } catch (_: Exception) {
        null
    }

    suspend fun install(
        context: Context,
        tempFile: File,
        moduleId: String,
        embed: Boolean,
    ): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            require(isSafeKpmModuleId(moduleId)) { "Unsafe KPM module name" }
            require(tempFile.isFile) { "KPM file not found" }
            require(isValidKpmFile(tempFile)) { "Not a valid KPM/ELF file" }
            if (embed) {
                val targetPath = "/data/adb/kpm/$moduleId.kpm"
                val copy = getRootShell().newJob().add(
                    "mkdir -p /data/adb/kpm && cp ${SuSFSConfig.shellQuote(tempFile.absolutePath)} " +
                        "${SuSFSConfig.shellQuote(targetPath)}"
                ).to(ArrayList(), ArrayList()).exec()
                check(copy.isSuccess) {
                    copy.err.joinToString("\n").ifBlank {
                        context.getString(R.string.config_exit_code, copy.code)
                    }
                }
            }
            check(loadKpmModule(tempFile.absolutePath)) {
                context.getString(R.string.config_command_rejected)
            }
            check(isLoaded(moduleId) != false) {
                context.getString(R.string.config_command_rejected)
            }
        }
    }

    suspend fun uninstall(context: Context, moduleId: String): Result<Unit> =
        withContext(Dispatchers.IO) {
            runCatching {
                require(isSafeKpmModuleId(moduleId)) { "Unsafe KPM module name" }
                check(unloadKpmModule(moduleId)) {
                    context.getString(R.string.config_command_rejected)
                }
                check(isLoaded(moduleId) == false) {
                    context.getString(R.string.config_command_rejected)
                }
                val removal = getRootShell().newJob().add(
                    "rm -f -- ${SuSFSConfig.shellQuote("/data/adb/kpm/$moduleId.kpm")}"
                ).to(ArrayList(), ArrayList()).exec()
                check(removal.isSuccess) {
                    removal.err.joinToString("\n").ifBlank {
                        context.getString(R.string.config_exit_code, removal.code)
                    }
                }
            }
        }
}
