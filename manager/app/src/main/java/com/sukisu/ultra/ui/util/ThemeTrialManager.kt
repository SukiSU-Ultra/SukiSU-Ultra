package com.sukisu.ultra.ui.util

import android.content.Context
import androidx.core.content.edit
import java.io.File
import java.util.UUID

/**
 * Tracks the single active theme trial. The pre-trial package is kept in app-private storage
 * until the process or task that started the trial is gone, then the previous appearance is
 * restored and the trial cache is removed.
 */
object ThemeTrialManager {
    private const val PREFS = "theme_trial"
    private const val KEY_ACTIVE = "active"
    private const val KEY_BACKUP = "backup"
    private const val KEY_PROCESS = "process"
    private const val KEY_TASK = "task"
    private const val NO_TASK = Int.MIN_VALUE

    private val processToken = UUID.randomUUID().toString()

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun isActive(context: Context): Boolean = prefs(context).getBoolean(KEY_ACTIVE, false)

    fun trialDir(context: Context): File = File(context.filesDir, "theme_trial")

    fun backupFile(context: Context): File = File(trialDir(context), "backup.sukisu")

    fun markActive(context: Context, backup: File, taskId: Int?) {
        prefs(context).edit {
            putBoolean(KEY_ACTIVE, true)
            putString(KEY_BACKUP, backup.absolutePath)
            putString(KEY_PROCESS, processToken)
            putInt(KEY_TASK, taskId ?: NO_TASK)
        }
    }

    /** True when the trial belongs to an earlier process or a different activity task. */
    fun shouldRestore(context: Context, taskId: Int? = null): Boolean {
        val prefs = prefs(context)
        if (!prefs.getBoolean(KEY_ACTIVE, false)) return false
        if (prefs.getString(KEY_PROCESS, null) != processToken) return true
        val storedTask = prefs.getInt(KEY_TASK, NO_TASK)
        return taskId != null && storedTask != NO_TASK && storedTask != taskId
    }

    /** Returns the backup to restore, clearing stale markers whose file disappeared. */
    fun activeBackup(context: Context): File? {
        val prefs = prefs(context)
        if (!prefs.getBoolean(KEY_ACTIVE, false)) return null
        val file = prefs.getString(KEY_BACKUP, null)?.let(::File)
        if (file == null || !file.isFile) {
            clear(context)
            return null
        }
        return file
    }

    fun clear(context: Context) {
        prefs(context).edit { clear() }
        trialDir(context).deleteRecursively()
    }

    /** Removes a leftover backup directory when no trial marker is active. */
    fun cleanupOrphan(context: Context) {
        if (!isActive(context)) {
            trialDir(context).deleteRecursively()
        }
    }
}
