package com.sukisu.ultra.ui.util

import android.content.Context
import androidx.core.content.edit
import java.io.File

/**
 * Bookkeeping for the adaptive (light + dark) theme currently applied on the device.
 *
 * When a v3 package with `adaptive=true` is applied, its source package is kept in app-private
 * storage and the marker is set, so the variant matching the system night mode can be re-applied
 * whenever the system flips between light and dark. Applying any non-adaptive theme clears it.
 */
object AdaptiveThemeStore {
    private const val PREFS_NAME = "adaptive_theme"
    private const val KEY_ACTIVE = "active"
    private const val KEY_VARIANT_DARK = "variant_dark"
    private const val DIR = "adaptive_theme"
    private const val CURRENT_NAME = "current.sukisu"
    private const val PENDING_NAME = "pending.sukisu"

    /** The applied adaptive package kept for variant re-apply, export and store upload. */
    fun currentFile(context: Context): File = File(File(context.filesDir, DIR), CURRENT_NAME)

    /** Staged copy of an adaptive import that has not been confirmed yet. */
    fun pendingFile(context: Context): File = File(File(context.filesDir, DIR), PENDING_NAME)

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun isActive(context: Context): Boolean =
        prefs(context).getBoolean(KEY_ACTIVE, false) && currentFile(context).isFile

    fun activeFile(context: Context): File? = currentFile(context).takeIf { isActive(context) }

    /** Which variant (dark=true) the currently applied adaptive theme last rendered. */
    fun appliedVariantDark(context: Context): Boolean =
        prefs(context).getBoolean(KEY_VARIANT_DARK, false)

    /** Promotes a staged source package and records which variant became active. */
    fun save(context: Context, source: File, darkApplied: Boolean) {
        val target = currentFile(context)
        target.parentFile?.mkdirs()
        if (source.absolutePath != target.absolutePath) {
            source.copyTo(target, overwrite = true)
        }
        prefs(context).edit {
            putBoolean(KEY_ACTIVE, true)
            putBoolean(KEY_VARIANT_DARK, darkApplied)
        }
    }

    fun setAppliedVariantDark(context: Context, dark: Boolean) {
        prefs(context).edit { putBoolean(KEY_VARIANT_DARK, dark) }
    }

    fun clear(context: Context) {
        prefs(context).edit {
            remove(KEY_ACTIVE)
            remove(KEY_VARIANT_DARK)
        }
        runCatching { currentFile(context).delete() }
        discardPending(context)
    }

    /** Drops a staged package from a canceled import without touching the active theme. */
    fun discardPending(context: Context) {
        runCatching { pendingFile(context).delete() }
    }
}
