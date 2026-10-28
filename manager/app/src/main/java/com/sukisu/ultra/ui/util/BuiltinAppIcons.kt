package com.sukisu.ultra.ui.util

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.MainActivity

data class BuiltinAppIcon(
    val id: String,
    @param:StringRes val nameRes: Int,
    @param:DrawableRes val iconRes: Int,
    /** Component enabled instead of [MainActivity] while this icon is selected. Null for the default icon. */
    val aliasClassName: String?,
)

/** Launcher icons that are compiled into the APK and can be applied through activity aliases. */
object BuiltinAppIcons {
    const val DEFAULT_ID = "default"
    const val KERNELSU_ID = "kernelsu"
    const val LOGO_ID = "sukisu_logo"
    const val ZAKO_ID = "zako"

    private const val TAG = "BuiltinAppIcons"
    private val mainActivityName = MainActivity::class.java.name

    val all: List<BuiltinAppIcon> = listOf(
        BuiltinAppIcon(
            id = DEFAULT_ID,
            nameRes = R.string.app_icon_builtin_default,
            iconRes = R.mipmap.ic_launcher,
            aliasClassName = null,
        ),
        BuiltinAppIcon(
            id = KERNELSU_ID,
            nameRes = R.string.app_icon_builtin_kernelsu,
            iconRes = R.mipmap.ic_launcher_alt,
            aliasClassName = mainActivityName + "Alias",
        ),
        BuiltinAppIcon(
            id = LOGO_ID,
            nameRes = R.string.app_icon_builtin_logo,
            iconRes = R.mipmap.ic_launcher_logo,
            aliasClassName = mainActivityName + "AliasLogo",
        ),
        BuiltinAppIcon(
            id = ZAKO_ID,
            nameRes = R.string.app_icon_builtin_zako,
            iconRes = R.mipmap.ic_launcher_zako,
            aliasClassName = mainActivityName + "AliasZako",
        ),
    )

    fun find(id: String?): BuiltinAppIcon = all.firstOrNull { it.id == id } ?: all.first()

    /**
     * Switches the launcher entry to [icon]. The target component is enabled before the previous
     * one is disabled so the launcher never observes a package without a launcher activity.
     */
    fun apply(context: Context, icon: BuiltinAppIcon) {
        val pm = context.packageManager
        val main = ComponentName(context, mainActivityName)
        val target = icon.aliasClassName?.let { ComponentName(context, it) }

        setEnabled(pm, target ?: main, true)
        all.mapNotNull { it.aliasClassName }
            .filter { it != icon.aliasClassName }
            .forEach { setEnabled(pm, ComponentName(context, it), false) }
        if (target != null) {
            setEnabled(pm, main, false)
        } else {
            // Re-enable the default entry even if a broken alias state disabled it earlier.
            setEnabled(pm, main, true)
        }
    }

    private fun setEnabled(pm: PackageManager, component: ComponentName, enabled: Boolean) {
        try {
            pm.setComponentEnabledSetting(
                component,
                if (enabled) {
                    PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                } else {
                    PackageManager.COMPONENT_ENABLED_STATE_DISABLED
                },
                PackageManager.DONT_KILL_APP,
            )
        } catch (t: Throwable) {
            Log.w(TAG, "Cannot change the enabled state of $component", t)
        }
    }
}
