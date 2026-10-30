package com.sukisu.ultra.ui.util

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.runtime.Immutable
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.MainActivity

@Immutable
data class BuiltinAppIcon(
    val id: String,
    @param:StringRes val nameRes: Int,
    @param:DrawableRes val iconRes: Int,
    @param:DrawableRes val foregroundRes: Int,
    /** Launcher component associated with this icon. */
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
            foregroundRes = R.drawable.ic_launcher_foreground,
            aliasClassName = mainActivityName + "AliasDefault",
        ),
        BuiltinAppIcon(
            id = KERNELSU_ID,
            nameRes = R.string.app_icon_builtin_kernelsu,
            iconRes = R.mipmap.ic_launcher_alt,
            foregroundRes = R.drawable.ic_launcher_foreground_alt,
            aliasClassName = mainActivityName + "Alias",
        ),
        BuiltinAppIcon(
            id = LOGO_ID,
            nameRes = R.string.app_icon_builtin_logo,
            iconRes = R.mipmap.ic_launcher_logo,
            foregroundRes = R.drawable.ic_launcher_foreground_logo,
            aliasClassName = mainActivityName + "AliasLogo",
        ),
        BuiltinAppIcon(
            id = ZAKO_ID,
            nameRes = R.string.app_icon_builtin_zako,
            iconRes = R.mipmap.ic_launcher_zako,
            foregroundRes = R.drawable.ic_launcher_foreground_zako,
            aliasClassName = mainActivityName + "AliasZako",
        ),
    )

    fun find(id: String?): BuiltinAppIcon = all.firstOrNull { it.id == id } ?: all.first()

    /** Switches the launcher entry while keeping the main activity available for deep links. */
    fun apply(
        context: Context,
        icon: BuiltinAppIcon,
        dynamicColor: Boolean = false,
    ) {
        val pm = context.packageManager
        val main = ComponentName(context, mainActivityName)
        val selectedClass = componentClassName(icon, dynamicColor)
        val target = ComponentName(context, selectedClass)

        setEnabled(pm, main, true)
        setEnabled(pm, target, true)
        allAliasClassNames()
            .filter { it != selectedClass }
            .forEach { setEnabled(pm, ComponentName(context, it), false) }
    }

    private fun componentClassName(
        icon: BuiltinAppIcon,
        dynamicColor: Boolean,
    ): String {
        if (dynamicColor) {
            return icon.aliasClassName ?: (mainActivityName + "AliasDefault")
        }
        return mainActivityName + "Alias" + aliasSuffix(icon) + "Static"
    }

    private fun allAliasClassNames(): List<String> = buildList {
        all.forEach { icon ->
            val base = mainActivityName + "Alias" + aliasSuffix(icon)
            add(icon.aliasClassName ?: (mainActivityName + "AliasDefault"))
            add(base + "Static")
        }
    }

    private fun aliasSuffix(icon: BuiltinAppIcon): String = when (icon.id) {
        DEFAULT_ID -> "Default"
        KERNELSU_ID -> ""
        LOGO_ID -> "Logo"
        ZAKO_ID -> "Zako"
        else -> "Default"
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
