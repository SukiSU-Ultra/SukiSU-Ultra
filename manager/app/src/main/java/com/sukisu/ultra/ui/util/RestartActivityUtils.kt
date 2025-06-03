package com.sukisu.ultra.ui.util

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import com.sukisu.ultra.ui.MainActivity

/**
 * 重启应用程序
 **/

fun Context.restartApp(
    activityClass: Class<out Activity>,
    finishCurrent: Boolean = true,
    clearTask: Boolean = true,
    newTask: Boolean = true
) {
    val intent = Intent(this, activityClass)
    if (clearTask) intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK)
    if (newTask) intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    startActivity(intent)

    if (finishCurrent && this is Activity) {
        finish()
    }
}

/**
 * 刷新启动器图标
 */
fun toggleLauncherIcon(context: Context, useAlt: Boolean) {
    val pm = context.packageManager
    val main = ComponentName(context, MainActivity::class.java.name)
    val alt = ComponentName(context, "${MainActivity::class.java.name}Alias")
    if (useAlt) {
        pm.setComponentEnabledSetting(main, PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP)
        pm.setComponentEnabledSetting(alt, PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP)
    } else {
        pm.setComponentEnabledSetting(alt, PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP)
        pm.setComponentEnabledSetting(main, PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP)
    }
}