package com.sukisu.ultra.data.repository

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.UserManager
import android.util.Log
import com.sukisu.ultra.ui.util.BuiltinAppIcons

/**
 * Restores the selected launcher icon after the package is replaced.
 *
 * Component enabled states fall back to the manifest defaults when the app is updated, so
 * without this the launcher shows the default icon until the manager is opened. Running the
 * switch from the update broadcast also means the correct alias is already active before the
 * user taps the icon, so the first launch no longer has to change components underneath itself.
 */
class AppIconUpdateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        if (context.getSystemService(UserManager::class.java)?.isUserUnlocked != true) return
        runCatching {
            val settings = SettingsRepositoryImpl()
            BuiltinAppIcons.applyIfNeeded(
                context = context.applicationContext,
                icon = BuiltinAppIcons.find(settings.appIconId),
                dynamicColor = settings.appIconDynamicColor,
            )
        }.onFailure {
            Log.w(TAG, "Cannot restore the launcher icon after update", it)
        }
    }

    private companion object {
        const val TAG = "AppIconUpdateReceiver"
    }
}
