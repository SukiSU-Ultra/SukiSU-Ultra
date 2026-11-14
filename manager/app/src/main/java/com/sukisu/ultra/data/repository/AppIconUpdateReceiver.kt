package com.sukisu.ultra.data.repository

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.UserManager
import android.util.Log
import com.sukisu.ultra.KernelSUApplication
import com.sukisu.ultra.ui.util.BuiltinAppIcons

/**
 * Restores the selected launcher icon after the package is replaced.
 *
 * Component enabled states fall back to the manifest defaults when the app is updated, so
 * without this the launcher shows the default icon until the manager is opened. Running the
 * switch from the update broadcast also means the correct alias is already active before the
 * user taps the icon, so the first launch no longer has to change components underneath itself.
 *
 * The broadcast is not guaranteed (a locked user skips it, some ROMs defer it), so
 * [com.sukisu.ultra.KernelSUApplication] repeats the check once the manager is backgrounded.
 * Neither path touches components while the launching task is starting: disabling the alias
 * that hosts it kills the app on several ROMs.
 */
class AppIconUpdateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        if (context.getSystemService(UserManager::class.java)?.isUserUnlocked != true) return
        // A deferred update broadcast can arrive while the user is already launching the
        // manager. Moving components under a visible task kills it on some ROMs, so let the
        // background repair in KernelSUApplication do it once the app leaves the screen.
        if ((context.applicationContext as? KernelSUApplication)?.isAppInForeground == true) return
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
