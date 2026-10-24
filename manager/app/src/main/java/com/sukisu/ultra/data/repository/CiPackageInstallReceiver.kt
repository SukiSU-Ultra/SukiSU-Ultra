package com.sukisu.ultra.data.repository

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import android.widget.Toast
import com.sukisu.ultra.R

/** Handles Android's asynchronous result for the CI APK installation session. */
class CiPackageInstallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_INSTALL_RESULT) return

        when (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_SUCCESS ->
                Toast.makeText(context, R.string.ci_update_install_success, Toast.LENGTH_LONG).show()

            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                @Suppress("DEPRECATION")
                val confirmation = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                } else {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT)
                }
                confirmation?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)?.let(context::startActivity)
            }

            else -> Toast.makeText(context, R.string.ci_update_install_failed, Toast.LENGTH_LONG).show()
        }
    }

    companion object {
        const val ACTION_INSTALL_RESULT = "com.sukisu.ultra.action.CI_INSTALL_RESULT"
    }
}
