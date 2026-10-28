package com.sukisu.ultra.ui

import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity

/**
 * Entry point for launcher shortcuts that use a custom icon.
 *
 * MainActivity is disabled while a built-in activity alias provides the launcher icon, so a
 * shortcut must not target it directly. This activity stays enabled and forwards to whichever
 * launcher entry is currently active.
 */
class AppIconShortcutActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val launcherIntent = Intent(Intent.ACTION_MAIN)
            .addCategory(Intent.CATEGORY_LAUNCHER)
            .setPackage(packageName)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val component = packageManager
            .queryIntentActivities(launcherIntent, 0)
            .firstOrNull()
            ?.activityInfo
            ?.let { ComponentName(packageName, it.name) }
        try {
            if (component != null) {
                startActivity(Intent(launcherIntent).setComponent(component))
            } else {
                startActivity(Intent(this, MainActivity::class.java))
            }
        } catch (_: Throwable) {
            // The active launcher entry can be changed between resolution and launch.
            runCatching { startActivity(Intent(this, MainActivity::class.java)) }
        } finally {
            finish()
        }
    }
}
