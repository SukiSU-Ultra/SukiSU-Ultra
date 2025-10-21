package com.sukisu.ultra.ui.activity.util

import android.content.Context
import android.database.ContentObserver
import android.os.Handler
import android.provider.Settings
import androidx.core.content.edit
import com.sukisu.ultra.ui.MainActivity
import com.sukisu.ultra.ui.theme.CardConfig
import com.sukisu.ultra.ui.theme.ThemeConfig
import kotlinx.coroutines.flow.MutableStateFlow

class ThemeChangeContentObserver(
    handler: Handler,
    private val onThemeChanged: () -> Unit
) : ContentObserver(handler) {
    override fun onChange(selfChange: Boolean) {
        super.onChange(selfChange)
        onThemeChanged()
    }
}

object ThemeUtils {

    fun initializeThemeSettings(activity: MainActivity, settingsStateFlow: MutableStateFlow<MainActivity.SettingsState>) {
        val prefs = activity.getSharedPreferences("settings", Context.MODE_PRIVATE)
        val isFirstRun = prefs.getBoolean("is_first_run", true)

        settingsStateFlow.value = MainActivity.SettingsState(
            isHideOtherInfo = prefs.getBoolean("is_hide_other_info", false),
            showKpmInfo = prefs.getBoolean("show_kpm_info", false)
        )

        if (isFirstRun) {
            ThemeConfig.preventBackgroundRefresh = false
            activity.getSharedPreferences("theme_prefs", Context.MODE_PRIVATE).edit {
                putBoolean("prevent_background_refresh", false)
            }
            prefs.edit { putBoolean("is_first_run", false) }
        }

        // 加载保存的背景设置
        loadThemeMode()
        loadThemeColors()
        loadDynamicColorState()
        CardConfig.load(activity.applicationContext)
    }

    fun registerThemeChangeObserver(activity: MainActivity): ThemeChangeContentObserver {
        val contentObserver = ThemeChangeContentObserver(Handler(activity.mainLooper)) {
            activity.runOnUiThread {
                if (!ThemeConfig.preventBackgroundRefresh) {
                    ThemeConfig.backgroundImageLoaded = false
                    loadCustomBackground()
                }
            }
        }

        activity.contentResolver.registerContentObserver(
            Settings.System.getUriFor("ui_night_mode"),
            false,
            contentObserver
        )

        return contentObserver
    }

    fun unregisterThemeChangeObserver(activity: MainActivity, observer: ThemeChangeContentObserver) {
        activity.contentResolver.unregisterContentObserver(observer)
    }

    fun onActivityPause(activity: MainActivity) {
        CardConfig.save(activity.applicationContext)
        activity.getSharedPreferences("theme_prefs", Context.MODE_PRIVATE).edit {
            putBoolean("prevent_background_refresh", true)
        }
        ThemeConfig.preventBackgroundRefresh = true
    }

    fun onActivityResume() {
        if (!ThemeConfig.backgroundImageLoaded && !ThemeConfig.preventBackgroundRefresh) {
            loadCustomBackground()
        }
    }

    private fun loadThemeMode() {
    }

    private fun loadThemeColors() {
    }

    private fun loadDynamicColorState() {
    }

    private fun loadCustomBackground() {
    }
}