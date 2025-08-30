package zako.zako.zako.zakoui.activity.util

import android.content.Context
import androidx.lifecycle.LifecycleCoroutineScope
import com.sukisu.ultra.ui.MainActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import zako.zako.zako.zakoui.activity.util.AppData.DataRefreshManager

object DataRefreshUtils {

    fun startDataRefreshCoroutine(scope: LifecycleCoroutineScope) {
        scope.launch(Dispatchers.IO) {
            while (isActive) {
                DataRefreshManager.refreshData()
                delay(5000)
            }
        }
    }

    fun startSettingsMonitorCoroutine(
        scope: LifecycleCoroutineScope,
        activity: MainActivity,
        settingsStateFlow: MutableStateFlow<MainActivity.SettingsState>
    ) {
        scope.launch(Dispatchers.IO) {
            while (isActive) {
                val prefs = activity.getSharedPreferences("settings", Context.MODE_PRIVATE)
                settingsStateFlow.value = MainActivity.SettingsState(
                    isHideOtherInfo = prefs.getBoolean("is_hide_other_info", false),
                    showKpmInfo = prefs.getBoolean("show_kpm_info", false)
                )
                delay(1000)
            }
        }
    }

    fun refreshData(scope: LifecycleCoroutineScope) {
        scope.launch {
            DataRefreshManager.refreshData()
        }
    }
}