package com.sukisu.ultra.ui.activity.util

import android.content.Context
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.runtime.Composable
import androidx.lifecycle.LifecycleCoroutineScope
import com.sukisu.ultra.Natives
import com.sukisu.ultra.ui.MainActivity
import com.sukisu.ultra.ui.util.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.*
import android.net.Uri
import androidx.lifecycle.lifecycleScope
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.sukisu.ultra.ui.component.ZipFileDetector
import com.sukisu.ultra.ui.component.ZipFileInfo
import com.sukisu.ultra.ui.component.ZipType
import com.ramcosta.composedestinations.generated.destinations.FlashScreenDestination
import com.ramcosta.composedestinations.generated.destinations.InstallScreenDestination
import com.sukisu.ultra.ui.screen.FlashIt
import kotlinx.coroutines.withContext
import androidx.core.content.edit

object AnimatedBottomBar {
    @Composable
    fun AnimatedBottomBarWrapper(
        showBottomBar: Boolean,
        content: @Composable () -> Unit
    ) {
        AnimatedVisibility(
            visible = showBottomBar,
            enter = slideInVertically(initialOffsetY = { it }) + fadeIn(),
            exit = slideOutVertically(targetOffsetY = { it }) + fadeOut()
        ) {
            content()
        }
    }
}

object UltraActivityUtils {

    suspend fun detectZipTypeAndShowConfirmation(
        activity: MainActivity,
        zipUris: ArrayList<Uri>,
        onResult: (List<ZipFileInfo>) -> Unit
    ) {
        val infos = ZipFileDetector.detectAndParseZipFiles(activity, zipUris)
        withContext(Dispatchers.Main) { onResult(infos) }
    }

    fun navigateToFlashScreen(
        activity: MainActivity,
        zipFiles: List<ZipFileInfo>,
        navigator: DestinationsNavigator
    ) {
        activity.lifecycleScope.launch {
            val moduleUris = zipFiles.filter { it.type == ZipType.MODULE }.map { it.uri }
            val kernelUris = zipFiles.filter { it.type == ZipType.KERNEL }.map { it.uri }

            when {
                kernelUris.isNotEmpty() && moduleUris.isEmpty() -> {
                    if (kernelUris.size == 1 && rootAvailable()) {
                        navigator.navigate(
                            InstallScreenDestination(
                                preselectedKernelUri = kernelUris.first().toString()
                            )
                        )
                    }
                    setAutoExitAfterFlash(activity)
                }

                moduleUris.isNotEmpty() -> {
                    navigator.navigate(
                        FlashScreenDestination(
                            FlashIt.FlashModules(ArrayList(moduleUris))
                        )
                    )
                    setAutoExitAfterFlash(activity)
                }
            }
        }
    }

    private fun setAutoExitAfterFlash(activity: Context) {
        activity.getSharedPreferences("kernel_flash_prefs", Context.MODE_PRIVATE)
            .edit {
                putBoolean("auto_exit_after_flash", true)
            }
    }
}

object AppData {
    object DataRefreshManager {
        // 私有状态流
        private val _superuserCount = MutableStateFlow(0)
        private val _moduleCount = MutableStateFlow(0)
        private val _kpmModuleCount = MutableStateFlow(0)

        // 公开的只读状态流
        val superuserCount: StateFlow<Int> = _superuserCount.asStateFlow()
        val moduleCount: StateFlow<Int> = _moduleCount.asStateFlow()
        val kpmModuleCount: StateFlow<Int> = _kpmModuleCount.asStateFlow()

        /**
         * 刷新所有数据计数
         */
        fun refreshData() {
            _superuserCount.value = getSuperuserCountUse()
            _moduleCount.value = getModuleCountUse()
            _kpmModuleCount.value = getKpmModuleCountUse()
        }
    }

    /**
     * 获取超级用户应用计数
     */
    fun getSuperuserCountUse(): Int {
        return try {
            if (!rootAvailable()) return 0
            getSuperuserCount()
        } catch (_: Exception) {
            0
        }
    }

    /**
     * 获取模块计数
     */
    fun getModuleCountUse(): Int {
        return try {
            if (!rootAvailable()) return 0
            getModuleCount()
        } catch (_: Exception) {
            0
        }
    }

    /**
     * 获取KPM模块计数
     */
    fun getKpmModuleCountUse(): Int {
        return try {
            if (!rootAvailable()) return 0
            val kpmVersion = getKpmVersionUse()
            if (kpmVersion.isEmpty() || kpmVersion.startsWith("Error")) return 0
            getKpmModuleCount()
        } catch (_: Exception) {
            0
        }
    }

    /**
     * 获取KPM版本
     */
    fun getKpmVersionUse(): String {
        return try {
            if (!rootAvailable()) return ""
            val version = getKpmVersion()
            version.ifEmpty { "" }
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }

    /**
     * 检查是否是完整功能模式
     */
    fun isFullFeatured(packageName: String): Boolean {
        val isManager = Natives.becomeManager(packageName)
        return isManager && !Natives.requireNewKernel() && rootAvailable()
    }
}

object DataRefreshUtils {
    fun startDataRefreshCoroutine(scope: LifecycleCoroutineScope) {
        scope.launch(Dispatchers.IO) {
            while (isActive) {
                AppData.DataRefreshManager.refreshData()
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
            AppData.DataRefreshManager.refreshData()
        }
    }
}

object DisplayUtils {
    fun applyCustomDpi(context: Context) {
        val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        val customDpi = prefs.getInt("app_dpi", 0)

        if (customDpi > 0) {
            try {
                val resources = context.resources
                val metrics = resources.displayMetrics
                metrics.density = customDpi / 160f
                @Suppress("DEPRECATION")
                metrics.scaledDensity = customDpi / 160f
                metrics.densityDpi = customDpi
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }
}