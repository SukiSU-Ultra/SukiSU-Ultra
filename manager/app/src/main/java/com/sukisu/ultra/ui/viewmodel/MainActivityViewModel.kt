package com.sukisu.ultra.ui.viewmodel

import android.content.Context
import android.content.SharedPreferences
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import com.sukisu.ultra.data.repository.SettingsRepository
import com.sukisu.ultra.data.repository.SettingsRepositoryImpl
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.theme.ThemeController
import com.sukisu.ultra.ui.util.ImageStorage
import java.io.File

class MainActivityViewModel(
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val prefs = ksuApp.getSharedPreferences("settings", Context.MODE_PRIVATE)
    private val settingRepo: SettingsRepository = SettingsRepositoryImpl()
    private val mainPageState = MainPageState(savedStateHandle)
    @Volatile private var systemWallpaperCacheValidated = false
    private val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == null || key in observedKeys) {
            if (key == "use_system_wallpaper") {
                if (settingRepo.useSystemWallpaper) {
                    refreshSystemWallpaper()
                } else {
                    systemWallpaperCacheValidated = false
                }
            }
            _uiState.value = readUiState()
        }
    }

    private val _uiState = MutableStateFlow(readUiState())
    val uiState: StateFlow<MainActivityUiState> = _uiState.asStateFlow()
    val selectedMainPage: StateFlow<Int> = mainPageState.selectedPage

    init {
        prefs.registerOnSharedPreferenceChangeListener(listener)
    }

    override fun onCleared() {
        prefs.unregisterOnSharedPreferenceChangeListener(listener)
    }

    fun setSelectedMainPage(page: Int) {
        mainPageState.updateSelectedPage(page)
    }

    /**
     * Keeps the cached launcher wallpaper up to date while the option is enabled. The copy
     * only runs when the system wallpaper file changed, so this is cheap on every resume.
     */
    fun refreshSystemWallpaper() {
        if (!settingRepo.useSystemWallpaper) return
        viewModelScope.launch {
            val result = ImageStorage.captureSystemWallpaper(ksuApp, force = false)
            systemWallpaperCacheValidated = result.path != null
            if (result.changed) {
                settingRepo.customBackgroundUpdatedAt = System.currentTimeMillis()
                if (settingRepo.extractColorFromBackground && result.path != null) {
                    settingRepo.keyColor = ImageStorage.extractSeedColor(File(result.path), settingRepo.keyColor)
                }
            }
            if (result.path == null) {
                settingRepo.useSystemWallpaper = false
            }
            _uiState.value = readUiState()
        }
    }

    private fun readUiState(): MainActivityUiState {
        val useSystemWallpaper = settingRepo.useSystemWallpaper
        val systemWallpaperPath = ImageStorage.systemWallpaperFile(ksuApp)
            .takeIf { it.isFile }?.absolutePath.orEmpty()
        return MainActivityUiState(
            appSettings = ThemeController.getAppSettings(),
            pageScale = settingRepo.pageScale,
            enableBlur = settingRepo.enableBlur,
            enableFloatingBottomBar = settingRepo.enableFloatingBottomBar,
            enableFloatingBottomBarBlur = settingRepo.enableFloatingBottomBarBlur,
            enableNavigationBadge = settingRepo.enableNavigationBadge,
            enableSwipeDismiss = settingRepo.enableSwipeDismiss,
            pagerInterceptionMode = settingRepo.pagerInterceptionMode,
            moduleDescriptionMaxLines = settingRepo.moduleDescriptionMaxLines,
            // The rest of the app only needs the effective background source.
            customBackgroundUri = if (
                useSystemWallpaper && systemWallpaperCacheValidated && systemWallpaperPath.isNotEmpty()
            ) {
                systemWallpaperPath
            } else {
                settingRepo.customBackgroundUri
            },
            customBackgroundUpdatedAt = settingRepo.customBackgroundUpdatedAt,
            cardBackgroundAlphaPercent = settingRepo.cardBackgroundAlphaPercent,
            customBackgroundBlurPercent = settingRepo.customBackgroundBlurPercent,
            customBackgroundScrimPercent = settingRepo.customBackgroundScrimPercent,
            uiMode = UiMode.fromValue(settingRepo.uiMode),
            customTexts = settingRepo.customTexts,
        )
    }

    private companion object {
        val observedKeys = setOf(
            "color_mode",
            "miuix_monet",
            "key_color",
            "color_style",
            "color_spec",
            "page_scale",
            "module_description_max_lines",
            "enable_blur",
            "enable_floating_bottom_bar",
            "enable_floating_bottom_bar_blur",
            "enable_navigation_badge",
            "enable_swipe_dismiss",
            "pager_interception_mode",
            "custom_bg_uri",
            "custom_bg_updated_at",
            "use_system_wallpaper",
            "card_bg_alpha_percent",
            "custom_bg_blur_percent",
            "custom_bg_scrim_percent",
            "ui_mode",
            "custom_texts",
        )
    }
}

private const val SELECTED_MAIN_PAGE_KEY = "selected_main_page"

private class MainPageState(
    private val savedStateHandle: SavedStateHandle,
) {
    val selectedPage: StateFlow<Int> = savedStateHandle.getStateFlow(SELECTED_MAIN_PAGE_KEY, 0)

    fun updateSelectedPage(page: Int) {
        savedStateHandle[SELECTED_MAIN_PAGE_KEY] = MainPagerConfig.coercePage(page)
    }
}

object MainPagerConfig {
    const val PAGE_COUNT = 4
    const val LAST_PAGE_INDEX = PAGE_COUNT - 1

    fun coercePage(page: Int): Int = page.coerceIn(0, LAST_PAGE_INDEX)
}
