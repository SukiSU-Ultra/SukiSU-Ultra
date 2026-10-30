package com.sukisu.ultra.ui.viewmodel

import android.content.Context
import android.net.Uri
import android.system.OsConstants
import android.widget.Toast
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.data.repository.SettingsRepository
import com.sukisu.ultra.data.repository.SettingsRepositoryImpl
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.screen.settings.SettingsUiState
import com.sukisu.ultra.ui.theme.ColorMode
import com.sukisu.ultra.ui.theme.ThemeController
import com.sukisu.ultra.ui.util.BgStorage
import com.sukisu.ultra.ui.screen.module.ModuleNameSort
import com.sukisu.ultra.ui.util.BuiltinAppIcon
import com.sukisu.ultra.ui.util.BuiltinAppIcons
import com.sukisu.ultra.ui.util.ImportedTheme
import com.sukisu.ultra.ui.util.ThemePackageData
import com.sukisu.ultra.ui.util.ThemePackageStorage
import com.sukisu.ultra.ui.util.findActivity
import java.io.File

class SettingsViewModel(
    private val repo: SettingsRepository = SettingsRepositoryImpl()
) : ViewModel() {

    private val _uiState = MutableStateFlow(SettingsUiState(
        checkUpdate = repo.checkUpdate,
        checkCiUpdate = repo.checkCiUpdate,
        checkModuleUpdate = repo.checkModuleUpdate,
        backgroundAppearanceExpanded = repo.backgroundAppearanceExpanded,
        customHomeTitle = repo.customHomeTitle,
        customWorkingTitle = repo.customWorkingTitle,
    ))
    val uiState: StateFlow<SettingsUiState> = _uiState.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        viewModelScope.launch {
            val appIconId = repo.appIconId
            val appIconDynamicColor = repo.appIconDynamicColor
            val themeMode = repo.themeMode
            val miuixMonet = repo.miuixMonet
            val keyColor = repo.keyColor
            val enablePredictiveBack = repo.enablePredictiveBack
            val enableSwipeDismiss = repo.enableSwipeDismiss
            val pagerInterceptionMode = repo.pagerInterceptionMode
            val enableBlur = repo.enableBlur
            val enableFloatingBottomBar = repo.enableFloatingBottomBar
            val enableFloatingBottomBarBlur = repo.enableFloatingBottomBarBlur
            val enableNavigationBadge = repo.enableNavigationBadge
            val pageScale = repo.pageScale
            val moduleDescriptionMaxLines = repo.moduleDescriptionMaxLines
            val enableWebDebugging = repo.enableWebDebugging
            val autoDeleteModuleZip = repo.autoDeleteModuleZip
            val showFullStatus = repo.showFullStatus
            val hideHomeWarnings = repo.hideHomeWarnings
            val colorStyle = repo.colorStyle
            val colorSpec = repo.colorSpec
            val isLkmMode = repo.isLkmMode()

            // Async loading for natives/features
            val suCompatStatus = repo.getSuCompatStatus()
            val suCompatPersistValue = repo.getSuCompatPersistValue()
            val isSuEnabled = repo.isSuEnabled()

            // Forced features show the value in effect, the persisted one is ignored
            val suCompatMode = when {
                suCompatStatus == "forced" -> if (isSuEnabled) 0 else 2
                suCompatPersistValue == 0L -> 2
                !isSuEnabled -> 1
                else -> 0
            }

            val kernelUmountStatus = repo.getKernelUmountStatus()
            val isKernelUmountEnabled = repo.isKernelUmountEnabled()
            val selinuxHideStatus = repo.getSelinuxHideStatus()
            val isSelinuxHideEnabled = repo.isSelinuxHideEnabled()
            val avcSpoofStatus = repo.getAvcSpoofStatus()
            val isAvcSpoofEnabled = repo.isAvcSpoofEnabled()
            val mountHideStatus = repo.getMountHideStatus()
            val isMountHideEnabled = repo.isMountHideEnabled()
            val sulogStatus = repo.getSulogStatus()
            val isSulogEnabled = if (sulogStatus == "forced") {
                repo.getSulogValue() == 1L
            } else {
                repo.getSulogPersistValue() == 1L
            }
            val adbRootStatus = repo.getAdbRootStatus()
            val isAdbRootEnabled = if (adbRootStatus == "forced") {
                repo.getAdbRootValue() == 1L
            } else {
                repo.getAdbRootPersistValue() == 1L
            }
            val shellSuAdbOnlyStatus = repo.getShellSuAdbOnlyStatus()
            val isShellSuAdbOnlyEnabled = if (shellSuAdbOnlyStatus == "forced") {
                repo.getShellSuAdbOnlyValue() == 1L
            } else {
                repo.getShellSuAdbOnlyPersistValue() == 1L
            }
            val isDefaultUmountModules = repo.isDefaultUmountModules()
            val uiMode = repo.uiMode
            val appLanguage = repo.appLanguage
            val autoJailbreak = repo.autoJailbreak
            val useSoftReboot = repo.useSoftReboot
            val isLateLoadMode = Natives.isLateLoadMode

            _uiState.update {
                it.copy(
                    uiMode = uiMode,
                    appLanguage = appLanguage,
                    checkUpdate = repo.checkUpdate,
                    checkCiUpdate = repo.checkCiUpdate,
                    checkModuleUpdate = repo.checkModuleUpdate,
                    appIconId = appIconId,
                    appIconDynamicColor = appIconDynamicColor,
                    backgroundAppearanceExpanded = repo.backgroundAppearanceExpanded,
                    customHomeTitle = repo.customHomeTitle,
                    customWorkingTitle = repo.customWorkingTitle,
                    themeMode = themeMode,
                    miuixMonet = miuixMonet,
                    keyColor = keyColor,
                    enablePredictiveBack = enablePredictiveBack,
                    enableSwipeDismiss = enableSwipeDismiss,
                    pagerInterceptionMode = pagerInterceptionMode,
                    enableBlur = enableBlur,
                    enableFloatingBottomBar = enableFloatingBottomBar,
                    enableFloatingBottomBarBlur = enableFloatingBottomBarBlur,
                    enableNavigationBadge = enableNavigationBadge,
                    pageScale = pageScale,
                    moduleDescriptionMaxLines = moduleDescriptionMaxLines,
                    enableWebDebugging = enableWebDebugging,
                    autoDeleteModuleZip = autoDeleteModuleZip,
                    showFullStatus = showFullStatus,
                    hideHomeWarnings = hideHomeWarnings,
                    colorStyle = colorStyle,
                    colorSpec = colorSpec,
                    suCompatStatus = suCompatStatus,
                    suCompatMode = suCompatMode,
                    isSuEnabled = isSuEnabled,
                    adbRootStatus = adbRootStatus,
                    isAdbRootEnabled = isAdbRootEnabled,
                    shellSuAdbOnlyStatus = shellSuAdbOnlyStatus,
                    isShellSuAdbOnlyEnabled = isShellSuAdbOnlyEnabled,
                    kernelUmountStatus = kernelUmountStatus,
                    isKernelUmountEnabled = isKernelUmountEnabled,
                    selinuxHideStatus = selinuxHideStatus,
                    isSelinuxHideEnabled = isSelinuxHideEnabled,
                    avcSpoofStatus = avcSpoofStatus,
                    isAvcSpoofEnabled = isAvcSpoofEnabled,
                    mountHideStatus = mountHideStatus,
                    isMountHideEnabled = isMountHideEnabled,
                    sulogStatus = sulogStatus,
                    isSulogEnabled = isSulogEnabled,
                    isDefaultUmountModules = isDefaultUmountModules,
                    isLkmMode = isLkmMode,
                    autoJailbreak = autoJailbreak,
                    useSoftReboot = useSoftReboot,
                    isLateLoadMode = isLateLoadMode,
                    customBackgroundUri = repo.customBackgroundUri,
                    customBackgroundUpdatedAt = repo.customBackgroundUpdatedAt,
                    useSystemWallpaper = repo.useSystemWallpaper && BgStorage.systemWallpaperFile(ksuApp).isFile,
                    systemWallpaperPath = "",
                    extractColorFromBackground = repo.extractColorFromBackground,
                    cardBackgroundAlphaPercent = repo.cardBackgroundAlphaPercent,
                    customBackgroundBlurPercent = repo.customBackgroundBlurPercent,
                    customBackgroundScrimPercent = repo.customBackgroundScrimPercent,
                )
            }
        }
    }

    /** Copies a newly picked image into the crop cache and hands its path to the crop screen. */
    fun stagePickedBackground(context: Context, uri: Uri, onReady: (String?) -> Unit) {
        viewModelScope.launch {
            val path = BgStorage.stageUri(context, uri)
            if (path == null) {
                Toast.makeText(
                    ksuApp,
                    R.string.background_crop_prepare_failed,
                    Toast.LENGTH_SHORT,
                ).show()
            }
            onReady(path)
        }
    }

    /** Copies the current background so the user can re-crop it without losing the original. */
    fun stageCurrentBackground(context: Context, onReady: (String?) -> Unit) {
        viewModelScope.launch {
            val current = repo.customBackgroundUri
            val path = if (current.isNotEmpty()) {
                BgStorage.stageFile(context, File(current))
            } else {
                null
            }
            if (path == null) {
                Toast.makeText(
                    ksuApp,
                    R.string.background_crop_prepare_failed,
                    Toast.LENGTH_SHORT,
                ).show()
            }
            onReady(path)
        }
    }

    /** Applies the in-app or gallery crop result and refreshes the dynamic color seed. */
    suspend fun finishBackgroundCrop(
        context: Context,
        output: File,
        sourcePath: String?,
    ): Boolean = withContext(Dispatchers.IO) {
        val savedPath = BgStorage.replace(context, output) ?: return@withContext false
        runCatching { if (output.isFile) output.delete() }
        BgStorage.discardStaged(sourcePath)
        val seed = if (repo.extractColorFromBackground) {
            BgStorage.extractSeedColor(File(savedPath), repo.keyColor)
        } else {
            repo.keyColor
        }
        repo.customBackgroundUri = savedPath
        repo.customBackgroundUpdatedAt = System.currentTimeMillis()
        repo.keyColor = seed
        _uiState.update {
            it.copy(
                customBackgroundUri = savedPath,
                customBackgroundUpdatedAt = repo.customBackgroundUpdatedAt,
                keyColor = seed,
            )
        }
        true
    }

    suspend fun applyOriginalBackground(context: Context, sourcePath: String): Boolean =
        withContext(Dispatchers.IO) {
            val source = File(sourcePath)
            if (!source.isFile) return@withContext false
            finishBackgroundCrop(context, source, null)
        }

    /**
     * Re-reads the appearance preferences. The crop screen owns a separate view model
     * instance, so the theme screen needs this when it is resumed from the cropper.
     */
    fun refreshBackgroundAppearance() {
        if (repo.useSystemWallpaper) {
            viewModelScope.launch {
                refreshSystemWallpaperCache()
                updateBackgroundAppearanceState()
            }
        } else {
            updateBackgroundAppearanceState()
        }
    }

    /** Re-copies the launcher wallpaper when it changed since the last capture. */
    private suspend fun refreshSystemWallpaperCache() {
        val result = BgStorage.captureSystemWallpaper(ksuApp, force = false)
        if (result.changed) {
            repo.customBackgroundUpdatedAt = System.currentTimeMillis()
            if (repo.extractColorFromBackground && result.path != null) {
                repo.keyColor = BgStorage.extractSeedColor(File(result.path), repo.keyColor)
            }
        }
        if (result.path == null) {
            // The cache cannot be decoded or rebuilt; fall back to the picked image.
            repo.useSystemWallpaper = false
        }
    }

    private fun updateBackgroundAppearanceState() {
        val useSystemWallpaper = repo.useSystemWallpaper
        val systemWallpaperPath = BgStorage.systemWallpaperFile(ksuApp)
            .takeIf { it.isFile }?.absolutePath.orEmpty()
        _uiState.update {
            it.copy(
                customBackgroundUri = repo.customBackgroundUri,
                customBackgroundUpdatedAt = repo.customBackgroundUpdatedAt,
                cardBackgroundAlphaPercent = repo.cardBackgroundAlphaPercent,
                customBackgroundBlurPercent = repo.customBackgroundBlurPercent,
                customBackgroundScrimPercent = repo.customBackgroundScrimPercent,
                keyColor = repo.keyColor,
                useSystemWallpaper = useSystemWallpaper && systemWallpaperPath.isNotEmpty(),
                systemWallpaperPath = systemWallpaperPath,
                extractColorFromBackground = repo.extractColorFromBackground,
            )
        }
    }

    fun setUseSystemWallpaper(context: Context, enabled: Boolean) {
        if (!enabled) {
            repo.useSystemWallpaper = false
            _uiState.update {
                it.copy(
                    useSystemWallpaper = false,
                    systemWallpaperPath = "",
                    isSystemWallpaperBusy = false,
                )
            }
            return
        }
        if (_uiState.value.isSystemWallpaperBusy) return
        _uiState.update { it.copy(isSystemWallpaperBusy = true) }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    BgStorage.captureSystemWallpaper(context, force = true)
                }
                if (result.path == null) {
                    Toast.makeText(
                        ksuApp,
                        R.string.settings_system_wallpaper_failed,
                        Toast.LENGTH_SHORT,
                    ).show()
                    return@launch
                }

                val keyColor = if (repo.extractColorFromBackground) {
                    withContext(Dispatchers.IO) {
                        BgStorage.extractSeedColor(File(result.path), repo.keyColor)
                    }
                } else {
                    repo.keyColor
                }
                val updatedAt = System.currentTimeMillis()
                repo.useSystemWallpaper = true
                repo.customBackgroundUpdatedAt = updatedAt
                if (repo.extractColorFromBackground) repo.keyColor = keyColor
                _uiState.update {
                    it.copy(
                        useSystemWallpaper = true,
                        systemWallpaperPath = result.path,
                        customBackgroundUpdatedAt = updatedAt,
                        keyColor = keyColor,
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                Toast.makeText(
                    ksuApp,
                    R.string.settings_system_wallpaper_failed,
                    Toast.LENGTH_SHORT,
                ).show()
            } finally {
                _uiState.update { it.copy(isSystemWallpaperBusy = false) }
            }
        }
    }

    /**
     * Toggles deriving the key color from the background. Enabling it immediately re-seeds from
     * the active background; disabling leaves the current color in place for manual selection.
     */
    fun setExtractColorFromBackground(enabled: Boolean) {
        repo.extractColorFromBackground = enabled
        _uiState.update { it.copy(extractColorFromBackground = enabled) }
        if (!enabled) return

        val backgroundPath = if (repo.useSystemWallpaper) {
            BgStorage.systemWallpaperFile(ksuApp).takeIf { it.isFile }?.absolutePath
        } else {
            repo.customBackgroundUri.takeIf { it.isNotEmpty() }
        } ?: return
        val background = File(backgroundPath).takeIf { it.isFile } ?: return

        viewModelScope.launch {
            val seed = BgStorage.extractSeedColor(background, repo.keyColor)
            repo.keyColor = seed
            _uiState.update { it.copy(keyColor = seed) }
        }
    }

    fun clearCustomBackground(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            BgStorage.clear(context)
            repo.customBackgroundUri = ""
            repo.customBackgroundUpdatedAt = System.currentTimeMillis()
            _uiState.update {
                it.copy(
                    customBackgroundUri = "",
                    customBackgroundUpdatedAt = repo.customBackgroundUpdatedAt,
                )
            }
        }
    }

    fun setCardBackgroundAlphaPercent(percent: Int) {
        repo.cardBackgroundAlphaPercent = percent
        _uiState.update { it.copy(cardBackgroundAlphaPercent = percent) }
    }

    fun setCustomBackgroundBlurPercent(percent: Int) {
        repo.customBackgroundBlurPercent = percent
        _uiState.update { it.copy(customBackgroundBlurPercent = percent) }
    }

    fun setCustomBackgroundScrimPercent(percent: Int) {
        repo.customBackgroundScrimPercent = percent
        _uiState.update { it.copy(customBackgroundScrimPercent = percent) }
    }

    fun exportTheme(context: Context, uri: Uri) {
        viewModelScope.launch {
            val state = _uiState.value
            val backgroundFile = state.customBackgroundUri
                .takeIf { it.isNotEmpty() }
                ?.let { path -> File(path).takeIf { it.isFile } }
            val builtinIconIds = setOf(
                BuiltinAppIcons.DEFAULT_ID,
                BuiltinAppIcons.KERNELSU_ID,
                BuiltinAppIcons.LOGO_ID,
                BuiltinAppIcons.ZAKO_ID,
            )
            val exportedIconId = if (state.appIconId in builtinIconIds) {
                state.appIconId
            } else {
                BuiltinAppIcons.DEFAULT_ID
            }
            val data = ThemePackageData(
                themeMode = state.themeMode,
                miuixMonet = state.miuixMonet,
                keyColor = state.keyColor,
                colorStyle = state.colorStyle,
                colorSpec = state.colorSpec,
                cardBackgroundAlphaPercent = state.cardBackgroundAlphaPercent,
                customBackgroundBlurPercent = state.customBackgroundBlurPercent,
                customBackgroundScrimPercent = state.customBackgroundScrimPercent,
                hasBackground = backgroundFile != null,
                uiMode = state.uiMode,
                appIconId = exportedIconId,
                enableFloatingBottomBar = state.enableFloatingBottomBar,
                enableFloatingBottomBarBlur = state.enableFloatingBottomBarBlur,
                enableNavigationBadge = state.enableNavigationBadge,
                enablePredictiveBack = repo.enablePredictiveBack,
                enableSwipeDismiss = repo.enableSwipeDismiss,
                moduleSortEnabledFirst = repo.moduleSortEnabledFirst,
                moduleSortActionFirst = repo.moduleSortActionFirst,
                moduleSortWebUiFirst = repo.moduleSortWebUiFirst,
                moduleSortZygiskFirst = repo.moduleSortZygiskFirst,
                moduleSortMetamoduleFirst = repo.moduleSortMetamoduleFirst,
                moduleSortNameOrder = repo.moduleSortNameOrder,
                moduleSortManual = repo.moduleSortManual,
            )
            ThemePackageStorage.export(context, uri, data, backgroundFile)
                .onSuccess {
                    Toast.makeText(ksuApp, R.string.theme_export_success, Toast.LENGTH_SHORT).show()
                }
                .onFailure {
                    Toast.makeText(ksuApp, R.string.theme_export_failed, Toast.LENGTH_SHORT).show()
                }
        }
    }

    fun importTheme(context: Context, uri: Uri) {
        viewModelScope.launch {
            ThemePackageStorage.import(context, uri)
                .onSuccess { imported ->
                    applyImportedTheme(context, imported)
                    Toast.makeText(ksuApp, R.string.theme_import_success, Toast.LENGTH_SHORT).show()
                }
                .onFailure {
                    Toast.makeText(ksuApp, R.string.theme_import_failed, Toast.LENGTH_SHORT).show()
                }
        }
    }

    private suspend fun applyImportedTheme(context: Context, imported: ImportedTheme) {
        val current = _uiState.value
        val data = imported.data
        val themeMode = data.themeMode?.takeIf { it in 0..6 } ?: current.themeMode
        val miuixMonet = data.miuixMonet ?: current.miuixMonet
        val keyColor = data.keyColor ?: current.keyColor
        val colorStyle = data.colorStyle
            ?.takeIf { name -> runCatching { PaletteStyle.valueOf(name) }.isSuccess }
            ?: current.colorStyle
        val colorSpec = data.colorSpec
            ?.takeIf { name -> runCatching { ColorSpec.SpecVersion.valueOf(name) }.isSuccess }
            ?: current.colorSpec
        val cardAlpha = (data.cardBackgroundAlphaPercent ?: current.cardBackgroundAlphaPercent)
            .coerceIn(BgStorage.CARD_ALPHA_MIN, BgStorage.CARD_ALPHA_MAX)
        val blurPercent = (data.customBackgroundBlurPercent ?: current.customBackgroundBlurPercent)
            .coerceIn(BgStorage.BACKGROUND_BLUR_PERCENT_MIN, BgStorage.BACKGROUND_BLUR_PERCENT_MAX)
        val scrimPercent = (data.customBackgroundScrimPercent ?: current.customBackgroundScrimPercent)
            .coerceIn(BgStorage.BACKGROUND_SCRIM_MIN, BgStorage.BACKGROUND_SCRIM_MAX)
        val backgroundUri = if (imported.backgroundPath != null) {
            imported.backgroundPath
        } else {
            BgStorage.clear(context)
            ""
        }

        // UI Mode
        val targetUiMode = data.uiMode?.takeIf { it == "miuix" || it == "material" } ?: current.uiMode
        repo.uiMode = targetUiMode

        repo.themeMode = themeMode
        repo.miuixMonet = miuixMonet
        repo.keyColor = keyColor
        repo.colorStyle = colorStyle
        repo.colorSpec = colorSpec
        repo.cardBackgroundAlphaPercent = cardAlpha
        repo.customBackgroundBlurPercent = blurPercent
        repo.customBackgroundScrimPercent = scrimPercent
        repo.customBackgroundUri = backgroundUri
        // The imported appearance owns the background; the device wallpaper is a local choice.
        repo.useSystemWallpaper = false
        if (imported.backgroundPath != null) {
            repo.customBackgroundUpdatedAt = System.currentTimeMillis()
        }

        // App Icon (builtin icons only)
        val builtinIconIds = setOf(
            BuiltinAppIcons.DEFAULT_ID,
            BuiltinAppIcons.KERNELSU_ID,
            BuiltinAppIcons.LOGO_ID,
            BuiltinAppIcons.ZAKO_ID,
        )
        val targetIconId = data.appIconId?.takeIf { it in builtinIconIds }
        if (targetIconId != null) {
            repo.appIconId = targetIconId
            val icon = BuiltinAppIcons.find(targetIconId)
            BuiltinAppIcons.apply(
                context = context,
                icon = icon,
                dynamicColor = repo.appIconDynamicColor,
            )
        }
        val effectiveIconId = targetIconId ?: current.appIconId

        // Visual Appearance (Bottom Bar)
        val floatingBottomBar = data.enableFloatingBottomBar ?: current.enableFloatingBottomBar
        val floatingBottomBarBlur = data.enableFloatingBottomBarBlur ?: current.enableFloatingBottomBarBlur
        val navigationBadge = data.enableNavigationBadge ?: current.enableNavigationBadge
        repo.enableFloatingBottomBar = floatingBottomBar
        repo.enableFloatingBottomBarBlur = floatingBottomBarBlur
        repo.enableNavigationBadge = navigationBadge

        // Gestures / Fluidity
        val predictiveBack = data.enablePredictiveBack ?: repo.enablePredictiveBack
        val swipeDismiss = data.enableSwipeDismiss ?: repo.enableSwipeDismiss
        repo.enablePredictiveBack = predictiveBack
        repo.enableSwipeDismiss = swipeDismiss

        // Module Sorting
        data.moduleSortEnabledFirst?.let { repo.moduleSortEnabledFirst = it }
        data.moduleSortActionFirst?.let { repo.moduleSortActionFirst = it }
        data.moduleSortWebUiFirst?.let { repo.moduleSortWebUiFirst = it }
        data.moduleSortZygiskFirst?.let { repo.moduleSortZygiskFirst = it }
        data.moduleSortMetamoduleFirst?.let { repo.moduleSortMetamoduleFirst = it }
        data.moduleSortNameOrder?.let { order ->
            if (runCatching { ModuleNameSort.valueOf(order) }.isSuccess) {
                repo.moduleSortNameOrder = order
            }
        }
        data.moduleSortManual?.let { repo.moduleSortManual = it }

        _uiState.update {
            it.copy(
                uiMode = targetUiMode,
                appIconId = effectiveIconId,
                themeMode = themeMode,
                miuixMonet = miuixMonet,
                keyColor = keyColor,
                colorStyle = colorStyle,
                colorSpec = colorSpec,
                cardBackgroundAlphaPercent = cardAlpha,
                customBackgroundBlurPercent = blurPercent,
                customBackgroundScrimPercent = scrimPercent,
                customBackgroundUri = backgroundUri,
                customBackgroundUpdatedAt = repo.customBackgroundUpdatedAt,
                useSystemWallpaper = false,
                systemWallpaperPath = "",
                enableFloatingBottomBar = floatingBottomBar,
                enableFloatingBottomBarBlur = floatingBottomBarBlur,
                enableNavigationBadge = navigationBadge,
                enablePredictiveBack = predictiveBack,
                enableSwipeDismiss = swipeDismiss,
            )
        }
    }

    fun resetBackgroundAppearance() {
        viewModelScope.launch {
            val defaultBlur = BgStorage.defaultBackgroundBlurPercent(ksuApp)
            repo.cardBackgroundAlphaPercent = BgStorage.DEFAULT_CARD_ALPHA
            repo.customBackgroundBlurPercent = defaultBlur
            repo.customBackgroundScrimPercent = BgStorage.DEFAULT_BACKGROUND_SCRIM

            // Theme colors, dynamic color and the custom background image are user choices.
            _uiState.update {
                it.copy(
                    cardBackgroundAlphaPercent = BgStorage.DEFAULT_CARD_ALPHA,
                    customBackgroundBlurPercent = defaultBlur,
                    customBackgroundScrimPercent = BgStorage.DEFAULT_BACKGROUND_SCRIM,
                )
            }

            Toast.makeText(ksuApp, R.string.theme_reset_done, Toast.LENGTH_SHORT).show()
        }
    }

    fun setCheckCiUpdate(enabled: Boolean) {
        repo.checkCiUpdate = enabled
        _uiState.update { it.copy(checkCiUpdate = enabled) }
    }

    fun setCheckUpdate(enabled: Boolean) {
        repo.checkUpdate = enabled
        _uiState.update { it.copy(checkUpdate = enabled) }
    }

    fun setUiMode(mode: String) {
        val oldMode = repo.uiMode
        val currentThemeMode = repo.themeMode

        val newThemeMode = when (oldMode) {
            "material" if mode == "miuix" -> {
                val colorMode = ColorMode.fromValue(currentThemeMode)
                val baseMode = if (colorMode == ColorMode.DARK_AMOLED) 2 else currentThemeMode
                if (repo.miuixMonet && !colorMode.isMonet) {
                    ColorMode.fromValue(baseMode).toMonetMode()
                } else if (!repo.miuixMonet && colorMode.isMonet) {
                    ColorMode.fromValue(baseMode).toNonMonetMode()
                } else baseMode
            }

            "miuix" if mode == "material" -> {
                val colorMode = ColorMode.fromValue(currentThemeMode)
                if (colorMode.isMonet) {
                    colorMode.toNonMonetMode()
                } else currentThemeMode
            }

            else -> currentThemeMode
        }

        repo.uiMode = mode
        repo.themeMode = newThemeMode
        _uiState.update { it.copy(uiMode = mode, themeMode = newThemeMode) }
    }

    fun setLanguage(context: Context, tag: String) {
        if (repo.appLanguage == tag) return
        repo.appLanguage = tag
        _uiState.update { it.copy(appLanguage = tag) }
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.TIRAMISU) {
            context.findActivity()?.recreate()
        }
    }

    fun setCheckModuleUpdate(enabled: Boolean) {
        repo.checkModuleUpdate = enabled
        _uiState.update { it.copy(checkModuleUpdate = enabled) }
    }

    fun setAutoDeleteModuleZip(enabled: Boolean) {
        repo.autoDeleteModuleZip = enabled
        _uiState.update { it.copy(autoDeleteModuleZip = enabled) }
    }
    fun setAppIcon(context: Context, iconId: String) {
        val icon = BuiltinAppIcons.find(iconId)
        repo.appIconId = icon.id
        _uiState.update { it.copy(appIconId = icon.id) }
        applyAppIconSettings(context, icon)
    }

    fun setAppIconDynamicColor(context: Context, enabled: Boolean) {
        repo.appIconDynamicColor = enabled
        _uiState.update { it.copy(appIconDynamicColor = enabled) }
        applyAppIconSettings(context)
    }

    fun setBackgroundAppearanceExpanded(expanded: Boolean) {
        repo.backgroundAppearanceExpanded = expanded
        _uiState.update { it.copy(backgroundAppearanceExpanded = expanded) }
    }

    fun setCustomHomeTitle(title: String) {
        val normalizedTitle = title.trim()
        repo.customHomeTitle = normalizedTitle
        _uiState.update { it.copy(customHomeTitle = normalizedTitle) }
    }

    fun setCustomWorkingTitle(title: String) {
        val normalizedTitle = title.trim()
        repo.customWorkingTitle = normalizedTitle
        _uiState.update { it.copy(customWorkingTitle = normalizedTitle) }
    }

    private fun applyAppIconSettings(
        context: Context,
        icon: BuiltinAppIcon = BuiltinAppIcons.find(repo.appIconId),
    ) {
        BuiltinAppIcons.apply(
            context = context,
            icon = icon,
            dynamicColor = repo.appIconDynamicColor,
        )
    }

    fun setThemeMode(mode: Int) {
        val currentUiMode = repo.uiMode
        val effectiveMode = if (currentUiMode == "miuix" && _uiState.value.miuixMonet) {
            mode + 3
        } else {
            mode
        }
        repo.themeMode = effectiveMode
        _uiState.update { it.copy(themeMode = effectiveMode) }
    }

    fun setColorMode(mode: ColorMode) {
        repo.themeMode = mode.value
        _uiState.update { it.copy(themeMode = mode.value) }
    }

    fun setMiuixMonet(enabled: Boolean) {
        val currentThemeMode = repo.themeMode
        val colorMode = ColorMode.fromValue(currentThemeMode)
        val newThemeMode = if (enabled) {
            if (!colorMode.isMonet) colorMode.toMonetMode() else currentThemeMode
        } else {
            if (colorMode.isMonet) colorMode.toNonMonetMode() else currentThemeMode
        }
        repo.miuixMonet = enabled
        repo.themeMode = newThemeMode
        _uiState.update { it.copy(miuixMonet = enabled, themeMode = newThemeMode) }
    }

    fun setKeyColor(color: Int) {
        repo.keyColor = color
        _uiState.update { it.copy(keyColor = color) }
    }

    fun setColorStyle(style: String) {
        repo.colorStyle = style
        _uiState.update { it.copy(colorStyle = style) }
    }

    fun setColorSpec(spec: String) {
        repo.colorSpec = spec
        _uiState.update { it.copy(colorSpec = spec) }
    }

    fun setEnablePredictiveBack(enabled: Boolean) {
        repo.enablePredictiveBack = enabled
        _uiState.update { it.copy(enablePredictiveBack = enabled) }
    }

    fun setEnableSwipeDismiss(enabled: Boolean) {
        repo.enableSwipeDismiss = enabled
        _uiState.update { it.copy(enableSwipeDismiss = enabled) }
    }

    fun setPagerInterceptionMode(mode: Int) {
        repo.pagerInterceptionMode = mode
        _uiState.update { it.copy(pagerInterceptionMode = mode.coerceIn(0, 2)) }
    }

    fun setEnableBlur(enabled: Boolean) {
        repo.enableBlur = enabled
        _uiState.update { it.copy(enableBlur = enabled) }
    }

    fun setEnableFloatingBottomBar(enabled: Boolean) {
        repo.enableFloatingBottomBar = enabled
        _uiState.update { it.copy(enableFloatingBottomBar = enabled) }
    }

    fun setEnableFloatingBottomBarBlur(enabled: Boolean) {
        repo.enableFloatingBottomBarBlur = enabled
        _uiState.update { it.copy(enableFloatingBottomBarBlur = enabled) }
    }

    fun setEnableNavigationBadge(enabled: Boolean) {
        repo.enableNavigationBadge = enabled
        _uiState.update { it.copy(enableNavigationBadge = enabled) }
    }

    fun setPageScale(scale: Float) {
        repo.pageScale = scale
        _uiState.update { it.copy(pageScale = scale) }
    }

    fun setModuleDescriptionMaxLines(lines: Int) {
        repo.moduleDescriptionMaxLines = lines
        _uiState.update { it.copy(moduleDescriptionMaxLines = lines) }
    }

    fun setEnableWebDebugging(enabled: Boolean) {
        repo.enableWebDebugging = enabled
        _uiState.update { it.copy(enableWebDebugging = enabled) }
    }

    fun setShowFullStatus(enabled: Boolean) {
        repo.showFullStatus = enabled
        _uiState.update { it.copy(showFullStatus = enabled) }
    }

    fun setHideHomeWarnings(enabled: Boolean) {
        repo.hideHomeWarnings = enabled
        _uiState.update { it.copy(hideHomeWarnings = enabled) }
    }

    fun setSuCompatMode(mode: Int) {
        viewModelScope.launch(Dispatchers.IO) {
            when (mode) {
                0 -> if (repo.setSuEnabled(true)) {
                    repo.execKsudFeatureSave()
                    repo.setSuCompatModePref(0)
                    _uiState.update { it.copy(suCompatMode = 0, isSuEnabled = true) }
                }

                1 -> if (repo.setSuEnabled(true)) {
                    repo.execKsudFeatureSave()
                    if (repo.setSuEnabled(false)) {
                        // "Disable until reboot" implies it should be enabled on next boot.
                        // We set the preference to 0 (Enabled) to match the persistent state.
                        repo.setSuCompatModePref(0)
                        _uiState.update { it.copy(suCompatMode = 1, isSuEnabled = false) }
                    }
                }

                2 -> if (repo.setSuEnabled(false)) {
                    repo.execKsudFeatureSave()
                    repo.setSuCompatModePref(2)
                    _uiState.update { it.copy(suCompatMode = 2, isSuEnabled = false) }
                }
            }
        }
    }

    fun setKernelUmountEnabled(enabled: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            if (repo.setKernelUmountEnabled(enabled)) {
                repo.execKsudFeatureSave()
                _uiState.update { it.copy(isKernelUmountEnabled = enabled) }
            }
        }
    }

    fun setSelinuxHideEnabled(enabled: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            val status = repo.setSelinuxHideEnabled(enabled)
            repo.execKsudFeatureSave()
            _uiState.update { it.copy(isSelinuxHideEnabled = enabled) }
            when (status) {
                0 -> {}
                -OsConstants.EAGAIN -> {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(ksuApp, R.string.settings_selinux_hide_reboot_required,
                            Toast.LENGTH_LONG).show()
                    }
                }
                else -> {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(ksuApp, ksuApp.getString(R.string.settings_selinux_hide_failed, status),
                            Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    fun setMountHideEnabled(enabled: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            val status = repo.setMountHideEnabled(enabled)
            repo.execKsudFeatureSave()
            _uiState.update { it.copy(isMountHideEnabled = enabled) }
            when (status) {
                0 -> {}
                -OsConstants.EAGAIN -> {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(ksuApp, R.string.settings_mount_hide_reboot_required,
                            Toast.LENGTH_LONG).show()
                    }
                }
                else -> {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(ksuApp, ksuApp.getString(R.string.settings_mount_hide_failed, status),
                            Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    fun setAutoJailbreak(enabled: Boolean) {
        repo.autoJailbreak = enabled
        _uiState.update { it.copy(autoJailbreak = enabled) }
    }

    fun setUseSoftReboot(enabled: Boolean) {
        repo.useSoftReboot = enabled
        _uiState.update { it.copy(useSoftReboot = enabled) }
    }

    fun setSulogEnabled(enabled: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            if (repo.setSulogEnabled(enabled)) {
                repo.execKsudFeatureSave()
                _uiState.update { it.copy(isSulogEnabled = enabled) }
            }
        }
    }

    fun setShellSuAdbOnlyEnabled(enabled: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            if (repo.setShellSuAdbOnlyEnabled(enabled)) {
                repo.execKsudFeatureSave()
                _uiState.update { it.copy(isShellSuAdbOnlyEnabled = enabled) }
            }
        }
    }

    fun setAdbRootEnabled(enabled: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            if (repo.setAdbRootEnabled(enabled)) {
                repo.execKsudFeatureSave()
                _uiState.update { it.copy(isAdbRootEnabled = enabled) }
            }
        }
    }

    fun setDefaultUmountModules(enabled: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            if (repo.setDefaultUmountModules(enabled)) {
                _uiState.update { it.copy(isDefaultUmountModules = enabled) }
            }
        }
    }

    fun setAvcSpoofEnabled(enabled: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            if (repo.setAvcSpoofEnabled(enabled)) {
                repo.execKsudFeatureSave()
                _uiState.update { it.copy(isAvcSpoofEnabled = repo.isAvcSpoofEnabled()) }
            } else {
                withContext(Dispatchers.Main) {
                    Toast.makeText(ksuApp, R.string.settings_avc_spoof_failed, Toast.LENGTH_LONG).show()
                }
            }
        }
    }
}
