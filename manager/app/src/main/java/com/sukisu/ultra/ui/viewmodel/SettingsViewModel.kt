package com.sukisu.ultra.ui.viewmodel

import android.content.Context
import androidx.core.content.edit
import android.net.Uri
import android.system.OsConstants
import android.widget.Toast
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
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
import com.sukisu.ultra.ui.screen.colorpalette.ColorPaletteUiState
import com.sukisu.ultra.ui.screen.settings.SettingsUiState
import com.sukisu.ultra.ui.screen.settings.ThemePackageOptions
import com.sukisu.ultra.ui.theme.ColorMode
import com.sukisu.ultra.ui.theme.ThemeController
import com.sukisu.ultra.ui.util.CustomTextGroup
import com.sukisu.ultra.ui.util.CustomTextKey
import com.sukisu.ultra.ui.util.AdaptiveThemeDraft
import com.sukisu.ultra.ui.util.AdaptiveThemeState
import com.sukisu.ultra.ui.util.AdaptiveThemeStore
import com.sukisu.ultra.ui.util.AdaptiveThemeVariantState
import com.sukisu.ultra.ui.util.AppearanceOverlayData
import com.sukisu.ultra.ui.util.AppearanceOverlayStore
import com.sukisu.ultra.ui.util.ImageStorage
import com.sukisu.ultra.ui.util.ImportedThemeVariant
import com.sukisu.ultra.ui.util.ThemePackageAdaptiveExport
import com.sukisu.ultra.ui.util.ThemePackageVariantExport
import com.sukisu.ultra.ui.util.ThemeVariantData
import com.sukisu.ultra.ui.util.customTextsInGroups
import com.sukisu.ultra.ui.screen.module.ModuleNameSort
import com.sukisu.ultra.ui.util.BuiltinAppIcon
import com.sukisu.ultra.ui.util.BuiltinAppIcons
import com.sukisu.ultra.ui.util.BottomBarIconSlot
import com.sukisu.ultra.ui.util.HomeCardSticker
import com.sukisu.ultra.ui.util.HomeCardStickerTransform
import com.sukisu.ultra.ui.util.HomeCardImageStyle
import com.sukisu.ultra.ui.util.HomeLayout
import com.sukisu.ultra.ui.util.HomeStatusAlignment
import com.sukisu.ultra.ui.util.HomeStatusStyle
import com.sukisu.ultra.ui.util.ImportedTheme
import com.sukisu.ultra.ui.util.ThemePackageData
import com.sukisu.ultra.ui.util.ThemePackageStorage
import com.sukisu.ultra.ui.util.ThemeTrialManager
import com.sukisu.ultra.ui.util.findActivity
import java.io.File

private data class CurrentThemePayload(
    val data: ThemePackageData,
    val backgroundFile: File?,
    val cardBackgroundFile: File?,
    val stickerFiles: List<File>,
    val bottomBarIconFiles: Map<String, File> = emptyMap(),
    val adaptive: ThemePackageAdaptiveExport? = null,
)

class SettingsViewModel(
    private val repo: SettingsRepository = SettingsRepositoryImpl()
) : ViewModel() {

    /** Parsed once when the view model is created; the store caches by raw JSON afterwards. */
    private val initialAppearanceData = AppearanceOverlayStore.data(repo)

    private val _uiState = MutableStateFlow(SettingsUiState(
        checkUpdate = repo.checkUpdate,
        checkCiUpdate = repo.checkCiUpdate,
        checkModuleUpdate = repo.checkModuleUpdate,
        backgroundAppearanceExpanded = repo.backgroundAppearanceExpanded,
        backgroundSectionExpanded = repo.backgroundSectionExpanded,
        themePackageSectionExpanded = repo.themePackageSectionExpanded,
        appearanceSectionExpanded = repo.appearanceSectionExpanded,
        homeCardSectionExpanded = repo.homeCardSectionExpanded,
        colorsSectionExpanded = repo.colorsSectionExpanded,
        bottomBarSectionExpanded = repo.bottomBarSectionExpanded,
        interactionSectionExpanded = repo.interactionSectionExpanded,
        detailsSectionExpanded = repo.detailsSectionExpanded,
        customHomeTitle = repo.customHomeTitle,
        customTexts = repo.customTexts,
        themeStoreBaseUrl = repo.themeStoreBaseUrl,
        themeStoreToken = repo.themeStoreToken,
        themeStoreAuthorId = repo.themeStoreAuthorId,
        themeStoreAuthorName = repo.themeStoreAuthorName,
        themeStoreAdminUrl = repo.themeStoreAdminUrl,
        themeStoreExtraSources = repo.themeStoreExtraSources,
        homeCardImagePath = repo.homeCardImagePath,
        hideHomeCardStatusText = repo.hideHomeCardStatusText,
        hideHomeCardDecoration = repo.hideHomeCardDecoration,
        homeCardStickers = repo.homeCardStickers,
        adaptiveThemeActive = AdaptiveThemeStore.isActive(repo),
        adaptiveDraftLightCaptured = AdaptiveThemeStore.loadDraft(repo)?.light != null,
        adaptiveDraftDarkCaptured = AdaptiveThemeStore.loadDraft(repo)?.dark != null,
        adaptiveDraftComplete = AdaptiveThemeStore.loadDraft(repo)?.complete == true,
        customAppearanceJson = repo.customAppearanceJson,
        customColorsPresent = initialAppearanceData?.colors != null,
        imageEffectsPresent = initialAppearanceData?.image != null,
        appearance = AppearanceOverlayStore.load(repo),
        appearanceData = initialAppearanceData,
    ))
    val uiState: StateFlow<SettingsUiState> = _uiState.asStateFlow()

    /**
     * The appearance page's own state. It is derived from [uiState] only when a setting actually
     * changes, so enum/string parsing and the preview inputs never run per recomposition.
     */
    val colorPaletteState: StateFlow<ColorPaletteUiState> = _uiState
        .map { it.toColorPaletteUiState() }
        .distinctUntilChanged()
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5_000),
            initialValue = _uiState.value.toColorPaletteUiState(),
        )

    /**
     * Incremented whenever the background seed is about to be recomputed or replaced. A scoring
     * run only commits its result while its generation is still current, so a slower run started
     * by an earlier tap cannot overwrite a newer choice.
     */
    private var seedGeneration = 0

    
    private var wallpaperGeneration = 0

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
            val enableProgressiveBlur = repo.enableProgressiveBlur
            val enableFloatingBottomBar = repo.enableFloatingBottomBar
            val enableFloatingBottomBarBlur = repo.enableFloatingBottomBarBlur
            val enableNavigationBadge = repo.enableNavigationBadge
            val pageScale = repo.pageScale
            val bottomBarIcons = repo.bottomBarIcons
            val moduleDescriptionMaxLines = repo.moduleDescriptionMaxLines
            val enableWebDebugging = repo.enableWebDebugging
            val autoDeleteModuleZip = repo.autoDeleteModuleZip
            val autoDeleteUpdateApk = repo.autoDeleteUpdateApk
            val showFullStatus = repo.showFullStatus
            val hideHomeWarnings = repo.hideHomeWarnings
            val showAiHomeCard = repo.showAiHomeCard
            val colorStyle = repo.colorStyle
            val colorSpec = repo.colorSpec
            val customAppearanceJson = repo.customAppearanceJson
            val appearanceData = withContext(Dispatchers.IO) { AppearanceOverlayStore.data(repo) }
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
            val systemWallpaperPath = ImageStorage.systemWallpaperFile(ksuApp)
                .takeIf { it.isFile }?.absolutePath.orEmpty()

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
                    backgroundSectionExpanded = repo.backgroundSectionExpanded,
                    themePackageSectionExpanded = repo.themePackageSectionExpanded,
                    appearanceSectionExpanded = repo.appearanceSectionExpanded,
                    homeCardSectionExpanded = repo.homeCardSectionExpanded,
                    colorsSectionExpanded = repo.colorsSectionExpanded,
                    bottomBarSectionExpanded = repo.bottomBarSectionExpanded,
                    interactionSectionExpanded = repo.interactionSectionExpanded,
                    detailsSectionExpanded = repo.detailsSectionExpanded,
                    customHomeTitle = repo.customHomeTitle,
                    customTexts = repo.customTexts,
                    adaptiveThemeActive = AdaptiveThemeStore.isActive(repo),
                    adaptiveDraftLightCaptured = AdaptiveThemeStore.loadDraft(repo)?.light != null,
                    adaptiveDraftDarkCaptured = AdaptiveThemeStore.loadDraft(repo)?.dark != null,
                    adaptiveDraftComplete = AdaptiveThemeStore.loadDraft(repo)?.complete == true,
                    homeCardImagePath = repo.homeCardImagePath,
                    hideHomeCardStatusText = repo.hideHomeCardStatusText,
                    hideHomeCardDecoration = repo.hideHomeCardDecoration,
                    homeCardStickers = repo.homeCardStickers,
                    bottomBarIcons = bottomBarIcons,
                    homeLayout = HomeLayout.fromValue(repo.homeLayout),
homeStatusAlignment = HomeStatusAlignment.fromValue(repo.homeStatusAlignment),
                    homeStatusScale = HomeStatusStyle.coerceScale(repo.homeStatusScale),
homePillScale = HomeStatusStyle.coercePillScale(repo.homePillScale),
                    homeStatusWidthFraction = HomeStatusStyle.coerceWidth(repo.homeStatusWidthFraction),
                    homeCardImageStyle = HomeCardImageStyle.fromValue(repo.homeCardImageStyle),
                    showHomeCardImageWithoutBackground = repo.showHomeCardImageWithoutBackground,
                    customAppearanceJson = customAppearanceJson,
                    customColorsPresent = appearanceData?.colors != null,
                    imageEffectsPresent = appearanceData?.image != null,
                    appearance = AppearanceOverlayStore.load(repo),
                    appearanceData = appearanceData,
                    themeMode = themeMode,
                    miuixMonet = miuixMonet,
                    keyColor = keyColor,
                    enablePredictiveBack = enablePredictiveBack,
                    enableSwipeDismiss = enableSwipeDismiss,
                    pagerInterceptionMode = pagerInterceptionMode,
                    enableBlur = enableBlur,
                    enableProgressiveBlur = enableProgressiveBlur,
                    enableFloatingBottomBar = enableFloatingBottomBar,
                    enableFloatingBottomBarBlur = enableFloatingBottomBarBlur,
                    enableNavigationBadge = enableNavigationBadge,
                    pageScale = pageScale,
                    moduleDescriptionMaxLines = moduleDescriptionMaxLines,
                    enableWebDebugging = enableWebDebugging,
                    autoDeleteModuleZip = autoDeleteModuleZip,
                    autoDeleteUpdateApk = autoDeleteUpdateApk,
                    showFullStatus = showFullStatus,
                    hideHomeWarnings = hideHomeWarnings,
                    showAiHomeCard = showAiHomeCard,
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
                    useSystemWallpaper = repo.useSystemWallpaper && systemWallpaperPath.isNotEmpty(),
                    systemWallpaperPath = systemWallpaperPath,
                    extractColorFromBackground = repo.derivesKeyColorFromBackground(),
                    cardBackgroundAlphaPercent = repo.cardBackgroundAlphaPercent,
                    customBackgroundBlurPercent = repo.customBackgroundBlurPercent,
                    customBackgroundScrimPercent = repo.customBackgroundScrimPercent,
                )
            }
        }
    }

    fun stagePickedBackground(context: Context, uri: Uri, onReady: (String?) -> Unit) {
        viewModelScope.launch {
            val path = ImageStorage.stageUri(context, uri)
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

    fun stageCurrentBackground(context: Context, onReady: (String?) -> Unit) {
        viewModelScope.launch {
            val current = repo.customBackgroundUri
            val path = if (current.isNotEmpty()) {
                ImageStorage.stageFile(context, File(current))
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

    suspend fun finishBackgroundCrop(
        context: Context,
        output: File,
        sourcePath: String?,
    ): Boolean = withContext(Dispatchers.IO) {
        val savedPath = ImageStorage.replace(context, output) ?: return@withContext false
        deactivateAdaptiveTheme()
        runCatching { if (output.isFile) output.delete() }
        ImageStorage.discardStaged(sourcePath)
        val seed = if (repo.derivesKeyColorFromBackground()) {
            ImageStorage.extractSeedColor(File(savedPath), repo.keyColor)
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

    private suspend fun refreshSystemWallpaperCache() {
        val generation = wallpaperGeneration
        val derivesKeyColor = repo.derivesKeyColorFromBackground()
        val result = ImageStorage.captureSystemWallpaper(ksuApp, force = false)
        if (generation != wallpaperGeneration) return
        if (result.changed) {
            repo.customBackgroundUpdatedAt = System.currentTimeMillis()
            if (derivesKeyColor && result.path != null) {
                repo.keyColor = ImageStorage.extractSeedColor(File(result.path), repo.keyColor)
            }
        }
        if (result.path == null) {
            // The cache cannot be decoded or rebuilt; fall back to the picked image.
            repo.useSystemWallpaper = false
        }
    }

    private fun updateBackgroundAppearanceState() {
        val useSystemWallpaper = repo.useSystemWallpaper
        val systemWallpaperPath = ImageStorage.systemWallpaperFile(ksuApp)
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
                extractColorFromBackground = repo.derivesKeyColorFromBackground(),
            )
        }
    }

    fun setUseSystemWallpaper(context: Context, enabled: Boolean) {
        if (!enabled) {
            wallpaperGeneration++
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
        val generation = ++wallpaperGeneration
        _uiState.update { it.copy(isSystemWallpaperBusy = true) }
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    ImageStorage.captureSystemWallpaper(context, force = true)
                }
                if (generation != wallpaperGeneration) return@launch
                if (result.path == null) {
                    Toast.makeText(
                        ksuApp,
                        R.string.settings_system_wallpaper_failed,
                        Toast.LENGTH_SHORT,
                    ).show()
                    return@launch
                }

                val keyColor = if (repo.derivesKeyColorFromBackground()) {
                    withContext(Dispatchers.IO) {
                        ImageStorage.extractSeedColor(File(result.path), repo.keyColor)
                    }
                } else {
                    repo.keyColor
                }
                val updatedAt = System.currentTimeMillis()
                deactivateAdaptiveTheme()
                repo.useSystemWallpaper = true
                repo.customBackgroundUpdatedAt = updatedAt
                if (repo.derivesKeyColorFromBackground()) repo.keyColor = keyColor
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

    fun setExtractColorFromBackground(enabled: Boolean) {
        val generation = ++seedGeneration
        repo.extractColorFromBackground = enabled
        if (!enabled) {
            _uiState.update { it.copy(extractColorFromBackground = false) }
            return
        }
        // The palette keeps the current color until the background has been scored, so there is
        // no flash through the system default; the pending color is published to the activity.
        val previousKeyColor = repo.keyColor
        // Commit the flip first so the switch responds immediately; the seed lands when the
        // background has been scored (decoding it can take a while on large wallpapers).
        _uiState.update { it.copy(extractColorFromBackground = true) }

        val background = repo.activeBackgroundFile() ?: return

        viewModelScope.launch {
            publishPendingSeed(previousKeyColor)
            val seed = ImageStorage.extractSeedColor(background, previousKeyColor)
            // Skip the write if another tap or color pick started a newer run in the meantime.
            if (generation != seedGeneration) return@launch
            clearPendingSeed()
            repo.keyColor = seed
            _uiState.update { it.copy(keyColor = seed) }
        }
    }

    fun clearCustomBackground(context: Context) {
        deactivateAdaptiveTheme()
        viewModelScope.launch(Dispatchers.IO) {
            ImageStorage.clear(context)
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

    fun pickBottomBarIcon(context: Context, slot: BottomBarIconSlot, uri: Uri) {
        viewModelScope.launch {
            val path = ImageStorage.saveBottomBarIcon(context, slot, uri)
            if (path != null) {
                val updated = _uiState.value.bottomBarIcons + (slot.key to path)
                repo.bottomBarIcons = updated
                _uiState.update { it.copy(bottomBarIcons = updated) }
            } else {
                Toast.makeText(context, R.string.bottom_bar_icon_failed, Toast.LENGTH_SHORT).show()
            }
        }
    }

    fun clearBottomBarIcon(context: Context, slot: BottomBarIconSlot) {
        viewModelScope.launch {
            ImageStorage.clearBottomBarIcon(context, slot)
            val updated = _uiState.value.bottomBarIcons - slot.key
            repo.bottomBarIcons = updated
            _uiState.update { it.copy(bottomBarIcons = updated) }
        }
    }

    fun clearAllBottomBarIcons(context: Context) {
        viewModelScope.launch {
            ImageStorage.clearBottomBarIcons(context)
            repo.bottomBarIcons = emptyMap()
            _uiState.update { it.copy(bottomBarIcons = emptyMap()) }
        }
    }

    fun pickHomeCardImage(context: Context, uri: Uri) {
        viewModelScope.launch {
            val path = ImageStorage.saveHomeCardImage(context, uri)
            if (path != null) {
                deactivateAdaptiveTheme()
                repo.homeCardImagePath = path
                _uiState.update { it.copy(homeCardImagePath = path) }
            } else {
                Toast.makeText(context, R.string.home_card_image_failed, Toast.LENGTH_SHORT).show()
            }
        }
    }

    fun clearHomeCardImage() {
        deactivateAdaptiveTheme()
        viewModelScope.launch {
            ImageStorage.clearHomeCardImage(ksuApp)
            repo.homeCardImagePath = ""
            repo.hideHomeCardStatusText = false
            repo.hideHomeCardDecoration = false
            _uiState.update {
                it.copy(
                    homeCardImagePath = "",
                    hideHomeCardStatusText = false,
                    hideHomeCardDecoration = false,
                )
            }
        }
    }

    fun setHideHomeCardStatusText(hidden: Boolean) {
        repo.hideHomeCardStatusText = hidden
        _uiState.update { it.copy(hideHomeCardStatusText = hidden) }
    }

    fun setHideHomeCardDecoration(hidden: Boolean) {
        repo.hideHomeCardDecoration = hidden
        _uiState.update { it.copy(hideHomeCardDecoration = hidden) }
    }

    fun setHomeLayout(layout: HomeLayout) {
        repo.homeLayout = layout.value
        _uiState.update { it.copy(homeLayout = layout) }
    }

    fun setHomeStatusAlignment(alignment: HomeStatusAlignment) {
        repo.homeStatusAlignment = alignment.value
        _uiState.update { it.copy(homeStatusAlignment = alignment) }
    }

    fun setHomeStatusScale(scale: Float) {
        val coerced = HomeStatusStyle.coerceScale(scale)
        repo.homeStatusScale = coerced
        _uiState.update { it.copy(homeStatusScale = coerced) }
    }

    fun setHomePillScale(scale: Float) {
        val coerced = HomeStatusStyle.coercePillScale(scale)
        repo.homePillScale = coerced
        _uiState.update { it.copy(homePillScale = coerced) }
    }

    fun setHomeStatusWidthFraction(fraction: Float) {
        val coerced = HomeStatusStyle.coerceWidth(fraction)
        repo.homeStatusWidthFraction = coerced
        _uiState.update { it.copy(homeStatusWidthFraction = coerced) }
    }

    fun setHomeCardImageStyle(style: HomeCardImageStyle) {
        repo.homeCardImageStyle = style.value
        _uiState.update { it.copy(homeCardImageStyle = style) }
    }

    fun setShowHomeCardImageWithoutBackground(show: Boolean) {
        repo.showHomeCardImageWithoutBackground = show
        _uiState.update { it.copy(showHomeCardImageWithoutBackground = show) }
    }

    fun addHomeCardSticker(context: Context, uri: Uri) {
        viewModelScope.launch {
            if (_uiState.value.homeCardStickers.size >= HomeCardSticker.MAX_COUNT) {
                Toast.makeText(context, R.string.settings_home_card_sticker_limit, Toast.LENGTH_SHORT).show()
                return@launch
            }
            val path = ImageStorage.saveHomeCardSticker(context, uri)
            if (path == null) {
                Toast.makeText(context, R.string.home_card_image_failed, Toast.LENGTH_SHORT).show()
                return@launch
            }
            // Re-read after the save: another add/remove may have completed while it ran.
            val updated = _uiState.value.homeCardStickers + HomeCardSticker(path)
            if (updated.size > HomeCardSticker.MAX_COUNT) {
                ImageStorage.deleteHomeCardSticker(ksuApp, path)
                Toast.makeText(context, R.string.settings_home_card_sticker_limit, Toast.LENGTH_SHORT).show()
                return@launch
            }
            repo.homeCardStickers = updated
            _uiState.update { it.copy(homeCardStickers = updated) }
        }
    }

    fun removeHomeCardSticker(index: Int) {
        val sticker = _uiState.value.homeCardStickers.getOrNull(index) ?: return
        viewModelScope.launch {
            ImageStorage.deleteHomeCardSticker(ksuApp, sticker.path)
            // Re-read after the delete and remove by path so concurrent edits cannot resurrect it.
            val current = _uiState.value.homeCardStickers
            val updated = current.filterNot { it.path == sticker.path }
            if (updated.size == current.size) return@launch
            repo.homeCardStickers = updated
            _uiState.update { it.copy(homeCardStickers = updated) }
        }
    }

    fun updateHomeCardStickerTransform(index: Int, transform: HomeCardStickerTransform) {
        val current = _uiState.value.homeCardStickers
        if (index !in current.indices) return
        val updated = current.toMutableList().apply {
            this[index] = this[index].copy(transform = transform.coerced())
        }
        repo.homeCardStickers = updated
        _uiState.update { it.copy(homeCardStickers = updated) }
    }

    fun exportImages(context: Context, uri: Uri) {
        viewModelScope.launch(Dispatchers.IO) {
            val state = _uiState.value
            val backgroundFile = if (!state.useSystemWallpaper && state.customBackgroundUri.isNotEmpty()) {
                File(state.customBackgroundUri).takeIf { it.isFile }
            } else null
            val cardBackgroundFile = state.homeCardImagePath
                .takeIf { it.isNotEmpty() }
                ?.let { File(it).takeIf { f -> f.isFile } }
            val stickerFiles = state.homeCardStickers
                .map { File(it.path) }
                .filter { it.isFile }
            if (backgroundFile == null && cardBackgroundFile == null && stickerFiles.isEmpty()) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(ksuApp, R.string.theme_export_failed, Toast.LENGTH_SHORT).show()
                }
                return@launch
            }
            ImageStorage.exportImages(context, uri, backgroundFile, cardBackgroundFile, stickerFiles)
                .onSuccess {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(ksuApp, R.string.theme_export_success, Toast.LENGTH_SHORT).show()
                    }
                }
                .onFailure {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(ksuApp, R.string.theme_export_failed, Toast.LENGTH_SHORT).show()
                    }
                }
        }
    }

    fun exportCustomBackground(context: Context, uri: Uri) = exportImages(context, uri)

    /** Applies a validated static overlay. Parsing happens in the editor/package boundary. */
    fun applyCustomAppearance(data: AppearanceOverlayData) {
        viewModelScope.launch {
            withContext(Dispatchers.IO) { AppearanceOverlayStore.save(repo, data) }
            val saved = AppearanceOverlayStore.data(repo)
            _uiState.update {
                it.copy(
                    customAppearanceJson = repo.customAppearanceJson,
                    customColorsPresent = saved?.colors != null,
                    imageEffectsPresent = saved?.image != null,
                    appearance = AppearanceOverlayStore.load(repo),
                    appearanceData = saved,
                )
            }
        }
    }

    fun resetCustomAppearance() {
        viewModelScope.launch {
            withContext(Dispatchers.IO) { AppearanceOverlayStore.clear(repo) }
            _uiState.update {
                it.copy(
                    customAppearanceJson = "",
                    customColorsPresent = false,
                    imageEffectsPresent = false,
                    appearance = null,
                    appearanceData = null,
                )
            }
        }
    }

    /** Re-reads the overlay after it may have changed outside this screen (AI, packages, ...). */
    fun refreshCustomAppearance() {
        viewModelScope.launch {
            val saved = withContext(Dispatchers.IO) { AppearanceOverlayStore.data(repo) }
            _uiState.update {
                it.copy(
                    customAppearanceJson = repo.customAppearanceJson,
                    customColorsPresent = saved?.colors != null,
                    imageEffectsPresent = saved?.image != null,
                    appearance = AppearanceOverlayStore.load(repo),
                    appearanceData = saved,
                )
            }
        }
    }

    fun exportTheme(context: Context, uri: Uri, options: ThemePackageOptions) {
        viewModelScope.launch {
            val payload = currentThemePayload(options)
            ThemePackageStorage.export(
                context = context,
                uri = uri,
                data = payload.data,
                backgroundFile = payload.backgroundFile,
                cardBackgroundFile = payload.cardBackgroundFile,
                cardStickerFiles = payload.stickerFiles,
                bottomBarIconFiles = payload.bottomBarIconFiles,
                adaptive = payload.adaptive,
            )
                .onSuccess {
                    Toast.makeText(ksuApp, R.string.theme_export_success, Toast.LENGTH_SHORT).show()
                }
                .onFailure {
                    Toast.makeText(ksuApp, R.string.theme_export_failed, Toast.LENGTH_SHORT).show()
                }
        }
    }

    /** Options picked in the export dialog, reused when the upload form builds a preset package. */
    private var pendingThemeUploadOptions: ThemePackageOptions? = null

    fun prepareThemeUpload(options: ThemePackageOptions) {
        pendingThemeUploadOptions = options
    }

    fun clearPendingThemeUploadOptions() {
        pendingThemeUploadOptions = null
    }

    suspend fun createCurrentThemePackage(context: Context): Result<File> = withContext(Dispatchers.IO) {
        runCatching {
            val options = pendingThemeUploadOptions ?: ThemePackageOptions()
            val payload = currentThemePayload(options, preferDraft = false)
            val file = File(context.cacheDir, "theme_upload_preset.sukisu")
            ThemePackageStorage.exportToFile(
                file = file,
                data = payload.data,
                backgroundFile = payload.backgroundFile,
                cardBackgroundFile = payload.cardBackgroundFile,
                cardStickerFiles = payload.stickerFiles,
                bottomBarIconFiles = payload.bottomBarIconFiles,
                adaptive = payload.adaptive,
            ).getOrThrow()
            file
        }
    }

    private fun currentThemePayload(
        options: ThemePackageOptions,
        preferDraft: Boolean = true,
    ): CurrentThemePayload {
        val draft = if (preferDraft) {
            AdaptiveThemeStore.loadDraft(repo)?.takeIf { it.complete }
        } else {
            null
        }
        val activeAdaptive = AdaptiveThemeStore.load(repo)
        val adaptive = when {
            draft != null -> ThemePackageAdaptiveExport(
                light = buildVariantExport(requireNotNull(draft.light), options),
                dark = buildVariantExport(requireNotNull(draft.dark), options),
            )

            activeAdaptive != null -> buildAdaptiveExport(activeAdaptive, options)
            else -> null
        }
        val backgroundFile = if (options.backgroundImage) {
            if (repo.useSystemWallpaper) {
                ImageStorage.systemWallpaperFile(ksuApp).takeIf { it.isFile }
            } else {
                repo.customBackgroundUri
                    .takeIf { it.isNotEmpty() }
                    ?.let { path -> File(path).takeIf { it.isFile } }
            }
        } else null
        val cardBackgroundFile = if (options.homeCardImage) {
            repo.homeCardImagePath
                .takeIf { it.isNotEmpty() }
                ?.let { path -> File(path).takeIf { it.isFile } }
        } else null
        val stickerEntries = if (options.stickers) {
            repo.homeCardStickers.filter { File(it.path).isFile }
        } else {
            emptyList()
        }
        val cardStickerFiles = stickerEntries.map { File(it.path) }
        val bottomBarIconFiles = if (options.bottomBarIcons) {
            repo.bottomBarIcons.mapNotNull { (slot, path) ->
                if (BottomBarIconSlot.fromKey(slot) == null) return@mapNotNull null
                File(path).takeIf { it.isFile }?.let { slot to it }
            }.toMap()
        } else {
            emptyMap()
        }
        val builtinIconIds = setOf(
            BuiltinAppIcons.DEFAULT_ID,
            BuiltinAppIcons.KERNELSU_ID,
            BuiltinAppIcons.LOGO_ID,
            BuiltinAppIcons.ZAKO_ID,
        )
        val exportedIconId = if (repo.appIconId in builtinIconIds) {
            repo.appIconId
        } else {
            BuiltinAppIcons.DEFAULT_ID
        }
        val data = ThemePackageData(
            version = if (adaptive != null) {
                ThemePackageStorage.ADAPTIVE_VERSION
            } else {
                ThemePackageStorage.BASE_VERSION
            },
            themeMode = repo.themeMode.takeIf { options.colors },
            miuixMonet = repo.miuixMonet.takeIf { options.colors },
            keyColor = repo.keyColor.takeIf { options.colors },
            colorStyle = repo.colorStyle.takeIf { options.colors },
            colorSpec = repo.colorSpec.takeIf { options.colors },
            cardBackgroundAlphaPercent = repo.cardBackgroundAlphaPercent.takeIf { options.backgroundAppearance },
            customBackgroundBlurPercent = repo.customBackgroundBlurPercent.takeIf { options.backgroundAppearance },
            customBackgroundScrimPercent = repo.customBackgroundScrimPercent.takeIf { options.backgroundAppearance },
            hasBackground = if (options.backgroundImage) backgroundFile != null else null,
            hasCardBackground = if (options.homeCardImage) cardBackgroundFile != null else null,
            hideHomeCardStatusText = repo.hideHomeCardStatusText.takeIf { options.homeCardDisplay },
            hideHomeCardDecoration = repo.hideHomeCardDecoration.takeIf { options.homeCardDisplay },
            homeLayout = HomeLayout.fromValue(repo.homeLayout).value.takeIf { options.homeCardDisplay },
homeStatusAlignment = HomeStatusAlignment.fromValue(repo.homeStatusAlignment).value
                .takeIf { options.homeCardDisplay },
            homeStatusScale = HomeStatusStyle.coerceScale(repo.homeStatusScale)
                .takeIf { options.homeCardDisplay },
            homePillScale = HomeStatusStyle.coercePillScale(repo.homePillScale)
                .takeIf { options.homeCardDisplay },
            homeStatusWidthFraction = HomeStatusStyle.coerceWidth(repo.homeStatusWidthFraction)
                .takeIf { options.homeCardDisplay },
            homeCardImageStyle = HomeCardImageStyle.fromValue(repo.homeCardImageStyle).value
                .takeIf { options.homeCardDisplay },
            showHomeCardImageWithoutBackground = repo.showHomeCardImageWithoutBackground
                .takeIf { options.homeCardDisplay },
            homeCardStickerTransforms = if (options.stickers) {
                stickerEntries.map { it.transform }
            } else {
                null
            },
            uiMode = repo.uiMode.takeIf { options.interfaceMode },
            appIconId = exportedIconId.takeIf { options.appIcon },
            enableBlur = repo.enableBlur.takeIf { options.interfaceSwitches },
            enableProgressiveBlur = repo.enableProgressiveBlur.takeIf { options.interfaceSwitches },
            enableFloatingBottomBar = repo.enableFloatingBottomBar.takeIf { options.interfaceSwitches },
            enableFloatingBottomBarBlur = repo.enableFloatingBottomBarBlur.takeIf { options.interfaceSwitches },
            enableNavigationBadge = repo.enableNavigationBadge.takeIf { options.interfaceSwitches },
            enablePredictiveBack = repo.enablePredictiveBack.takeIf { options.interactionBehavior },
            enableSwipeDismiss = repo.enableSwipeDismiss.takeIf { options.interactionBehavior },
            pagerInterceptionMode = repo.pagerInterceptionMode.takeIf { options.interactionBehavior },
            pageScale = repo.pageScale.takeIf { options.interactionBehavior },
            moduleSortEnabledFirst = repo.moduleSortEnabledFirst.takeIf { options.moduleDisplay },
            moduleSortActionFirst = repo.moduleSortActionFirst.takeIf { options.moduleDisplay },
            moduleSortWebUiFirst = repo.moduleSortWebUiFirst.takeIf { options.moduleDisplay },
            moduleSortZygiskFirst = repo.moduleSortZygiskFirst.takeIf { options.moduleDisplay },
            moduleSortMetamoduleFirst = repo.moduleSortMetamoduleFirst.takeIf { options.moduleDisplay },
            moduleSortNameOrder = repo.moduleSortNameOrder.takeIf { options.moduleDisplay },
            moduleSortManual = repo.moduleSortManual.takeIf { options.moduleDisplay },
            moduleDescriptionMaxLines = repo.moduleDescriptionMaxLines.takeIf { options.moduleDisplay },
            customHomeTitle = if (options.customTexts && CustomTextGroup.HOME in options.customTextGroups) {
                repo.customHomeTitle.takeIf { it.isNotBlank() }
            } else {
                null
            },
            customTexts = if (options.customTexts) {
                customTextsInGroups(repo.customTexts, options.customTextGroups)
                    .takeIf { it.isNotEmpty() }
            } else {
                null
            },
            bottomBarIcons = bottomBarIconFiles.keys.toList().takeIf {
                options.bottomBarIcons
            },
            appearance = currentAppearanceForExport(options),
        )
        return CurrentThemePayload(
            data,
            backgroundFile,
            cardBackgroundFile,
            cardStickerFiles,
            bottomBarIconFiles,
            adaptive,
        )
    }

    private fun currentAppearanceForExport(options: ThemePackageOptions): AppearanceOverlayData? {
        val data = AppearanceOverlayStore.data(repo) ?: return null
        val colors = data.colors.takeIf { options.customColors }
        val image = data.image.takeIf { options.imageEffects }
        if (colors == null && image == null) return null
        return AppearanceOverlayData(colors = colors, image = image)
    }

    private fun buildAdaptiveExport(
        state: AdaptiveThemeState,
        options: ThemePackageOptions,
    ): ThemePackageAdaptiveExport = ThemePackageAdaptiveExport(
        light = buildVariantExport(state.light, options),
        dark = buildVariantExport(state.dark, options),
    )

    private fun buildVariantExport(
        variant: AdaptiveThemeVariantState,
        options: ThemePackageOptions,
    ): ThemePackageVariantExport {
        val source = variant.data
        val background = if (options.backgroundImage && source.hasBackground == true) {
            File(variant.backgroundPath).takeIf { it.isFile }
        } else {
            null
        }
        val card = if (options.homeCardImage && source.hasCardBackground == true) {
            File(variant.cardBackgroundPath).takeIf { it.isFile }
        } else {
            null
        }
        val stickers = if (options.stickers) {
            variant.stickers.map { File(it.path) }.filter { it.isFile }
        } else {
            emptyList()
        }
        val backgroundFlag = when {
            !options.backgroundImage -> null
            source.hasBackground == false -> false
            source.hasBackground == true && background != null -> true
            // A missing file must not produce a package that claims to contain it.
            else -> null
        }
        val cardFlag = when {
            !options.homeCardImage -> null
            source.hasCardBackground == false -> false
            source.hasCardBackground == true && card != null -> true
            else -> null
        }
        val stickerTransforms = when {
            !options.stickers -> null
            source.homeCardStickerTransforms == null -> null
            source.homeCardStickerTransforms.isEmpty() -> source.homeCardStickerTransforms
            stickers.isEmpty() -> null
            else -> source.homeCardStickerTransforms
        }
        val data = source.copy(
            themeMode = if (options.colors) source.themeMode else null,
            miuixMonet = if (options.colors) source.miuixMonet else null,
            keyColor = if (options.colors) source.keyColor else null,
            colorStyle = if (options.colors) source.colorStyle else null,
            colorSpec = if (options.colors) source.colorSpec else null,
            cardBackgroundAlphaPercent = if (options.backgroundAppearance) {
                source.cardBackgroundAlphaPercent
            } else {
                null
            },
            customBackgroundBlurPercent = if (options.backgroundAppearance) {
                source.customBackgroundBlurPercent
            } else {
                null
            },
            customBackgroundScrimPercent = if (options.backgroundAppearance) {
                source.customBackgroundScrimPercent
            } else {
                null
            },
            hasBackground = backgroundFlag,
            hasCardBackground = cardFlag,
            hideHomeCardStatusText = if (options.homeCardDisplay) {
                source.hideHomeCardStatusText
            } else {
                null
            },
            hideHomeCardDecoration = if (options.homeCardDisplay) {
                source.hideHomeCardDecoration
            } else {
                null
            },
            homeLayout = if (options.homeCardDisplay) source.homeLayout else null,
homeStatusAlignment = if (options.homeCardDisplay) source.homeStatusAlignment else null,
            homeStatusScale = if (options.homeCardDisplay) source.homeStatusScale else null,
homePillScale = if (options.homeCardDisplay) source.homePillScale else null,
            homeStatusWidthFraction = if (options.homeCardDisplay) {
                source.homeStatusWidthFraction
            } else {
                null
            },
            homeCardImageStyle = if (options.homeCardDisplay) source.homeCardImageStyle else null,
            showHomeCardImageWithoutBackground = if (options.homeCardDisplay) {
                source.showHomeCardImageWithoutBackground
            } else {
                null
            },
            homeCardStickerTransforms = stickerTransforms,
            uiMode = if (options.interfaceMode) repo.uiMode else null,
            // The chrome and behavior switches are global settings, not per light/dark appearance,
            // so both halves always carry the live values instead of what the state captured.
            enableBlur = if (options.interfaceSwitches) repo.enableBlur else null,
            enableProgressiveBlur = if (options.interfaceSwitches) {
                repo.enableProgressiveBlur
            } else {
                null
            },
            enableFloatingBottomBar = if (options.interfaceSwitches) {
                repo.enableFloatingBottomBar
            } else {
                null
            },
            enableFloatingBottomBarBlur = if (options.interfaceSwitches) {
                repo.enableFloatingBottomBarBlur
            } else {
                null
            },
            enableNavigationBadge = if (options.interfaceSwitches) {
                repo.enableNavigationBadge
            } else {
                null
            },
            enablePredictiveBack = if (options.interactionBehavior) {
                repo.enablePredictiveBack
            } else {
                null
            },
            enableSwipeDismiss = if (options.interactionBehavior) {
                repo.enableSwipeDismiss
            } else {
                null
            },
            pagerInterceptionMode = if (options.interactionBehavior) repo.pagerInterceptionMode else null,
            pageScale = if (options.interactionBehavior) repo.pageScale else null,
            moduleDescriptionMaxLines = if (options.moduleDisplay) repo.moduleDescriptionMaxLines else null,
        )
        return ThemePackageVariantExport(
            data = data,
            backgroundFile = background,
            cardBackgroundFile = card,
            cardStickerFiles = stickers,
        )
    }

    fun importTheme(context: Context, uri: Uri) {
        viewModelScope.launch {
            ThemePackageStorage.import(context, uri)
                .onSuccess { imported ->
                    _uiState.update {
                        it.copy(
                            pendingImportTheme = imported,
                            showThemeImportDialog = true,
                        )
                    }
                }
                .onFailure {
                    Toast.makeText(ksuApp, R.string.theme_import_failed, Toast.LENGTH_SHORT).show()
                }
        }
    }

    
    fun importThemeFile(context: Context, file: File) {
        viewModelScope.launch {
            ThemePackageStorage.import(context, Uri.fromFile(file))
                .onSuccess { imported ->
                    _uiState.update {
                        it.copy(
                            pendingImportTheme = imported,
                            showThemeImportDialog = true,
                        )
                    }
                }
                .onFailure {
                    Toast.makeText(ksuApp, R.string.theme_import_failed, Toast.LENGTH_SHORT).show()
                }
            runCatching { file.delete() }
        }
    }

    fun dismissImportThemeDialog() {
        val pending = _uiState.value.pendingImportTheme
        pending?.temporaryFiles()?.forEach { path ->
            runCatching { File(path).delete() }
        }
        _uiState.update {
            it.copy(
                pendingImportTheme = null,
                showThemeImportDialog = false,
            )
        }
    }

    fun confirmImportTheme(context: Context, options: ThemePackageOptions) {
        val pending = _uiState.value.pendingImportTheme ?: return
        viewModelScope.launch {
            val rollbackPackage = runCatching {
                withContext(Dispatchers.IO) { createCurrentThemePackage(context).getOrThrow() }
            }.getOrNull()
            // Applying copies every extracted image and rewrites the appearance settings.
            // Keeping it off the main thread avoids an ANR while a large package is promoted.
            val applied = runCatching {
                withContext(Dispatchers.IO) { applyImportedTheme(context, pending, options, clearFirst = true) }
            }
            if (applied.isFailure) {
                AdaptiveThemeStore.clear(repo)
                if (pending.isAdaptive) {
                    withContext(Dispatchers.IO) {
                        runCatching { ImageStorage.clearAdaptiveImages(context) }
                    }
                }
                pending.temporaryFiles().forEach { path ->
                    runCatching { File(path).delete() }
                }
                _uiState.update {
                    it.copy(
                        pendingImportTheme = null,
                        showThemeImportDialog = false,
                        adaptiveThemeActive = false,
                    )
                }
                val rolledBack = rollbackPackage != null && runCatching {
                    withContext(NonCancellable + Dispatchers.IO) {
                        val restored = ThemePackageStorage.import(context, Uri.fromFile(rollbackPackage))
                            .getOrNull() ?: return@withContext false
                        applyImportedTheme(context, restored, ThemePackageOptions())
                    }
                }.isSuccess
                rollbackPackage?.let { file -> runCatching { file.delete() } }
                Toast.makeText(
                    ksuApp,
                    if (rolledBack) R.string.theme_import_failed_restored else R.string.theme_import_failed,
                    Toast.LENGTH_LONG,
                ).show()
                return@launch
            }
            rollbackPackage?.let { file -> runCatching { file.delete() } }
            // A normal import is a permanent choice; it supersedes any running trial.
            ThemeTrialManager.clear(context)
            _uiState.update {
                it.copy(
                    pendingImportTheme = null,
                    showThemeImportDialog = false,
                )
            }
            Toast.makeText(ksuApp, R.string.theme_import_success, Toast.LENGTH_SHORT).show()
        }
    }

    fun startThemeTrial(context: Context, packageFile: File) {
        val appContext = context.applicationContext
        val taskId = context.findActivity()?.taskId
        viewModelScope.launch {
            val result = beginThemeTrial(appContext, packageFile, taskId)
            Toast.makeText(
                ksuApp,
                if (result.isSuccess) R.string.theme_store_trial_started
                else R.string.theme_store_trial_failed,
                Toast.LENGTH_LONG,
            ).show()
        }
    }

    private suspend fun beginThemeTrial(
        context: Context,
        packageFile: File,
        taskId: Int?,
    ): Result<Unit> =
        withContext(NonCancellable + Dispatchers.IO) {
            runCatching {
                if (ThemeTrialManager.activeBackup(context) == null) {
                    val backup = createCurrentThemePackage(context).getOrThrow()
                    val target = ThemeTrialManager.backupFile(context)
                    target.parentFile?.mkdirs()
                    backup.copyTo(target, overwrite = true)
                    backup.delete()
                    ThemeTrialManager.markActive(context, target, taskId)
                }
                try {
                    val imported = ThemePackageStorage.import(context, Uri.fromFile(packageFile)).getOrThrow()
                    // Do not switch launcher aliases for a temporary trial; it also avoids
                    // disabling the alias that is currently hosting the task on restore.
                    applyImportedTheme(
                        context,
                        imported,
                        ThemePackageOptions(appIcon = false),
                        clearFirst = true,
                    )
                } catch (error: Exception) {
                    restoreTrialBackup(context)
                    throw error
                }
            }.also {
                runCatching { packageFile.delete() }
            }
        }

    fun restoreThemeTrial(context: Context, taskId: Int? = null) {
        if (!ThemeTrialManager.shouldRestore(context, taskId)) return
        val appContext = context.applicationContext
        viewModelScope.launch {
            withContext(NonCancellable + Dispatchers.IO) {
                restoreTrialBackup(appContext)
            }
        }
    }

    private suspend fun restoreTrialBackup(context: Context): Boolean {
        val backup = ThemeTrialManager.activeBackup(context) ?: return false
        val imported = ThemePackageStorage.import(context, Uri.fromFile(backup)).getOrNull()
            ?: return false
        return runCatching {
            applyImportedTheme(context, imported, ThemePackageOptions())
        }.onSuccess {
            ThemeTrialManager.clear(context)
        }.isSuccess
    }

    private suspend fun resetAppearanceForImport(
        context: Context,
        state: SettingsUiState,
        options: ThemePackageOptions,
        imported: ImportedTheme,
    ): SettingsUiState {
        var updated = state
        if (options.colors) {
            seedGeneration++
            clearPendingSeed()
            deactivateAdaptiveTheme()
            repo.themeMode = 0
            repo.miuixMonet = false
            repo.keyColor = 0
            repo.extractColorFromBackground = false
            repo.colorStyle = PaletteStyle.TonalSpot.name
            repo.colorSpec = ColorSpec.SpecVersion.SPEC_2025.name
            updated = updated.copy(
                themeMode = 0,
                miuixMonet = false,
                keyColor = 0,
                extractColorFromBackground = false,
                colorStyle = PaletteStyle.TonalSpot.name,
                colorSpec = ColorSpec.SpecVersion.SPEC_2025.name,
                adaptiveThemeActive = false,
            )
        }
        // Packages that carry no background data hide the dialog option, so the previous
        // wallpaper is cleared along with the rest of the old preset; a package with a
        // background only keeps the current one when the user unticked the option.
        val backgroundImageOptionAvailable =
            imported.backgroundPath != null ||
                imported.light?.backgroundPath != null ||
                imported.dark?.backgroundPath != null ||
                (!imported.isAdaptive && imported.data.hasBackground == false)
        if (options.backgroundImage || !backgroundImageOptionAvailable) {
            wallpaperGeneration++
            ImageStorage.clear(context)
            runCatching { ImageStorage.systemWallpaperFile(context).delete() }
            repo.customBackgroundUri = ""
            repo.customBackgroundUpdatedAt = 0L
            repo.useSystemWallpaper = false
            updated = updated.copy(
                customBackgroundUri = "",
                customBackgroundUpdatedAt = 0L,
                useSystemWallpaper = false,
                systemWallpaperPath = "",
                isSystemWallpaperBusy = false,
            )
        }
        if (options.backgroundAppearance) {
            val defaultBlur = ImageStorage.defaultBackgroundBlurPercent(context)
            repo.cardBackgroundAlphaPercent = ImageStorage.DEFAULT_CARD_ALPHA
            repo.customBackgroundBlurPercent = defaultBlur
            repo.customBackgroundScrimPercent = ImageStorage.DEFAULT_BACKGROUND_SCRIM
            updated = updated.copy(
                cardBackgroundAlphaPercent = ImageStorage.DEFAULT_CARD_ALPHA,
                customBackgroundBlurPercent = defaultBlur,
                customBackgroundScrimPercent = ImageStorage.DEFAULT_BACKGROUND_SCRIM,
            )
        }
        // Packages without card image data leave the import dialog without the option, so the
        // previous image is cleared instead of being carried over the new theme. Keeping it is
        // only possible when the package declares the group and the user unticked it.
        val homeCardImageOptionAvailable =
            imported.cardBackgroundPath != null ||
                imported.light?.cardBackgroundPath != null ||
                imported.dark?.cardBackgroundPath != null ||
                (!imported.isAdaptive && imported.data.hasCardBackground == false)
        if (options.homeCardImage || !homeCardImageOptionAvailable) {
            ImageStorage.clearHomeCardImage(context)
            repo.homeCardImagePath = ""
            updated = updated.copy(homeCardImagePath = "")
        }
        // Same rule as the card image: a package without sticker data clears the previous
        // stickers; the package stickers are imported afterwards when it has them.
        val stickersOptionAvailable =
            imported.stickerPaths.isNotEmpty() ||
                imported.light?.stickerPaths?.isNotEmpty() == true ||
                imported.dark?.stickerPaths?.isNotEmpty() == true ||
                (!imported.isAdaptive && imported.data.homeCardStickerTransforms != null)
        if (options.stickers || !stickersOptionAvailable) {
            ImageStorage.clearHomeCardSticker(context)
            repo.homeCardStickers = emptyList()
            updated = updated.copy(homeCardStickers = emptyList())
        }
        if (options.homeCardDisplay) {
            repo.hideHomeCardStatusText = false
            repo.hideHomeCardDecoration = false
            repo.homeLayout = HomeLayout.CLASSIC.value
            repo.homeStatusAlignment = HomeStatusAlignment.START.value
            repo.homeStatusScale = HomeStatusStyle.SCALE_DEFAULT
            repo.homePillScale = HomeStatusStyle.PILL_SCALE_DEFAULT
            repo.homeStatusWidthFraction = HomeStatusStyle.WIDTH_DEFAULT
            repo.homeCardImageStyle = HomeCardImageStyle.BANNER.value
            repo.showHomeCardImageWithoutBackground = false
            updated = updated.copy(
                hideHomeCardStatusText = false,
                hideHomeCardDecoration = false,
                homeLayout = HomeLayout.CLASSIC,
                homeStatusAlignment = HomeStatusAlignment.START,
                homeStatusScale = HomeStatusStyle.SCALE_DEFAULT,
                homePillScale = HomeStatusStyle.PILL_SCALE_DEFAULT,
                homeStatusWidthFraction = HomeStatusStyle.WIDTH_DEFAULT,
                homeCardImageStyle = HomeCardImageStyle.BANNER,
                showHomeCardImageWithoutBackground = false,
            )
        }
        if (options.appIcon && updated.appIconId != BuiltinAppIcons.DEFAULT_ID) {
            repo.appIconId = BuiltinAppIcons.DEFAULT_ID
            BuiltinAppIcons.apply(
                context = context,
                icon = BuiltinAppIcons.find(BuiltinAppIcons.DEFAULT_ID),
                dynamicColor = repo.appIconDynamicColor,
            )
            updated = updated.copy(appIconId = BuiltinAppIcons.DEFAULT_ID)
        }
        if (options.interfaceSwitches) {
            // The import replaces the interface-switch group as a whole: switches the package
            // does not carry fall back to the app defaults instead of surviving from the old
            // preset, and the apply step below restores the package values that are present.
            repo.enableBlur = false
            repo.enableProgressiveBlur = false
            repo.enableFloatingBottomBar = false
            repo.enableFloatingBottomBarBlur = false
            repo.enableNavigationBadge = true
            updated = updated.copy(
                enableBlur = false,
                enableProgressiveBlur = false,
                enableFloatingBottomBar = false,
                enableFloatingBottomBarBlur = false,
                enableNavigationBadge = true,
            )
        }
        // The icon group has no always-on switch in the import dialog, so treat a package that
        // carries no icon data as "no icons": clear the previous custom icons either way, and
        // let the apply step import the package icons when it has them.
        val packageHasBottomBarIcons =
            imported.data.bottomBarIcons != null || imported.bottomBarIconPaths.isNotEmpty()
        if (options.bottomBarIcons || !packageHasBottomBarIcons) {
            ImageStorage.clearBottomBarIcons(context)
            repo.bottomBarIcons = emptyMap()
            updated = updated.copy(bottomBarIcons = emptyMap())
        }
        if (updated != state) {
            // Push only the fields the final apply update below does not republish.
            _uiState.update {
                it.copy(
                    extractColorFromBackground = updated.extractColorFromBackground,
                    isSystemWallpaperBusy = updated.isSystemWallpaperBusy,
                )
            }
        }
        return updated
    }

    private suspend fun applyImportedTheme(
        context: Context,
        imported: ImportedTheme,
        options: ThemePackageOptions,
        clearFirst: Boolean = false,
    ) {
        val current = if (clearFirst) {
            resetAppearanceForImport(context, _uiState.value, options, imported)
        } else {
            _uiState.value
        }
        val adaptiveState = if (imported.isAdaptive) {
            withContext(Dispatchers.IO) { buildAdaptiveState(context, imported, options) }
        } else {
            null
        }
        if (adaptiveState != null) {
            AdaptiveThemeStore.save(repo, adaptiveState)
        } else {
            AdaptiveThemeStore.clear(repo)
        }
        // Adaptive packages keep their appearance on the two variants; the legacy sections below
        // are masked so they cannot overwrite what AdaptiveThemeStore applies.
        val data = if (imported.isAdaptive) {
            imported.data.copy(
                themeMode = null,
                miuixMonet = null,
                keyColor = null,
                colorStyle = null,
                colorSpec = null,
                cardBackgroundAlphaPercent = null,
                customBackgroundBlurPercent = null,
                customBackgroundScrimPercent = null,
                hasBackground = null,
                hasCardBackground = null,
                hideHomeCardStatusText = null,
                hideHomeCardDecoration = null,
                homeCardStickerTransforms = null,
                homeLayout = null,
                homeStatusAlignment = null,
                homeStatusScale = null,
                homePillScale = null,
                homeStatusWidthFraction = null,
                homeCardImageStyle = null,
                showHomeCardImageWithoutBackground = null,
                uiMode = null,
                enableFloatingBottomBar = null,
                enableFloatingBottomBarBlur = null,
                enableNavigationBadge = null,
                enablePredictiveBack = null,
                enableSwipeDismiss = null,
                enableBlur = null,
                enableProgressiveBlur = null,
                pagerInterceptionMode = null,
                pageScale = null,
                moduleDescriptionMaxLines = null,
                moduleSortEnabledFirst = null,
                moduleSortActionFirst = null,
                moduleSortWebUiFirst = null,
                moduleSortZygiskFirst = null,
                moduleSortMetamoduleFirst = null,
                moduleSortNameOrder = null,
                moduleSortManual = null,
            )
        } else {
            imported.data
        }

        var themeMode = current.themeMode
        var miuixMonet = current.miuixMonet
        var keyColor = current.keyColor
        var colorStyle = current.colorStyle
        var colorSpec = current.colorSpec
        var cardAlpha = current.cardBackgroundAlphaPercent
        var blurPercent = current.customBackgroundBlurPercent
        var scrimPercent = current.customBackgroundScrimPercent
        var targetUiMode = current.uiMode
        var hideHomeCardDecoration = current.hideHomeCardDecoration
        var hideHomeCardStatusText = current.hideHomeCardStatusText
        var homeCardStickers = current.homeCardStickers
        var bottomBarIcons = current.bottomBarIcons
        var enableBlur = current.enableBlur
        var enableProgressiveBlur = current.enableProgressiveBlur
        var pagerMode = current.pagerInterceptionMode
        var pageScale = current.pageScale
        var moduleMaxLines = current.moduleDescriptionMaxLines

        if (options.colors) {
            themeMode = data.themeMode?.takeIf { it in 0..6 } ?: current.themeMode
            miuixMonet = data.miuixMonet ?: current.miuixMonet
            keyColor = data.keyColor ?: current.keyColor
            colorStyle = data.colorStyle
                ?.takeIf { name -> runCatching { PaletteStyle.valueOf(name) }.isSuccess }
                ?: current.colorStyle
            colorSpec = data.colorSpec
                ?.takeIf { name -> runCatching { ColorSpec.SpecVersion.valueOf(name) }.isSuccess }
                ?: current.colorSpec

            repo.themeMode = themeMode
            repo.miuixMonet = miuixMonet
            repo.keyColor = keyColor
            repo.colorStyle = colorStyle
            repo.colorSpec = colorSpec
        }

        if (options.backgroundAppearance) {
            cardAlpha = (data.cardBackgroundAlphaPercent ?: current.cardBackgroundAlphaPercent)
                .coerceIn(ImageStorage.CARD_ALPHA_MIN, ImageStorage.CARD_ALPHA_MAX)
            blurPercent = (data.customBackgroundBlurPercent ?: current.customBackgroundBlurPercent)
                .coerceIn(ImageStorage.BACKGROUND_BLUR_PERCENT_MIN, ImageStorage.BACKGROUND_BLUR_PERCENT_MAX)
            scrimPercent = (data.customBackgroundScrimPercent ?: current.customBackgroundScrimPercent)
                .coerceIn(ImageStorage.BACKGROUND_SCRIM_MIN, ImageStorage.BACKGROUND_SCRIM_MAX)

            repo.cardBackgroundAlphaPercent = cardAlpha
            repo.customBackgroundBlurPercent = blurPercent
            repo.customBackgroundScrimPercent = scrimPercent
        }

        if (options.homeCardDisplay) {
            data.hideHomeCardDecoration?.let {
                repo.hideHomeCardDecoration = it
                hideHomeCardDecoration = it
            }
            data.hideHomeCardStatusText?.let {
                repo.hideHomeCardStatusText = it
                hideHomeCardStatusText = it
            }
            data.homeLayout?.let { repo.homeLayout = HomeLayout.fromValue(it).value }
            data.homeStatusAlignment?.let {
                repo.homeStatusAlignment = HomeStatusAlignment.fromValue(it).value
            }
            data.homeStatusScale?.let {
                repo.homeStatusScale = HomeStatusStyle.coerceScale(it)
            }
            data.homePillScale?.let {
                repo.homePillScale = HomeStatusStyle.coercePillScale(it)
            }
            data.homeStatusWidthFraction?.let {
                repo.homeStatusWidthFraction = HomeStatusStyle.coerceWidth(it)
            }
            data.homeCardImageStyle?.let {
                repo.homeCardImageStyle = HomeCardImageStyle.fromValue(it).value
            }
            data.showHomeCardImageWithoutBackground?.let {
                repo.showHomeCardImageWithoutBackground = it
            }
        }

        var floatingBottomBar = current.enableFloatingBottomBar
        var floatingBottomBarBlur = current.enableFloatingBottomBarBlur
        var navigationBadge = current.enableNavigationBadge
        var predictiveBack = repo.enablePredictiveBack
        var swipeDismiss = repo.enableSwipeDismiss

        if (options.interfaceMode) {
            targetUiMode = data.uiMode?.takeIf { it == "miuix" || it == "material" } ?: current.uiMode
            repo.uiMode = targetUiMode
        }

        if (options.interfaceSwitches) {
            data.enableBlur?.let {
                repo.enableBlur = it
                enableBlur = it
            }
            data.enableProgressiveBlur?.let {
                repo.enableProgressiveBlur = it
                enableProgressiveBlur = it
            }
            floatingBottomBar = data.enableFloatingBottomBar ?: current.enableFloatingBottomBar
            floatingBottomBarBlur = data.enableFloatingBottomBarBlur ?: current.enableFloatingBottomBarBlur
            navigationBadge = data.enableNavigationBadge ?: current.enableNavigationBadge
            repo.enableFloatingBottomBar = floatingBottomBar
            repo.enableFloatingBottomBarBlur = floatingBottomBarBlur
            repo.enableNavigationBadge = navigationBadge
        }

        if (options.interactionBehavior) {
            predictiveBack = data.enablePredictiveBack ?: repo.enablePredictiveBack
            swipeDismiss = data.enableSwipeDismiss ?: repo.enableSwipeDismiss
            repo.enablePredictiveBack = predictiveBack
            repo.enableSwipeDismiss = swipeDismiss

            data.pagerInterceptionMode?.let { mode ->
                val coerced = mode.coerceIn(0, 2)
                repo.pagerInterceptionMode = coerced
                pagerMode = coerced
            }
            data.pageScale?.let { scale ->
                val coerced = scale.coerceIn(0.8f, 1.1f)
                repo.pageScale = coerced
                pageScale = coerced
            }
        }

        if (options.moduleDisplay) {
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
            data.moduleDescriptionMaxLines?.let { lines ->
                val coerced = lines.coerceIn(1, 5)
                repo.moduleDescriptionMaxLines = coerced
                moduleMaxLines = coerced
            }
        }

        var backgroundUri = current.customBackgroundUri
        var homeCardImagePath = current.homeCardImagePath
        if (options.backgroundImage) {
            if (imported.backgroundPath != null) {
                backgroundUri = ImageStorage.replace(context, File(imported.backgroundPath)) ?: ""
                repo.customBackgroundUri = backgroundUri
                repo.useSystemWallpaper = false
                repo.customBackgroundUpdatedAt = System.currentTimeMillis()
            } else if (data.hasBackground == false) {
                // The package explicitly has no background, so restore the absence too.
                ImageStorage.clear(context)
                backgroundUri = ""
                repo.customBackgroundUri = ""
                repo.useSystemWallpaper = false
                repo.customBackgroundUpdatedAt = System.currentTimeMillis()
            }
        } else if (imported.backgroundPath != null) {
            runCatching { File(imported.backgroundPath).delete() }
        }

        if (options.homeCardImage) {
            if (imported.cardBackgroundPath != null) {
                val cardPath = ImageStorage.replaceHomeCardImage(context, File(imported.cardBackgroundPath)) ?: ""
                repo.homeCardImagePath = cardPath
                homeCardImagePath = cardPath
            } else if (data.hasCardBackground == false) {
                ImageStorage.clearHomeCardImage(context)
                repo.homeCardImagePath = ""
                homeCardImagePath = ""
            }
        } else if (imported.cardBackgroundPath != null) {
            runCatching { File(imported.cardBackgroundPath).delete() }
        }

        if (options.stickers) {
            if (imported.stickerPaths.isNotEmpty()) {
                val transforms = data.homeCardStickerTransforms.orEmpty()
                val importedStickers = imported.stickerPaths.mapIndexedNotNull { index, path ->
                    val saved = ImageStorage.importHomeCardSticker(context, File(path))
                        ?: return@mapIndexedNotNull null
                    HomeCardSticker(
                        path = saved,
                        transform = transforms.getOrNull(index)?.coerced() ?: HomeCardStickerTransform(),
                    )
                }.take(HomeCardSticker.MAX_COUNT)
                if (importedStickers.isNotEmpty()) {
                    current.homeCardStickers.forEach { ImageStorage.deleteHomeCardSticker(ksuApp, it.path) }
                    repo.homeCardStickers = importedStickers
                    homeCardStickers = importedStickers
                }
            } else if (data.homeCardStickerTransforms != null) {
                // A v2 package with an empty list explicitly clears the existing stickers.
                current.homeCardStickers.forEach { ImageStorage.deleteHomeCardSticker(ksuApp, it.path) }
                repo.homeCardStickers = emptyList()
                homeCardStickers = emptyList()
            }
        } else {
            imported.stickerPaths.forEach { runCatching { File(it).delete() } }
        }

        if (options.bottomBarIcons) {
            // The field doubles as the "this package owns the icons" marker: an empty list
            // explicitly clears the current icons, a missing field leaves them untouched.
            if (data.bottomBarIcons != null) {
                ImageStorage.clearBottomBarIcons(context)
                bottomBarIcons = imported.bottomBarIconPaths.mapNotNull { (slotKey, path) ->
                    val slot = BottomBarIconSlot.fromKey(slotKey) ?: return@mapNotNull null
                    ImageStorage.importBottomBarIcon(context, slot, File(path))
                        ?.let { slotKey to it }
                }.toMap()
                repo.bottomBarIcons = bottomBarIcons
            }
        } else {
            imported.bottomBarIconPaths.values.forEach { runCatching { File(it).delete() } }
        }

        var effectiveIconId = current.appIconId
        if (options.appIcon) {
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
                effectiveIconId = targetIconId
            }
        }

        var effectiveHomeTitle = current.customHomeTitle
        var effectiveCustomTexts = current.customTexts
        if (options.customTexts) {
            val selectedGroups = options.customTextGroups
            // Only the selected categories are replaced; the others keep their current text.
            val textsMap = current.customTexts.toMutableMap()
            textsMap.keys.toList().forEach { key ->
                val group = CustomTextKey.fromKey(key)?.group
                if (group != null && group in selectedGroups) textsMap.remove(key)
            }
            (data.customTexts ?: emptyMap()).forEach { (key, value) ->
                val group = CustomTextKey.fromKey(key)?.group
                if (group != null && group in selectedGroups && value.isNotBlank()) {
                    textsMap[key] = value
                }
            }
            if (CustomTextGroup.HOME in selectedGroups) {
                val homeTitle = data.customHomeTitle
                    ?: textsMap[CustomTextKey.HOME_TITLE.key]
                if (!homeTitle.isNullOrBlank()) {
                    textsMap[CustomTextKey.HOME_TITLE.key] = homeTitle
                    repo.customHomeTitle = homeTitle
                    effectiveHomeTitle = homeTitle
                } else {
                    repo.customHomeTitle = ""
                    effectiveHomeTitle = ""
                }
            }
            repo.customTexts = textsMap
            effectiveCustomTexts = textsMap
        }

        if (options.customColors || options.imageEffects) {
            // Selected sections are replaced as a whole; unselected sections keep the user's
            // current overlay. A package without the selected section clears it, matching the
            // "clear first, then overwrite" behaviour of the other groups.
            val merged = AppearanceOverlayStore.merge(
                current = AppearanceOverlayStore.data(repo),
                incoming = data.appearance,
                applyColors = options.customColors,
                applyImageEffects = options.imageEffects,
            )
            if (merged == null) {
                AppearanceOverlayStore.clear(repo)
            } else {
                AppearanceOverlayStore.save(repo, merged)
            }
        }
        val savedAppearance = AppearanceOverlayStore.data(repo)

        if (adaptiveState != null) {
            val dark = isEffectiveDarkMode(context)
            AdaptiveThemeStore.apply(repo, adaptiveState.variant(dark))
            repo.adaptiveAppliedMode = if (dark) 1 else 0
            // The legacy sections above only touched non-appearance fields; mirror the applied
            // variant back into the local state so the final update cannot publish stale values.
            themeMode = repo.themeMode
            miuixMonet = repo.miuixMonet
            keyColor = repo.keyColor
            colorStyle = repo.colorStyle
            colorSpec = repo.colorSpec
            cardAlpha = repo.cardBackgroundAlphaPercent
            blurPercent = repo.customBackgroundBlurPercent
            scrimPercent = repo.customBackgroundScrimPercent
            targetUiMode = repo.uiMode
            hideHomeCardDecoration = repo.hideHomeCardDecoration
            hideHomeCardStatusText = repo.hideHomeCardStatusText
            homeCardStickers = repo.homeCardStickers
            bottomBarIcons = repo.bottomBarIcons
            backgroundUri = repo.customBackgroundUri
            homeCardImagePath = repo.homeCardImagePath
            floatingBottomBar = repo.enableFloatingBottomBar
            floatingBottomBarBlur = repo.enableFloatingBottomBarBlur
            navigationBadge = repo.enableNavigationBadge
            predictiveBack = repo.enablePredictiveBack
            swipeDismiss = repo.enableSwipeDismiss
            enableBlur = repo.enableBlur
            enableProgressiveBlur = repo.enableProgressiveBlur
            pagerMode = repo.pagerInterceptionMode
            pageScale = repo.pageScale
            moduleMaxLines = repo.moduleDescriptionMaxLines
        }

        // Any extracted file that was not promoted above is no longer needed.
        imported.temporaryFiles().forEach { path ->
            runCatching { File(path).delete() }
        }

        _uiState.update {
            it.copy(
                uiMode = targetUiMode,
                appIconId = effectiveIconId,
                customHomeTitle = effectiveHomeTitle,
                customTexts = effectiveCustomTexts,
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
                homeCardImagePath = homeCardImagePath,
                hideHomeCardStatusText = hideHomeCardStatusText,
                hideHomeCardDecoration = hideHomeCardDecoration,
                homeCardStickers = homeCardStickers,
                bottomBarIcons = bottomBarIcons,
                homeLayout = HomeLayout.fromValue(repo.homeLayout),
homeStatusAlignment = HomeStatusAlignment.fromValue(repo.homeStatusAlignment),
                homeStatusScale = HomeStatusStyle.coerceScale(repo.homeStatusScale),
homePillScale = HomeStatusStyle.coercePillScale(repo.homePillScale),
                homeStatusWidthFraction = HomeStatusStyle.coerceWidth(repo.homeStatusWidthFraction),
                homeCardImageStyle = HomeCardImageStyle.fromValue(repo.homeCardImageStyle),
                showHomeCardImageWithoutBackground = repo.showHomeCardImageWithoutBackground,
                customAppearanceJson = repo.customAppearanceJson,
                customColorsPresent = savedAppearance?.colors != null,
                imageEffectsPresent = savedAppearance?.image != null,
                appearance = AppearanceOverlayStore.load(repo),
                appearanceData = savedAppearance,
                adaptiveThemeActive = adaptiveState != null,
                useSystemWallpaper = if (
                    options.backgroundImage &&
                    (imported.backgroundPath != null ||
                        data.hasBackground == false ||
                        (adaptiveState != null && adaptiveState.light.data.hasBackground != null))
                ) {
                    false
                } else {
                    // The clear-first reset may already have turned the system wallpaper off
                    // for a package without background data; keep that result, not the old state.
                    current.useSystemWallpaper
                },
                systemWallpaperPath = if (
                    options.backgroundImage &&
                    (imported.backgroundPath != null ||
                        data.hasBackground == false ||
                        (adaptiveState != null && adaptiveState.light.data.hasBackground != null))
                ) {
                    ""
                } else {
                    current.systemWallpaperPath
                },
                enableFloatingBottomBar = floatingBottomBar,
                enableFloatingBottomBarBlur = floatingBottomBarBlur,
                enableNavigationBadge = navigationBadge,
                enablePredictiveBack = predictiveBack,
                enableSwipeDismiss = swipeDismiss,
                enableBlur = enableBlur,
                enableProgressiveBlur = enableProgressiveBlur,
                pagerInterceptionMode = pagerMode,
                pageScale = pageScale,
                moduleDescriptionMaxLines = moduleMaxLines,
            )
        }
    }

    
    private suspend fun buildAdaptiveState(
        context: Context,
        imported: ImportedTheme,
        options: ThemePackageOptions,
    ): AdaptiveThemeState {
        val light = imported.light ?: error("Light variant is missing")
        val dark = imported.dark ?: error("Dark variant is missing")
        return AdaptiveThemeState(
            light = buildVariantState(context, light, dark = false, options = options),
            dark = buildVariantState(context, dark, dark = true, options = options),
        )
    }

    private suspend fun buildVariantState(
        context: Context,
        variant: ImportedThemeVariant,
        dark: Boolean,
        options: ThemePackageOptions,
    ): AdaptiveThemeVariantState {
        val backgroundPath = if (options.backgroundImage) {
            if (variant.backgroundPath != null) {
                requireNotNull(
                    ImageStorage.replaceAdaptiveBackground(
                        context,
                        File(variant.backgroundPath),
                        dark,
                    ),
                ) { "Failed to save adaptive background" }
            } else {
                ImageStorage.clearAdaptiveBackground(context, dark)
                ""
            }
        } else {
            ""
        }
        val cardBackgroundPath = if (options.homeCardImage) {
            if (variant.cardBackgroundPath != null) {
                requireNotNull(
                    ImageStorage.replaceAdaptiveHomeCardImage(
                        context,
                        File(variant.cardBackgroundPath),
                        dark,
                    ),
                ) { "Failed to save adaptive card background" }
            } else {
                ImageStorage.clearAdaptiveHomeCardImage(context, dark)
                ""
            }
        } else {
            ""
        }

        val stickerTransforms = variant.data.homeCardStickerTransforms
        val stickers = if (options.stickers) {
            ImageStorage.clearAdaptiveHomeCardStickers(context, dark)
            if (variant.stickerPaths.isEmpty()) {
                emptyList()
            } else {
                variant.stickerPaths.mapIndexedNotNull { index, path ->
                    val saved = ImageStorage.importAdaptiveHomeCardSticker(
                        context,
                        File(path),
                        dark,
                        index,
                    ) ?: return@mapIndexedNotNull null
                    HomeCardSticker(
                        path = saved,
                        transform = stickerTransforms?.getOrNull(index)?.coerced()
                            ?: HomeCardStickerTransform(),
                    )
                }.take(HomeCardSticker.MAX_COUNT)
            }
        } else {
            emptyList()
        }

        val stickerData = when {
            !options.stickers -> null
            stickerTransforms != null || variant.stickerPaths.isNotEmpty() -> stickers.map { it.transform }
            else -> null
        }

        return AdaptiveThemeVariantState(
            data = variant.data.copy(
                // A missing mode still binds to the system switch; only the monet flavour is kept.
                themeMode = if (options.colors) variant.data.themeMode ?: 0 else null,
                miuixMonet = if (options.colors) variant.data.miuixMonet else null,
                keyColor = if (options.colors) variant.data.keyColor else null,
                colorStyle = if (options.colors) variant.data.colorStyle else null,
                colorSpec = if (options.colors) variant.data.colorSpec else null,
                cardBackgroundAlphaPercent = if (options.backgroundAppearance) {
                    variant.data.cardBackgroundAlphaPercent
                } else {
                    null
                },
                customBackgroundBlurPercent = if (options.backgroundAppearance) {
                    variant.data.customBackgroundBlurPercent
                } else {
                    null
                },
                customBackgroundScrimPercent = if (options.backgroundAppearance) {
                    variant.data.customBackgroundScrimPercent
                } else {
                    null
                },
                hasBackground = if (options.backgroundImage) variant.data.hasBackground else null,
                hasCardBackground = if (options.homeCardImage) {
                    variant.data.hasCardBackground
                } else {
                    null
                },
                hideHomeCardStatusText = if (options.homeCardDisplay) {
                    variant.data.hideHomeCardStatusText
                } else {
                    null
                },
                hideHomeCardDecoration = if (options.homeCardDisplay) {
                    variant.data.hideHomeCardDecoration
                } else {
                    null
                },
                homeLayout = if (options.homeCardDisplay) variant.data.homeLayout else null,
homeStatusAlignment = if (options.homeCardDisplay) {
                variant.data.homeStatusAlignment
            } else {
                null
            },
                homeStatusScale = if (options.homeCardDisplay) variant.data.homeStatusScale else null,
homePillScale = if (options.homeCardDisplay) variant.data.homePillScale else null,
                homeStatusWidthFraction = if (options.homeCardDisplay) {
                    variant.data.homeStatusWidthFraction
                } else {
                    null
                },
                homeCardImageStyle = if (options.homeCardDisplay) {
                    variant.data.homeCardImageStyle
                } else {
                    null
                },
                showHomeCardImageWithoutBackground = if (options.homeCardDisplay) {
                    variant.data.showHomeCardImageWithoutBackground
                } else {
                    null
                },
                homeCardStickerTransforms = stickerData,
                uiMode = if (options.interfaceMode) variant.data.uiMode else null,
                enableBlur = if (options.interfaceSwitches) variant.data.enableBlur else null,
                enableProgressiveBlur = if (options.interfaceSwitches) {
                    variant.data.enableProgressiveBlur
                } else {
                    null
                },
                enableFloatingBottomBar = if (options.interfaceSwitches) {
                    variant.data.enableFloatingBottomBar
                } else {
                    null
                },
                enableFloatingBottomBarBlur = if (options.interfaceSwitches) {
                    variant.data.enableFloatingBottomBarBlur
                } else {
                    null
                },
                enableNavigationBadge = if (options.interfaceSwitches) {
                    variant.data.enableNavigationBadge
                } else {
                    null
                },
                enablePredictiveBack = if (options.interactionBehavior) {
                    variant.data.enablePredictiveBack
                } else {
                    null
                },
                enableSwipeDismiss = if (options.interactionBehavior) {
                    variant.data.enableSwipeDismiss
                } else {
                    null
                },
                pagerInterceptionMode = if (options.interactionBehavior) {
                    variant.data.pagerInterceptionMode
                } else {
                    null
                },
                pageScale = if (options.interactionBehavior) variant.data.pageScale else null,
                moduleDescriptionMaxLines = if (options.moduleDisplay) {
                    variant.data.moduleDescriptionMaxLines
                } else {
                    null
                },
            ),
            backgroundPath = backgroundPath,
            cardBackgroundPath = cardBackgroundPath,
            stickers = stickers,
        )
    }

    private fun isSystemDarkMode(context: Context): Boolean =
        context.resources.configuration.uiMode and
            android.content.res.Configuration.UI_MODE_NIGHT_MASK ==
            android.content.res.Configuration.UI_MODE_NIGHT_YES

    private fun isEffectiveDarkMode(context: Context): Boolean {
        val mode = ColorMode.fromValue(repo.themeMode)
        return mode.isDark || (mode.isSystem && isSystemDarkMode(context))
    }

    private fun deactivateAdaptiveTheme() {
        if (!AdaptiveThemeStore.isActive(repo)) return
        AdaptiveThemeStore.clear(repo)
        _uiState.update { it.copy(adaptiveThemeActive = false) }
    }

    fun refreshAdaptiveAppearance() {
        viewModelScope.launch {
            AdaptiveThemeStore.sync(repo, isEffectiveDarkMode(ksuApp))
            val systemWallpaperPath = ImageStorage.systemWallpaperFile(ksuApp)
                .takeIf { it.isFile }?.absolutePath.orEmpty()
            _uiState.update {
                it.copy(
                    themeMode = repo.themeMode,
                    miuixMonet = repo.miuixMonet,
                    keyColor = repo.keyColor,
                    colorStyle = repo.colorStyle,
                    colorSpec = repo.colorSpec,
                    customBackgroundUri = repo.customBackgroundUri,
                    customBackgroundUpdatedAt = repo.customBackgroundUpdatedAt,
                    useSystemWallpaper = repo.useSystemWallpaper && systemWallpaperPath.isNotEmpty(),
                    systemWallpaperPath = systemWallpaperPath,
                    cardBackgroundAlphaPercent = repo.cardBackgroundAlphaPercent,
                    customBackgroundBlurPercent = repo.customBackgroundBlurPercent,
                    customBackgroundScrimPercent = repo.customBackgroundScrimPercent,
                    homeCardImagePath = repo.homeCardImagePath,
                    hideHomeCardStatusText = repo.hideHomeCardStatusText,
                    hideHomeCardDecoration = repo.hideHomeCardDecoration,
                    homeCardStickers = repo.homeCardStickers,
                    enableFloatingBottomBar = repo.enableFloatingBottomBar,
                    enableFloatingBottomBarBlur = repo.enableFloatingBottomBarBlur,
                    enableNavigationBadge = repo.enableNavigationBadge,
                    enablePredictiveBack = repo.enablePredictiveBack,
                    enableSwipeDismiss = repo.enableSwipeDismiss,
                    uiMode = repo.uiMode,
                    adaptiveThemeActive = AdaptiveThemeStore.isActive(repo),
                    adaptiveDraftLightCaptured = AdaptiveThemeStore.loadDraft(repo)?.light != null,
                    adaptiveDraftDarkCaptured = AdaptiveThemeStore.loadDraft(repo)?.dark != null,
                    adaptiveDraftComplete = AdaptiveThemeStore.loadDraft(repo)?.complete == true,
                    adaptiveDraftRevision = it.adaptiveDraftRevision + 1,
                )
            }
        }
    }

    fun captureAdaptiveDraft(context: Context, dark: Boolean) {
        viewModelScope.launch {
            val variant = withContext(Dispatchers.IO) { buildDraftVariant(context, dark) }
            if (variant == null) {
                Toast.makeText(ksuApp, R.string.theme_adaptive_capture_failed, Toast.LENGTH_SHORT).show()
                return@launch
            }
            val current = AdaptiveThemeStore.loadDraft(repo) ?: AdaptiveThemeDraft()
            val updated = if (dark) current.copy(dark = variant) else current.copy(light = variant)
            AdaptiveThemeStore.saveDraft(repo, updated)
            // The previously archived package no longer matches the edited draft.
            publishDraftFlags(updated)
            Toast.makeText(
                ksuApp,
                ksuApp.getString(
                    R.string.theme_adaptive_capture_success,
                    ksuApp.getString(
                        if (dark) R.string.theme_adaptive_draft_dark
                        else R.string.theme_adaptive_draft_light,
                    ),
                ),
                Toast.LENGTH_SHORT,
            ).show()
        }
    }

    fun clearAdaptiveDraft(context: Context) {
        viewModelScope.launch {
            AdaptiveThemeStore.clearDraft(repo)
            withContext(Dispatchers.IO) {
                ImageStorage.clearAdaptiveBackground(context, dark = false, draft = true)
                ImageStorage.clearAdaptiveBackground(context, dark = true, draft = true)
                ImageStorage.clearAdaptiveHomeCardImage(context, dark = false, draft = true)
                ImageStorage.clearAdaptiveHomeCardImage(context, dark = true, draft = true)
                ImageStorage.clearAdaptiveHomeCardStickers(context, dark = false, draft = true)
                ImageStorage.clearAdaptiveHomeCardStickers(context, dark = true, draft = true)
            }
            publishDraftFlags(null)
            Toast.makeText(ksuApp, R.string.theme_adaptive_draft_cleared, Toast.LENGTH_SHORT).show()
        }
    }

    fun applyAdaptiveDraft(context: Context) {
        viewModelScope.launch {
            val draft = AdaptiveThemeStore.loadDraft(repo)
            if (draft?.complete != true) {
                Toast.makeText(ksuApp, R.string.theme_adaptive_draft_incomplete, Toast.LENGTH_SHORT).show()
                return@launch
            }
            val light = withContext(Dispatchers.IO) {
                promoteDraftVariant(context, draft.light, dark = false)
            }
            val darkVariant = withContext(Dispatchers.IO) {
                promoteDraftVariant(context, draft.dark, dark = true)
            }
            if (light == null || darkVariant == null) {
                Toast.makeText(ksuApp, R.string.theme_adaptive_capture_failed, Toast.LENGTH_SHORT).show()
                return@launch
            }
            val state = AdaptiveThemeState(light = light, dark = darkVariant)
            AdaptiveThemeStore.save(repo, state)
            val dark = isEffectiveDarkMode(context)
            AdaptiveThemeStore.apply(repo, state.variant(dark))
            repo.adaptiveAppliedMode = if (dark) 1 else 0
            refreshAdaptiveAppearance()
            Toast.makeText(ksuApp, R.string.theme_adaptive_applied, Toast.LENGTH_SHORT).show()
        }
    }

    private suspend fun promoteDraftVariant(
        context: Context,
        variant: AdaptiveThemeVariantState?,
        dark: Boolean,
    ): AdaptiveThemeVariantState? = withContext(Dispatchers.IO) {
        if (variant == null) return@withContext null
        runCatching {
            val backgroundSource = variant.backgroundPath
                .takeIf { it.isNotBlank() }
                ?.let { File(it).takeIf { file -> file.isFile } }
            check(variant.data.hasBackground != true || backgroundSource != null) {
                "Draft background is missing"
            }
            val backgroundPath = backgroundSource
                ?.let { ImageStorage.stageFile(context, it) }
                ?.let { staged -> ImageStorage.replaceAdaptiveBackground(context, File(staged), dark) }
                ?: run {
                    ImageStorage.clearAdaptiveBackground(context, dark)
                    ""
                }
            val cardSource = variant.cardBackgroundPath
                .takeIf { it.isNotBlank() }
                ?.let { File(it).takeIf { file -> file.isFile } }
            check(variant.data.hasCardBackground != true || cardSource != null) {
                "Draft card background is missing"
            }
            val cardPath = cardSource
                ?.let { ImageStorage.stageFile(context, it) }
                ?.let { staged -> ImageStorage.replaceAdaptiveHomeCardImage(context, File(staged), dark) }
                ?: run {
                    ImageStorage.clearAdaptiveHomeCardImage(context, dark)
                    ""
                }
            ImageStorage.clearAdaptiveHomeCardStickers(context, dark)
            val stickers = variant.stickers.mapIndexedNotNull { index, sticker ->
                val staged = ImageStorage.stageFile(context, File(sticker.path))
                    ?: return@mapIndexedNotNull null
                ImageStorage.importAdaptiveHomeCardSticker(
                    context,
                    File(staged),
                    dark,
                    index,
                )?.let { path -> HomeCardSticker(path = path, transform = sticker.transform) }
            }
            AdaptiveThemeVariantState(
                data = variant.data.copy(
                    hasBackground = backgroundPath.isNotEmpty(),
                    hasCardBackground = cardPath.isNotEmpty(),
                    homeCardStickerTransforms = stickers.map { it.transform },
                ),
                backgroundPath = backgroundPath,
                cardBackgroundPath = cardPath,
                stickers = stickers,
            )
        }.getOrNull()
    }

    fun hasAdaptiveThemeForUpload(): Boolean =
        AdaptiveThemeStore.loadDraft(repo)?.complete == true ||
            AdaptiveThemeStore.isActive(repo)

    fun loadAdaptiveDraft(): AdaptiveThemeDraft? = AdaptiveThemeStore.loadDraft(repo)

    suspend fun createAdaptiveThemePackage(context: Context): Result<File> =
        withContext(Dispatchers.IO) {
            runCatching {
                val payload = currentThemePayload(ThemePackageOptions(), preferDraft = true)
                requireNotNull(payload.adaptive) { "No adaptive theme available" }
                val file = File(
                    context.cacheDir,
                    "theme_upload_adaptive_${System.currentTimeMillis()}.sukisu",
                )
                ThemePackageStorage.exportToFile(
                    file = file,
                    data = payload.data,
                    backgroundFile = payload.backgroundFile,
                    cardBackgroundFile = payload.cardBackgroundFile,
                    cardStickerFiles = payload.stickerFiles,
                    bottomBarIconFiles = payload.bottomBarIconFiles,
                    adaptive = payload.adaptive,
                ).getOrThrow()
                file
            }
        }

    private fun publishDraftFlags(draft: AdaptiveThemeDraft?) {
        _uiState.update {
            it.copy(
                adaptiveDraftLightCaptured = draft?.light != null,
                adaptiveDraftDarkCaptured = draft?.dark != null,
                adaptiveDraftComplete = draft?.complete == true,
                adaptiveDraftRevision = it.adaptiveDraftRevision + 1,
            )
        }
    }

    private suspend fun buildDraftVariant(
        context: Context,
        dark: Boolean,
    ): AdaptiveThemeVariantState? = withContext(Dispatchers.IO) {
        runCatching {
            // Read from the repository rather than the UI projection: the builder can be opened
            // and used before the appearance state has finished loading.
            val backgroundSource = when {
                repo.useSystemWallpaper ->
                    ImageStorage.systemWallpaperFile(context).takeIf { it.isFile }

                repo.customBackgroundUri.isNotBlank() ->
                    File(repo.customBackgroundUri).takeIf { it.isFile }

                else -> null
            }
            val backgroundPath = if (backgroundSource != null) {
                val staged = ImageStorage.stageFile(context, backgroundSource)
                    ?: error("Could not stage the background")
                ImageStorage.replaceAdaptiveBackground(
                    context,
                    File(staged),
                    dark,
                    draft = true,
                ) ?: error("Could not save the background")
            } else {
                ImageStorage.clearAdaptiveBackground(context, dark, draft = true)
                ""
            }

            val cardSource = repo.homeCardImagePath
                .takeIf { it.isNotBlank() }
                ?.let { File(it).takeIf { file -> file.isFile } }
            val cardPath = if (cardSource != null) {
                val staged = ImageStorage.stageFile(context, cardSource)
                    ?: error("Could not stage the card image")
                ImageStorage.replaceAdaptiveHomeCardImage(
                    context,
                    File(staged),
                    dark,
                    draft = true,
                ) ?: error("Could not save the card image")
            } else {
                ImageStorage.clearAdaptiveHomeCardImage(context, dark, draft = true)
                ""
            }

            ImageStorage.clearAdaptiveHomeCardStickers(context, dark, draft = true)
            val stickers = repo.homeCardStickers.mapIndexedNotNull { index, sticker ->
                val source = File(sticker.path).takeIf { it.isFile }
                    ?: return@mapIndexedNotNull null
                val staged = ImageStorage.stageFile(context, source)
                    ?: return@mapIndexedNotNull null
                ImageStorage.importAdaptiveHomeCardSticker(
                    context,
                    File(staged),
                    dark,
                    index,
                    draft = true,
                )?.let { path ->
                    HomeCardSticker(path = path, transform = sticker.transform.coerced())
                }
            }.take(HomeCardSticker.MAX_COUNT)

            AdaptiveThemeVariantState(
                data = ThemeVariantData(
                    themeMode = repo.themeMode,
                    miuixMonet = repo.miuixMonet,
                    keyColor = repo.keyColor,
                    colorStyle = repo.colorStyle,
                    colorSpec = repo.colorSpec,
                    cardBackgroundAlphaPercent = repo.cardBackgroundAlphaPercent,
                    customBackgroundBlurPercent = repo.customBackgroundBlurPercent,
                    customBackgroundScrimPercent = repo.customBackgroundScrimPercent,
                    hasBackground = backgroundPath.isNotEmpty(),
                    hasCardBackground = cardPath.isNotEmpty(),
                    hideHomeCardStatusText = repo.hideHomeCardStatusText,
                    hideHomeCardDecoration = repo.hideHomeCardDecoration,
                    homeCardStickerTransforms = stickers.map { it.transform },
                    homeLayout = repo.homeLayout,
homeStatusAlignment = repo.homeStatusAlignment,
                    homeStatusScale = repo.homeStatusScale,
homePillScale = repo.homePillScale,
                    homeStatusWidthFraction = repo.homeStatusWidthFraction,
                    homeCardImageStyle = repo.homeCardImageStyle,
                    showHomeCardImageWithoutBackground = repo.showHomeCardImageWithoutBackground,
                    uiMode = repo.uiMode,
                    enableFloatingBottomBar = repo.enableFloatingBottomBar,
                    enableFloatingBottomBarBlur = repo.enableFloatingBottomBarBlur,
                    enableNavigationBadge = repo.enableNavigationBadge,
                    enablePredictiveBack = repo.enablePredictiveBack,
                    enableSwipeDismiss = repo.enableSwipeDismiss,
                ),
                backgroundPath = backgroundPath,
                cardBackgroundPath = cardPath,
                stickers = stickers,
            )
        }.getOrNull()
    }

    fun resetBackgroundAppearance() {
        ThemeTrialManager.clear(ksuApp)
        viewModelScope.launch {
            val defaultBlur = ImageStorage.defaultBackgroundBlurPercent(ksuApp)
            repo.cardBackgroundAlphaPercent = ImageStorage.DEFAULT_CARD_ALPHA
            repo.customBackgroundBlurPercent = defaultBlur
            repo.customBackgroundScrimPercent = ImageStorage.DEFAULT_BACKGROUND_SCRIM
            repo.hideHomeCardStatusText = false
            repo.hideHomeCardDecoration = false

            // Theme colors, dynamic color and the custom background image are user choices.
            _uiState.update {
                it.copy(
                    cardBackgroundAlphaPercent = ImageStorage.DEFAULT_CARD_ALPHA,
                    customBackgroundBlurPercent = defaultBlur,
                    customBackgroundScrimPercent = ImageStorage.DEFAULT_BACKGROUND_SCRIM,
                    hideHomeCardStatusText = false,
                    hideHomeCardDecoration = false,
                )
            }

            Toast.makeText(ksuApp, R.string.theme_reset_done, Toast.LENGTH_SHORT).show()
        }
    }

    fun clearAllAppearance() {
        ThemeTrialManager.clear(ksuApp)
        deactivateAdaptiveTheme()
        seedGeneration++
        wallpaperGeneration++
        clearPendingSeed()
        viewModelScope.launch {
            val defaultBlur = ImageStorage.defaultBackgroundBlurPercent(ksuApp)
            ImageStorage.clear(ksuApp)
            ImageStorage.clearHomeCardImage(ksuApp)
            ImageStorage.clearHomeCardSticker(ksuApp)
            ImageStorage.clearBottomBarIcons(ksuApp)
            ImageStorage.clearAdaptiveImages(ksuApp)
            AdaptiveThemeStore.clearDraft(repo)
            runCatching { ImageStorage.systemWallpaperFile(ksuApp).delete() }

            repo.customBackgroundUri = ""
            repo.customBackgroundUpdatedAt = 0L
            repo.useSystemWallpaper = false
            repo.homeCardImagePath = ""
            repo.homeCardStickers = emptyList()
            repo.bottomBarIcons = emptyMap()
            repo.cardBackgroundAlphaPercent = ImageStorage.DEFAULT_CARD_ALPHA
            repo.customBackgroundBlurPercent = defaultBlur
            repo.customBackgroundScrimPercent = ImageStorage.DEFAULT_BACKGROUND_SCRIM
            repo.hideHomeCardStatusText = false
            repo.hideHomeCardDecoration = false
            repo.homeLayout = HomeLayout.CLASSIC.value
            repo.homeStatusAlignment = HomeStatusAlignment.START.value
            repo.homeStatusScale = HomeStatusStyle.SCALE_DEFAULT
            repo.homePillScale = HomeStatusStyle.PILL_SCALE_DEFAULT
            repo.homeStatusWidthFraction = HomeStatusStyle.WIDTH_DEFAULT
            repo.homeCardImageStyle = HomeCardImageStyle.BANNER.value
            repo.showHomeCardImageWithoutBackground = false
            repo.themeMode = 0
            repo.miuixMonet = false
            repo.keyColor = 0
            repo.extractColorFromBackground = false
            repo.colorStyle = PaletteStyle.TonalSpot.name
            repo.colorSpec = ColorSpec.SpecVersion.SPEC_2025.name
            repo.customTexts = emptyMap()
            repo.customHomeTitle = ""
            repo.appIconId = BuiltinAppIcons.DEFAULT_ID
            BuiltinAppIcons.apply(
                context = ksuApp,
                icon = BuiltinAppIcons.find(BuiltinAppIcons.DEFAULT_ID),
                dynamicColor = repo.appIconDynamicColor,
            )

            _uiState.update {
                it.copy(
                    customBackgroundUri = "",
                    customBackgroundUpdatedAt = 0L,
                    useSystemWallpaper = false,
                    systemWallpaperPath = "",
                    isSystemWallpaperBusy = false,
                    homeCardImagePath = "",
                    homeCardStickers = emptyList(),
                    bottomBarIcons = emptyMap(),
                    cardBackgroundAlphaPercent = ImageStorage.DEFAULT_CARD_ALPHA,
                    customBackgroundBlurPercent = defaultBlur,
                    customBackgroundScrimPercent = ImageStorage.DEFAULT_BACKGROUND_SCRIM,
                    hideHomeCardStatusText = false,
                    hideHomeCardDecoration = false,
                    homeLayout = HomeLayout.CLASSIC,
                homeStatusAlignment = HomeStatusAlignment.START,
                    homeStatusScale = HomeStatusStyle.SCALE_DEFAULT,
                homePillScale = HomeStatusStyle.PILL_SCALE_DEFAULT,
                    homeCardImageStyle = HomeCardImageStyle.BANNER,
                    showHomeCardImageWithoutBackground = false,
                    themeMode = 0,
                    miuixMonet = false,
                    keyColor = 0,
                    extractColorFromBackground = false,
                    colorStyle = PaletteStyle.TonalSpot.name,
                    colorSpec = ColorSpec.SpecVersion.SPEC_2025.name,
                    customTexts = emptyMap(),
                    customHomeTitle = "",
                    appIconId = BuiltinAppIcons.DEFAULT_ID,
                    adaptiveThemeActive = false,
                    adaptiveDraftLightCaptured = false,
                    adaptiveDraftDarkCaptured = false,
                    adaptiveDraftComplete = false,
                )
            }

            Toast.makeText(ksuApp, R.string.theme_clear_all_done, Toast.LENGTH_SHORT).show()
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

    fun setAutoDeleteUpdateApk(enabled: Boolean) {
        repo.autoDeleteUpdateApk = enabled
        _uiState.update { it.copy(autoDeleteUpdateApk = enabled) }
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

    fun setBackgroundSectionExpanded(expanded: Boolean) {
        repo.backgroundSectionExpanded = expanded
        _uiState.update { it.copy(backgroundSectionExpanded = expanded) }
    }

    fun setThemePackageSectionExpanded(expanded: Boolean) {
        repo.themePackageSectionExpanded = expanded
        _uiState.update { it.copy(themePackageSectionExpanded = expanded) }
    }

    fun setAppearanceSectionExpanded(expanded: Boolean) {
        repo.appearanceSectionExpanded = expanded
        _uiState.update { it.copy(appearanceSectionExpanded = expanded) }
    }

    fun setHomeCardSectionExpanded(expanded: Boolean) {
        repo.homeCardSectionExpanded = expanded
        _uiState.update { it.copy(homeCardSectionExpanded = expanded) }
    }

    fun setColorsSectionExpanded(expanded: Boolean) {
        repo.colorsSectionExpanded = expanded
        _uiState.update { it.copy(colorsSectionExpanded = expanded) }
    }

    fun setBottomBarSectionExpanded(expanded: Boolean) {
        repo.bottomBarSectionExpanded = expanded
        _uiState.update { it.copy(bottomBarSectionExpanded = expanded) }
    }

    fun setInteractionSectionExpanded(expanded: Boolean) {
        repo.interactionSectionExpanded = expanded
        _uiState.update { it.copy(interactionSectionExpanded = expanded) }
    }

    fun setDetailsSectionExpanded(expanded: Boolean) {
        repo.detailsSectionExpanded = expanded
        _uiState.update { it.copy(detailsSectionExpanded = expanded) }
    }

    fun setCustomHomeTitle(title: String) {
        val normalizedTitle = title.trim()
        repo.customHomeTitle = normalizedTitle
        val updatedTexts = repo.customTexts.toMutableMap()
        if (normalizedTitle.isEmpty()) {
            updatedTexts.remove("home.title")
        } else {
            updatedTexts["home.title"] = normalizedTitle
        }
        repo.customTexts = updatedTexts
        _uiState.update {
            it.copy(
                customHomeTitle = normalizedTitle,
                customTexts = updatedTexts,
            )
        }
    }

    fun setCustomText(key: String, value: String) {
        val trimmed = value.trim()
        val current = repo.customTexts.toMutableMap()
        if (trimmed.isEmpty()) {
            current.remove(key)
        } else {
            current[key] = trimmed
        }
        repo.customTexts = current
        if (key == "home.title") {
            repo.customHomeTitle = trimmed
        }
        _uiState.update {
            it.copy(
                customTexts = current,
                customHomeTitle = if (key == "home.title") trimmed else it.customHomeTitle,
            )
        }
    }

    fun setThemeStoreBaseUrl(url: String) {
        val trimmed = url.trim()
        repo.themeStoreBaseUrl = trimmed
        _uiState.update { it.copy(themeStoreBaseUrl = trimmed) }
    }

    fun setThemeStoreToken(token: String) {
        val trimmed = token.trim()
        repo.themeStoreToken = trimmed
        _uiState.update { it.copy(themeStoreToken = trimmed) }
    }

    fun setThemeStoreAuthorId(id: String) {
        val trimmed = id.trim()
        repo.themeStoreAuthorId = trimmed
        _uiState.update { it.copy(themeStoreAuthorId = trimmed) }
    }

    fun setThemeStoreAuthorName(name: String) {
        val trimmed = name.trim()
        repo.themeStoreAuthorName = trimmed
        _uiState.update { it.copy(themeStoreAuthorName = trimmed) }
    }

    fun setThemeStoreAdminUrl(url: String) {
        val trimmed = url.trim()
        repo.themeStoreAdminUrl = trimmed
        _uiState.update { it.copy(themeStoreAdminUrl = trimmed) }
    }

    fun setThemeStoreExtraSources(sources: List<com.sukisu.ultra.data.model.ThemeStoreSourceConfig>) {
        repo.themeStoreExtraSources = sources
        _uiState.update { it.copy(themeStoreExtraSources = sources) }
    }

    fun resetAllCustomTexts() {
        repo.customTexts = emptyMap()
        repo.customHomeTitle = ""
        _uiState.update {
            it.copy(
                customTexts = emptyMap(),
                customHomeTitle = "",
            )
        }
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

    /**
     * Picks a theme seed by hand. A non-zero color replaces any key color derived from the
     * background; the default pick turns background extraction back on when a background is
     * active.
     */
    fun setKeyColor(color: Int) {
        val generation = ++seedGeneration
        repo.keyColor = color
        val extract = color == 0 && repo.hasActiveBackground()
        repo.extractColorFromBackground = extract
        _uiState.update { it.copy(keyColor = color, extractColorFromBackground = extract) }
        if (!extract) return

        val background = repo.activeBackgroundFile() ?: return
        viewModelScope.launch {
            publishPendingSeed(color)
            val seed = ImageStorage.extractSeedColor(background, color)
            // Skip the write if another color pick or the toggle started a newer run.
            if (generation != seedGeneration) return@launch
            clearPendingSeed()
            repo.keyColor = seed
            _uiState.update { it.copy(keyColor = seed) }
        }
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

    fun setEnableProgressiveBlur(enabled: Boolean) {
        repo.enableProgressiveBlur = enabled
        _uiState.update { it.copy(enableProgressiveBlur = enabled) }
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

    fun setShowAiHomeCard(enabled: Boolean) {
        repo.showAiHomeCard = enabled
        _uiState.update { it.copy(showAiHomeCard = enabled) }
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

    private fun publishPendingSeed(keyColor: Int) {
        ksuApp.getSharedPreferences(MainActivityViewModel.SETTINGS_PREFS, Context.MODE_PRIVATE)
            .edit() { putInt(MainActivityViewModel.KEY_COLOR_PENDING, keyColor) }
    }

    private fun clearPendingSeed() {
        ksuApp.getSharedPreferences(MainActivityViewModel.SETTINGS_PREFS, Context.MODE_PRIVATE)
            .edit() { remove(MainActivityViewModel.KEY_COLOR_PENDING) }
    }

    private fun SettingsRepository.derivesKeyColorFromBackground(): Boolean =
        extractColorFromBackground && keyColor == 0

    private fun SettingsRepository.activeBackgroundFile(): File? {
        val path = if (useSystemWallpaper) {
            ImageStorage.systemWallpaperFile(ksuApp).takeIf { it.isFile }?.absolutePath
        } else {
            customBackgroundUri.takeIf { it.isNotEmpty() }
        } ?: return null
        return File(path).takeIf { it.isFile }
    }

    private fun SettingsRepository.hasActiveBackground(): Boolean = activeBackgroundFile() != null

    private fun SettingsUiState.toColorPaletteUiState(): ColorPaletteUiState {
        val colorMode = ColorMode.fromValue(themeMode)
        val resolvedStyle = parsePaletteStyle(colorStyle)
        val resolvedSpec = parseColorSpec(colorSpec)
        return ColorPaletteUiState(
            loading = false,
            keyColor = keyColor,
            miuixMonet = miuixMonet,
            currentColorMode = colorMode,
            currentPaletteStyle = resolvedStyle ?: PaletteStyle.TonalSpot,
            currentColorSpec = resolvedSpec ?: ColorSpec.SpecVersion.SPEC_2025,
            backgroundPath = if (useSystemWallpaper) systemWallpaperPath else customBackgroundUri,
            backgroundUpdatedAt = customBackgroundUpdatedAt,
            useSystemWallpaper = useSystemWallpaper,
            isSystemWallpaperBusy = isSystemWallpaperBusy,
            customBackgroundUri = customBackgroundUri,
            cardBackgroundAlphaPercent = cardBackgroundAlphaPercent,
            customBackgroundBlurPercent = customBackgroundBlurPercent,
            customBackgroundScrimPercent = customBackgroundScrimPercent,
            enableProgressiveBlur = enableProgressiveBlur,
            enableFloatingBottomBar = enableFloatingBottomBar,
            enableFloatingBottomBarBlur = enableFloatingBottomBarBlur,
            enableNavigationBadge = enableNavigationBadge,
            pageScale = pageScale,
            customHomeTitle = customHomeTitle,
            homeCardImagePath = homeCardImagePath,
            hideHomeCardStatusText = hideHomeCardStatusText,
            hideHomeCardDecoration = hideHomeCardDecoration,
            homeCardStickers = homeCardStickers,
            homeLayout = homeLayout,
homeStatusAlignment = homeStatusAlignment,
            homeStatusScale = homeStatusScale,
homePillScale = homePillScale,
            homeStatusWidthFraction = homeStatusWidthFraction,
            homeCardImageStyle = homeCardImageStyle,
            showHomeCardImageWithoutBackground = showHomeCardImageWithoutBackground,
            adaptiveThemeActive = adaptiveThemeActive,
            adaptiveDraftLightCaptured = adaptiveDraftLightCaptured,
            adaptiveDraftDarkCaptured = adaptiveDraftDarkCaptured,
            adaptiveDraftComplete = adaptiveDraftComplete,
            themeMode = themeMode,
            colorStyle = colorStyle,
            colorSpec = colorSpec,
            extractColorFromBackground = extractColorFromBackground,
            backgroundAppearanceExpanded = backgroundAppearanceExpanded,
            backgroundSectionExpanded = backgroundSectionExpanded,
            themePackageSectionExpanded = themePackageSectionExpanded,
            appearanceSectionExpanded = appearanceSectionExpanded,
            homeCardSectionExpanded = homeCardSectionExpanded,
            colorsSectionExpanded = colorsSectionExpanded,
            bottomBarSectionExpanded = bottomBarSectionExpanded,
            interactionSectionExpanded = interactionSectionExpanded,
            detailsSectionExpanded = detailsSectionExpanded,
            showFullStatus = showFullStatus,
            hideHomeWarnings = hideHomeWarnings,
            showAiHomeCard = showAiHomeCard,
            moduleDescriptionMaxLines = moduleDescriptionMaxLines,
            appearance = appearance,
            customAppearanceJson = customAppearanceJson,
            customColorsPresent = customColorsPresent,
            imageEffectsPresent = imageEffectsPresent,
        )
    }

    private fun parsePaletteStyle(value: String): PaletteStyle? =
        runCatching { PaletteStyle.valueOf(value) }.getOrNull()

    private fun parseColorSpec(value: String): ColorSpec.SpecVersion? =
        runCatching { ColorSpec.SpecVersion.valueOf(value) }.getOrNull()
}
