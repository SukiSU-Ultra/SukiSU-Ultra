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
import com.sukisu.ultra.ui.util.ImageStorage
import com.sukisu.ultra.ui.util.customTextsInGroups
import com.sukisu.ultra.ui.screen.module.ModuleNameSort
import com.sukisu.ultra.ui.util.BuiltinAppIcon
import com.sukisu.ultra.ui.util.BuiltinAppIcons
import com.sukisu.ultra.ui.util.HomeCardSticker
import com.sukisu.ultra.ui.util.HomeCardStickerTransform
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
)

class SettingsViewModel(
    private val repo: SettingsRepository = SettingsRepositoryImpl()
) : ViewModel() {

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

    /** Invalidates an in-flight wallpaper capture when the option changes or appearance resets. */
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
            val enableFloatingBottomBar = repo.enableFloatingBottomBar
            val enableFloatingBottomBarBlur = repo.enableFloatingBottomBarBlur
            val enableNavigationBadge = repo.enableNavigationBadge
            val pageScale = repo.pageScale
            val moduleDescriptionMaxLines = repo.moduleDescriptionMaxLines
            val enableWebDebugging = repo.enableWebDebugging
            val autoDeleteModuleZip = repo.autoDeleteModuleZip
            val showFullStatus = repo.showFullStatus
            val hideHomeWarnings = repo.hideHomeWarnings
            val showAiHomeCard = repo.showAiHomeCard
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
                    customHomeTitle = repo.customHomeTitle,
                    customTexts = repo.customTexts,
        homeCardImagePath = repo.homeCardImagePath,
                    hideHomeCardStatusText = repo.hideHomeCardStatusText,
                    hideHomeCardDecoration = repo.hideHomeCardDecoration,
                    homeCardStickers = repo.homeCardStickers,
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

    /** Copies a newly picked image into the crop cache and hands its path to the crop screen. */
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

    /** Copies the current background so the user can re-crop it without losing the original. */
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

    /** Applies the in-app or gallery crop result and refreshes the dynamic color seed. */
    suspend fun finishBackgroundCrop(
        context: Context,
        output: File,
        sourcePath: String?,
    ): Boolean = withContext(Dispatchers.IO) {
        val savedPath = ImageStorage.replace(context, output) ?: return@withContext false
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

    /**
     * Toggles deriving the key color from the background. Enabling it commits the switch right
     * away and re-seeds from the active background in the background; disabling leaves the
     * current color in place for manual selection.
     */
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

    fun pickHomeCardImage(context: Context, uri: Uri) {
        viewModelScope.launch {
            val path = ImageStorage.saveHomeCardImage(context, uri)
            if (path != null) {
                repo.homeCardImagePath = path
                _uiState.update { it.copy(homeCardImagePath = path) }
            } else {
                Toast.makeText(context, R.string.home_card_image_failed, Toast.LENGTH_SHORT).show()
            }
        }
    }

    fun clearHomeCardImage() {
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

    fun exportTheme(context: Context, uri: Uri, options: ThemePackageOptions) {
        viewModelScope.launch {
            val payload = currentThemePayload(options)
            ThemePackageStorage.export(context, uri, payload.data, payload.backgroundFile, payload.cardBackgroundFile, payload.stickerFiles)
                .onSuccess {
                    Toast.makeText(ksuApp, R.string.theme_export_success, Toast.LENGTH_SHORT).show()
                }
                .onFailure {
                    Toast.makeText(ksuApp, R.string.theme_export_failed, Toast.LENGTH_SHORT).show()
                }
        }
    }

    /** Builds a .sukisu package from the current device appearance for store submission. */
    suspend fun createCurrentThemePackage(context: Context): Result<File> = withContext(Dispatchers.IO) {
        runCatching {
            val payload = currentThemePayload(ThemePackageOptions())
            val file = File(context.cacheDir, "theme_upload_preset.sukisu")
            ThemePackageStorage.exportToFile(
                file = file,
                data = payload.data,
                backgroundFile = payload.backgroundFile,
                cardBackgroundFile = payload.cardBackgroundFile,
                cardStickerFiles = payload.stickerFiles,
            ).getOrThrow()
            file
        }
    }

    private fun currentThemePayload(options: ThemePackageOptions): CurrentThemePayload {
        val state = _uiState.value
        val backgroundFile = if (options.backgroundImage) {
            if (state.useSystemWallpaper) {
                ImageStorage.systemWallpaperFile(ksuApp).takeIf { it.isFile }
            } else {
                state.customBackgroundUri
                    .takeIf { it.isNotEmpty() }
                    ?.let { path -> File(path).takeIf { it.isFile } }
            }
        } else null
        val cardBackgroundFile = if (options.homeCardImage) {
            state.homeCardImagePath
                .takeIf { it.isNotEmpty() }
                ?.let { path -> File(path).takeIf { it.isFile } }
        } else null
        val stickerEntries = if (options.stickers) {
            state.homeCardStickers.filter { File(it.path).isFile }
        } else {
            emptyList()
        }
        val cardStickerFiles = stickerEntries.map { File(it.path) }
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
            themeMode = state.themeMode.takeIf { options.colors },
            miuixMonet = state.miuixMonet.takeIf { options.colors },
            keyColor = state.keyColor.takeIf { options.colors },
            colorStyle = state.colorStyle.takeIf { options.colors },
            colorSpec = state.colorSpec.takeIf { options.colors },
            cardBackgroundAlphaPercent = state.cardBackgroundAlphaPercent.takeIf { options.backgroundAppearance },
            customBackgroundBlurPercent = state.customBackgroundBlurPercent.takeIf { options.backgroundAppearance },
            customBackgroundScrimPercent = state.customBackgroundScrimPercent.takeIf { options.backgroundAppearance },
            hasBackground = if (options.backgroundImage) backgroundFile != null else null,
            hasCardBackground = if (options.homeCardImage) cardBackgroundFile != null else null,
            hideHomeCardStatusText = state.hideHomeCardStatusText.takeIf { options.homeCardDisplay },
            hideHomeCardDecoration = state.hideHomeCardDecoration.takeIf { options.homeCardDisplay },
            homeCardStickerTransforms = if (options.stickers) {
                stickerEntries.map { it.transform }
            } else {
                null
            },
            uiMode = state.uiMode.takeIf { options.customConfig },
            appIconId = exportedIconId.takeIf { options.appIcon },
            enableFloatingBottomBar = state.enableFloatingBottomBar.takeIf { options.customConfig },
            enableFloatingBottomBarBlur = state.enableFloatingBottomBarBlur.takeIf { options.customConfig },
            enableNavigationBadge = state.enableNavigationBadge.takeIf { options.customConfig },
            enablePredictiveBack = repo.enablePredictiveBack.takeIf { options.customConfig },
            enableSwipeDismiss = repo.enableSwipeDismiss.takeIf { options.customConfig },
            moduleSortEnabledFirst = repo.moduleSortEnabledFirst.takeIf { options.customConfig },
            moduleSortActionFirst = repo.moduleSortActionFirst.takeIf { options.customConfig },
            moduleSortWebUiFirst = repo.moduleSortWebUiFirst.takeIf { options.customConfig },
            moduleSortZygiskFirst = repo.moduleSortZygiskFirst.takeIf { options.customConfig },
            moduleSortMetamoduleFirst = repo.moduleSortMetamoduleFirst.takeIf { options.customConfig },
            moduleSortNameOrder = repo.moduleSortNameOrder.takeIf { options.customConfig },
            moduleSortManual = repo.moduleSortManual.takeIf { options.customConfig },
            customHomeTitle = if (options.customTexts && CustomTextGroup.HOME in options.customTextGroups) {
                state.customHomeTitle.takeIf { it.isNotBlank() }
            } else {
                null
            },
            customTexts = if (options.customTexts) {
                customTextsInGroups(state.customTexts, options.customTextGroups)
                    .takeIf { it.isNotEmpty() }
            } else {
                null
            },
        )
        return CurrentThemePayload(data, backgroundFile, cardBackgroundFile, cardStickerFiles)
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

    /** Imports a package downloaded by the theme store. */
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
        if (pending?.backgroundPath != null) {
            runCatching { File(pending.backgroundPath).delete() }
        }
        if (pending?.cardBackgroundPath != null) {
            runCatching { File(pending.cardBackgroundPath).delete() }
        }
        if (pending?.stickerPaths != null) {
            pending.stickerPaths.forEach { runCatching { File(it).delete() } }
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
            applyImportedTheme(context, pending, options)
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

    /**
     * Starts a store trial in the view model scope. Running it here instead of directly in a
     * composable `LaunchedEffect` means a rotation or recomposition cannot cancel the apply
     * halfway through and leave the trial marker with a deleted package.
     */
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

    /**
     * Applies a store package as a trial. The current appearance is backed up first; a marker
     * makes the next process start restore that backup and delete the trial cache.
     */
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
                    )
                } catch (error: Exception) {
                    restoreTrialBackup(context)
                    throw error
                }
            }.also {
                runCatching { packageFile.delete() }
            }
        }

    /** Restores and clears a trial left over from a previous process or activity task. */
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

    private suspend fun applyImportedTheme(
        context: Context,
        imported: ImportedTheme,
        options: ThemePackageOptions,
    ) {
        val current = _uiState.value
        val data = imported.data

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
        }

        var floatingBottomBar = current.enableFloatingBottomBar
        var floatingBottomBarBlur = current.enableFloatingBottomBarBlur
        var navigationBadge = current.enableNavigationBadge
        var predictiveBack = repo.enablePredictiveBack
        var swipeDismiss = repo.enableSwipeDismiss

        if (options.customConfig) {
            targetUiMode = data.uiMode?.takeIf { it == "miuix" || it == "material" } ?: current.uiMode
            repo.uiMode = targetUiMode

            floatingBottomBar = data.enableFloatingBottomBar ?: current.enableFloatingBottomBar

            floatingBottomBarBlur = data.enableFloatingBottomBarBlur ?: current.enableFloatingBottomBarBlur
            navigationBadge = data.enableNavigationBadge ?: current.enableNavigationBadge
            repo.enableFloatingBottomBar = floatingBottomBar
            repo.enableFloatingBottomBarBlur = floatingBottomBarBlur
            repo.enableNavigationBadge = navigationBadge

            predictiveBack = data.enablePredictiveBack ?: repo.enablePredictiveBack
            swipeDismiss = data.enableSwipeDismiss ?: repo.enableSwipeDismiss
            repo.enablePredictiveBack = predictiveBack
            repo.enableSwipeDismiss = swipeDismiss

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
                useSystemWallpaper = if (
                    options.backgroundImage &&
                    (imported.backgroundPath != null || data.hasBackground == false)
                ) {
                    false
                } else {
                    it.useSystemWallpaper
                },
                systemWallpaperPath = if (
                    options.backgroundImage &&
                    (imported.backgroundPath != null || data.hasBackground == false)
                ) {
                    ""
                } else {
                    it.systemWallpaperPath
                },
                enableFloatingBottomBar = floatingBottomBar,
                enableFloatingBottomBarBlur = floatingBottomBarBlur,
                enableNavigationBadge = navigationBadge,
                enablePredictiveBack = predictiveBack,
                enableSwipeDismiss = swipeDismiss,
            )
        }
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
        seedGeneration++
        wallpaperGeneration++
        clearPendingSeed()
        viewModelScope.launch {
            val defaultBlur = ImageStorage.defaultBackgroundBlurPercent(ksuApp)
            ImageStorage.clear(ksuApp)
            ImageStorage.clearHomeCardImage(ksuApp)
            ImageStorage.clearHomeCardSticker(ksuApp)
            runCatching { ImageStorage.systemWallpaperFile(ksuApp).delete() }

            repo.customBackgroundUri = ""
            repo.customBackgroundUpdatedAt = 0L
            repo.useSystemWallpaper = false
            repo.homeCardImagePath = ""
            repo.homeCardStickers = emptyList()
            repo.cardBackgroundAlphaPercent = ImageStorage.DEFAULT_CARD_ALPHA
            repo.customBackgroundBlurPercent = defaultBlur
            repo.customBackgroundScrimPercent = ImageStorage.DEFAULT_BACKGROUND_SCRIM
            repo.hideHomeCardStatusText = false
            repo.hideHomeCardDecoration = false
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
                    cardBackgroundAlphaPercent = ImageStorage.DEFAULT_CARD_ALPHA,
                    customBackgroundBlurPercent = defaultBlur,
                    customBackgroundScrimPercent = ImageStorage.DEFAULT_BACKGROUND_SCRIM,
                    hideHomeCardStatusText = false,
                    hideHomeCardDecoration = false,
                    themeMode = 0,
                    miuixMonet = false,
                    keyColor = 0,
                    extractColorFromBackground = false,
                    colorStyle = PaletteStyle.TonalSpot.name,
                    colorSpec = ColorSpec.SpecVersion.SPEC_2025.name,
                    customTexts = emptyMap(),
                    customHomeTitle = "",
                    appIconId = BuiltinAppIcons.DEFAULT_ID,
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

    /**
     * Tells the activity to stay on [keyColor] until the background seed lands, so a tap that
     * re-seeds does not re-derive the palette for an intermediate color first. Same file the
     * activity already listens to for every other appearance change.
     */
    private fun publishPendingSeed(keyColor: Int) {
        ksuApp.getSharedPreferences(MainActivityViewModel.SETTINGS_PREFS, Context.MODE_PRIVATE)
            .edit() { putInt(MainActivityViewModel.KEY_COLOR_PENDING, keyColor) }
    }

    private fun clearPendingSeed() {
        ksuApp.getSharedPreferences(MainActivityViewModel.SETTINGS_PREFS, Context.MODE_PRIVATE)
            .edit() { remove(MainActivityViewModel.KEY_COLOR_PENDING) }
    }

    /**
     * Whether the theme seed currently comes from the background image. A manually picked key
     * color wins over the stored flag, so both seed sources are never active at once.
     */
    private fun SettingsRepository.derivesKeyColorFromBackground(): Boolean =
        extractColorFromBackground && keyColor == 0

    /** The background image the theme colors and the app background currently use, if any. */
    private fun SettingsRepository.activeBackgroundFile(): File? {
        val path = if (useSystemWallpaper) {
            ImageStorage.systemWallpaperFile(ksuApp).takeIf { it.isFile }?.absolutePath
        } else {
            customBackgroundUri.takeIf { it.isNotEmpty() }
        } ?: return null
        return File(path).takeIf { it.isFile }
    }

    private fun SettingsRepository.hasActiveBackground(): Boolean = activeBackgroundFile() != null

    /** One-shot mapping with the same fallbacks the screen used to apply while composing. */
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
            enableFloatingBottomBar = enableFloatingBottomBar,
            enableFloatingBottomBarBlur = enableFloatingBottomBarBlur,
            enableNavigationBadge = enableNavigationBadge,
            pageScale = pageScale,
            customHomeTitle = customHomeTitle,
            homeCardImagePath = homeCardImagePath,
            hideHomeCardStatusText = hideHomeCardStatusText,
            hideHomeCardDecoration = hideHomeCardDecoration,
            homeCardStickers = homeCardStickers,
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
            showFullStatus = showFullStatus,
            hideHomeWarnings = hideHomeWarnings,
            showAiHomeCard = showAiHomeCard,
            moduleDescriptionMaxLines = moduleDescriptionMaxLines,
        )
    }

    /**
     * Same parsing the page used to do inline, resolved off the composition. Unknown stored
     * values fall back to the defaults at the call site instead of failing.
     */
    private fun parsePaletteStyle(value: String): PaletteStyle? =
        runCatching { PaletteStyle.valueOf(value) }.getOrNull()

    private fun parseColorSpec(value: String): ColorSpec.SpecVersion? =
        runCatching { ColorSpec.SpecVersion.valueOf(value) }.getOrNull()
}
