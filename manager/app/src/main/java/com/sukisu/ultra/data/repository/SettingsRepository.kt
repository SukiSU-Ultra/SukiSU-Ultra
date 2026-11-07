package com.sukisu.ultra.data.repository

import com.sukisu.ultra.ui.util.HomeCardSticker

interface SettingsRepository {
    var customBackgroundUri: String
    var customBackgroundUpdatedAt: Long
    
    var useSystemWallpaper: Boolean
    /**
     * Derive the theme key color from the active background image. This and [keyColor] are
     * mutually exclusive: a non-zero [keyColor] wins, so read through
     * [com.sukisu.ultra.ui.viewmodel.derivesKeyColorFromBackground] instead of the raw flag.
     */
    var extractColorFromBackground: Boolean
    var cardBackgroundAlphaPercent: Int
    var customBackgroundBlurPercent: Int
    var customBackgroundScrimPercent: Int
    var backgroundAppearanceExpanded: Boolean
    
    var backgroundSectionExpanded: Boolean
    var themePackageSectionExpanded: Boolean
    var appearanceSectionExpanded: Boolean
    var homeCardSectionExpanded: Boolean
    var colorsSectionExpanded: Boolean
    var bottomBarSectionExpanded: Boolean
    var interactionSectionExpanded: Boolean
    var detailsSectionExpanded: Boolean
    var customHomeTitle: String
    var customTexts: Map<String, String>
    
    var themeStoreBaseUrl: String
    
    var themeStoreToken: String
    
    var themeStoreAuthorId: String
    
    var themeStoreAuthorName: String
    
    var themeStoreAdminUrl: String
    
    var themeStoreExtraSources: List<com.sukisu.ultra.data.model.ThemeStoreSourceConfig>
    
    var themeStoreUploadSource: String
    var themeStoreGridLayout: Boolean
    var homeCardImagePath: String
    
    var hideHomeCardStatusText: Boolean
    
    var hideHomeCardDecoration: Boolean
    var homeCardStickers: List<HomeCardSticker>
    /** Custom bottom bar icon images keyed by [com.sukisu.ultra.ui.util.BottomBarIconSlot.key]. */
    var bottomBarIcons: Map<String, String>
    /** "classic" or "immersive"; see [com.sukisu.ultra.ui.util.HomeLayout]. */
    var homeLayout: String
    /** "start" or "end"; see [com.sukisu.ultra.ui.util.HomeStatusAlignment]. */
    var homeStatusAlignment: String
    /** Uniform scale for the immersive status area, coerced to the supported range. */
    var homeStatusScale: Float
    /** Independent scale for the working-status pill. */
    var homePillScale: Float
    /** Width of the immersive status cluster relative to the page content width. */
    var homeStatusWidthFraction: Float
    /** "window", "banner" or "off"; see [com.sukisu.ultra.ui.util.HomeCardImageStyle]. */
    var homeCardImageStyle: String
    /** Show the immersive card image even when no custom background is active. */
    var showHomeCardImageWithoutBackground: Boolean
    
    var adaptiveThemeJson: String
    
    var adaptiveAppliedMode: Int
    
    var adaptiveDraftJson: String
    /** Canonical JSON for the static colour/image-effect overlay; empty when disabled. */
    var customAppearanceJson: String
    var uiMode: String
    var appLanguage: String
    var checkUpdate: Boolean
    var checkCiUpdate: Boolean
    var checkModuleUpdate: Boolean
    var autoDeleteModuleZip: Boolean
    /** When enabled, a manager self-update installs without keeping the APK in Downloads. */
    var autoDeleteUpdateApk: Boolean
    
    var appIconId: String
    var appIconDynamicColor: Boolean
    var themeMode: Int
    var miuixMonet: Boolean
    var keyColor: Int
    var colorStyle: String
    var colorSpec: String
    var enablePredictiveBack: Boolean
    var enableSwipeDismiss: Boolean
    var pagerInterceptionMode: Int
    var enableBlur: Boolean
    /** Progressive (edge gradient) blur behind the top and bottom bars. */
    var enableProgressiveBlur: Boolean
    var enableFloatingBottomBar: Boolean
    var enableFloatingBottomBarBlur: Boolean
    var enableNavigationBadge: Boolean
    var navigationRailExpanded: Boolean
    var pageScale: Float
    var moduleDescriptionMaxLines: Int
    var enableWebDebugging: Boolean
    var moduleSortEnabledFirst: Boolean
    var moduleSortActionFirst: Boolean
    var moduleSortWebUiFirst: Boolean
    var moduleSortZygiskFirst: Boolean
    var moduleSortMetamoduleFirst: Boolean
    var moduleSortNameOrder: String
    var moduleSortManual: Boolean
    var moduleManualOrder: String
    
    var moduleRepoSortOrder: String
    var superuserShowSystemApps: Boolean
    var superuserShowOnlyPrimaryUserApps: Boolean
    var superuserSortOption: Int
    var suLogFilters: Set<String>?
    var showFullStatus: Boolean
    var hideHomeWarnings: Boolean
    
    var showAiHomeCard: Boolean
    var autoJailbreak: Boolean
    var useSoftReboot: Boolean
    val intentToken: String

    suspend fun getSuCompatStatus(): String
    suspend fun getSuCompatPersistValue(): Long?
    fun isSuEnabled(): Boolean
    fun setSuEnabled(enabled: Boolean): Boolean
    fun setSuCompatModePref(mode: Int)
    fun getSuCompatModePref(): Int

    suspend fun getKernelUmountStatus(): String
    fun isKernelUmountEnabled(): Boolean
    fun setKernelUmountEnabled(enabled: Boolean): Boolean

    suspend fun getSelinuxHideStatus(): String
    fun isSelinuxHideEnabled(): Boolean
    fun setSelinuxHideEnabled(enabled: Boolean): Int

    suspend fun getAvcSpoofStatus(): String
    fun isAvcSpoofEnabled(): Boolean
    fun setAvcSpoofEnabled(enabled: Boolean): Boolean

    suspend fun getMountHideStatus(): String
    fun isMountHideEnabled(): Boolean
    fun setMountHideEnabled(enabled: Boolean): Int

    suspend fun getSulogStatus(): String
    suspend fun getSulogPersistValue(): Long?
    suspend fun getSulogValue(): Long?
    fun setSulogEnabled(enabled: Boolean): Boolean

    suspend fun getAdbRootStatus(): String
    suspend fun getAdbRootPersistValue(): Long?
    suspend fun getAdbRootValue(): Long?
    fun setAdbRootEnabled(enabled: Boolean): Boolean
    suspend fun getShellSuAdbOnlyStatus(): String
    suspend fun getShellSuAdbOnlyValue(): Long?
    suspend fun getShellSuAdbOnlyPersistValue(): Long?
    fun setShellSuAdbOnlyEnabled(enabled: Boolean): Boolean

    fun isDefaultUmountModules(): Boolean
    fun setDefaultUmountModules(enabled: Boolean): Boolean

    fun isLkmMode(): Boolean

    fun execKsudFeatureSave()
}
