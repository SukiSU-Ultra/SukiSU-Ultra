package com.sukisu.ultra.data.repository

interface SettingsRepository {
    var customBackgroundUri: String
    var customBackgroundUpdatedAt: Long
    /** Use the launcher wallpaper as the app background instead of [customBackgroundUri]. */
    var useSystemWallpaper: Boolean
    /** Derive the theme key color from the active background image. */
    var extractColorFromBackground: Boolean
    var cardBackgroundAlphaPercent: Int
    var customBackgroundBlurPercent: Int
    var customBackgroundScrimPercent: Int
    var backgroundAppearanceExpanded: Boolean
    var customHomeTitle: String
    var customTexts: Map<String, String>
    var homeCardImagePath: String
    var uiMode: String
    var appLanguage: String
    var checkUpdate: Boolean
    var checkCiUpdate: Boolean
    var checkModuleUpdate: Boolean
    var autoDeleteModuleZip: Boolean
    /** Id of the selected launcher icon (see [com.sukisu.ultra.ui.util.BuiltinAppIcons]). */
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
    /** Name of the [com.sukisu.ultra.ui.screen.modulerepo.RepoSort] entry. */
    var moduleRepoSortOrder: String
    var superuserShowSystemApps: Boolean
    var superuserShowOnlyPrimaryUserApps: Boolean
    var superuserSortOption: Int
    var suLogFilters: Set<String>?
    var showFullStatus: Boolean
    var hideHomeWarnings: Boolean
    /** Show the decorative check mark on the Miuix home status card. */
    var showHomeStatusIcon: Boolean
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
