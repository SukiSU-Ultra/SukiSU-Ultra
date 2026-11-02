package com.sukisu.ultra.ui.screen.settings

import androidx.compose.runtime.Immutable
import androidx.compose.runtime.saveable.listSaver
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.util.BuiltinAppIcons
import com.sukisu.ultra.ui.util.CustomTextGroup
import com.sukisu.ultra.ui.util.HomeCardSticker

@Immutable
data class SettingsUiState(
    val uiMode: String = UiMode.DEFAULT_VALUE,
    val appLanguage: String = "",
    val checkUpdate: Boolean = true,
    val checkCiUpdate: Boolean = false,
    val checkModuleUpdate: Boolean = true,
    val autoDeleteModuleZip: Boolean = false,
    val appIconId: String = BuiltinAppIcons.DEFAULT_ID,
    val appIconDynamicColor: Boolean = false,
    val themeMode: Int = 0,
    val miuixMonet: Boolean = false,
    val keyColor: Int = 0,
    val colorStyle: String = PaletteStyle.TonalSpot.name,
    val colorSpec: String = ColorSpec.SpecVersion.SPEC_2025.name,
    val enablePredictiveBack: Boolean = false,
    val enableSwipeDismiss: Boolean = true,
    val pagerInterceptionMode: Int = 1,
    val enableBlur: Boolean = true,
    val enableFloatingBottomBar: Boolean = false,
    val enableFloatingBottomBarBlur: Boolean = false,
    val enableNavigationBadge: Boolean = true,
    val pageScale: Float = 1.0f,
    val moduleDescriptionMaxLines: Int = 4,
    val enableWebDebugging: Boolean = false,
    val showFullStatus: Boolean = true,
    val hideHomeWarnings: Boolean = false,
    val showAiHomeCard: Boolean = false,

    // Su Compat
    val suCompatStatus: String = "",
    val suCompatMode: Int = 0, // 0: enable default, 1: disable until reboot, 2: disable always
    val isSuEnabled: Boolean = false,

    // Kernel Umount
    val kernelUmountStatus: String = "",
    val isKernelUmountEnabled: Boolean = false,

    // SELinux Hide
    val selinuxHideStatus: String = "",
    val isSelinuxHideEnabled: Boolean = false,

    // AVC log spoofing
    val avcSpoofStatus: String = "",
    val isAvcSpoofEnabled: Boolean = false,

    // Mount Hide
    val mountHideStatus: String = "",
    val isMountHideEnabled: Boolean = false,

    // SU Log
    val sulogStatus: String = "",
    val isSulogEnabled: Boolean = false,

    // Umount Modules
    val isDefaultUmountModules: Boolean = false,

    // ADB Root
    val adbRootStatus: String = "",
    val isAdbRootEnabled: Boolean = false,

    // Shell SU ADB Only
    val shellSuAdbOnlyStatus: String = "",
    val isShellSuAdbOnlyEnabled: Boolean = false,

    val isLkmMode: Boolean = false,
    val isLateLoadMode: Boolean = false,

    // Auto Jailbreak
    val autoJailbreak: Boolean = false,

    // Soft Reboot
    val useSoftReboot: Boolean = false,

    val customBackgroundUri: String = "",
    val customBackgroundUpdatedAt: Long = 0L,
    val useSystemWallpaper: Boolean = false,
    /** Cached launcher wallpaper used when [useSystemWallpaper] is on and the file exists. */
    val systemWallpaperPath: String = "",
    val isSystemWallpaperBusy: Boolean = false,
    val extractColorFromBackground: Boolean = false,
    val cardBackgroundAlphaPercent: Int = 60,
    val customBackgroundBlurPercent: Int = 50,
    val customBackgroundScrimPercent: Int = -35,
    val backgroundAppearanceExpanded: Boolean = true,
    val backgroundSectionExpanded: Boolean = true,
    val themePackageSectionExpanded: Boolean = true,
    val appearanceSectionExpanded: Boolean = true,
    val homeCardSectionExpanded: Boolean = true,
    val colorsSectionExpanded: Boolean = true,
    val customHomeTitle: String = "",
    val customTexts: Map<String, String> = emptyMap(),
    val themeStoreBaseUrl: String = "",
    val themeStoreToken: String = "",
    val themeStoreAuthorId: String = "",
    val themeStoreAuthorName: String = "",
    val themeStoreAdminUrl: String = "",
    val themeStoreExtraSources: List<com.sukisu.ultra.data.model.ThemeStoreSourceConfig> = emptyList(),
    val homeCardImagePath: String = "",
    val hideHomeCardStatusText: Boolean = false,
    val hideHomeCardDecoration: Boolean = false,
    val homeCardStickers: List<HomeCardSticker> = emptyList(),

    val pendingImportTheme: com.sukisu.ultra.ui.util.ImportedTheme? = null,
    val showThemeImportDialog: Boolean = false,
)

/**
 * What a theme package import or export covers. The groups mirror the appearance page's
 * collapsible sections, and the sub-options let users pick individual parts of a group.
 */
@Immutable
data class ThemePackageOptions(
    val colors: Boolean = true,
    val backgroundImage: Boolean = true,
    val backgroundAppearance: Boolean = true,
    val homeCardImage: Boolean = true,
    val stickers: Boolean = true,
    val homeCardDisplay: Boolean = true,
    val appIcon: Boolean = true,
    val customTexts: Boolean = true,
    val customTextGroups: Set<CustomTextGroup> = CustomTextGroup.entries.toSet(),
    val customConfig: Boolean = true,
)

val ThemePackageOptionsSaver = listSaver<ThemePackageOptions, Boolean>(
    save = {
        listOf(
            it.colors,
            it.backgroundImage,
            it.backgroundAppearance,
            it.homeCardImage,
            it.stickers,
            it.homeCardDisplay,
            it.appIcon,
            it.customTexts,
            it.customTextGroups.contains(CustomTextGroup.HOME),
            it.customTextGroups.contains(CustomTextGroup.PAGE_MAIN),
            it.customTextGroups.contains(CustomTextGroup.PAGE_FEATURE),
            it.customTextGroups.contains(CustomTextGroup.SETTINGS),
            it.customConfig,
        )
    },
    restore = {
        ThemePackageOptions(
            colors = it[0],
            backgroundImage = it[1],
            backgroundAppearance = it[2],
            homeCardImage = it[3],
            stickers = it[4],
            homeCardDisplay = it[5],
            appIcon = it[6],
            customTexts = it[7],
            customTextGroups = buildSet {
                if (it.getOrElse(8) { true }) add(CustomTextGroup.HOME)
                if (it.getOrElse(9) { true }) add(CustomTextGroup.PAGE_MAIN)
                if (it.getOrElse(10) { true }) add(CustomTextGroup.PAGE_FEATURE)
                if (it.getOrElse(11) { true }) add(CustomTextGroup.SETTINGS)
            },
            customConfig = it.getOrElse(12) { true },
        )
    },
)

@Immutable
data class SettingsScreenActions(
    val onSetCheckUpdate: (Boolean) -> Unit,
    val onSetCheckCiUpdate: (Boolean) -> Unit,
    val onSetCheckModuleUpdate: (Boolean) -> Unit,
    val onSetAutoDeleteModuleZip: (Boolean) -> Unit,
    val onOpenTheme: () -> Unit,
    val onSetUiModeIndex: (Int) -> Unit,
    val onOpenProfileTemplate: () -> Unit,
    val onSetLanguage: (String) -> Unit,
    val onSetSuCompatMode: (Int) -> Unit,
    val onSetKernelUmountEnabled: (Boolean) -> Unit,
    val onSetSelinuxHideEnabled: (Boolean) -> Unit,
    val onSetAvcSpoofEnabled: (Boolean) -> Unit,
    val onSetMountHideEnabled: (Boolean) -> Unit,
    val onSetSulogEnabled: (Boolean) -> Unit,
    val onSetAdbRootEnabled: (Boolean) -> Unit,
    val onSetShellSuAdbOnlyEnabled: (Boolean) -> Unit,
    val onSetDefaultUmountModules: (Boolean) -> Unit,
    val onSetEnableWebDebugging: (Boolean) -> Unit,
    val onSetAutoJailbreak: (Boolean) -> Unit,
    val onSetUseSoftReboot: (Boolean) -> Unit,
    val onOpenAbout: () -> Unit,
    val onOpenTools: () -> Unit,
    val onOpenSusfsConfig: () -> Unit,
    val onOpenExtensions: () -> Unit,
)
