package com.sukisu.ultra.ui.screen.colorpalette

import androidx.compose.runtime.Immutable
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.sukisu.ultra.ui.screen.settings.SettingsUiState
import com.sukisu.ultra.ui.screen.settings.ThemePackageOptions
import com.sukisu.ultra.ui.theme.ColorMode
import com.sukisu.ultra.ui.util.HomeCardImageStyle
import com.sukisu.ultra.ui.util.HomeCardSticker
import com.sukisu.ultra.ui.util.HomeCardStickerTransform
import com.sukisu.ultra.ui.util.HomeLayout
import com.sukisu.ultra.ui.util.HomeStatusAlignment
import com.sukisu.ultra.ui.util.ResolvedAppearance
import com.sukisu.ultra.ui.util.BottomBarIconSlot

/**
 * Everything the appearance page renders, resolved once in
 * [com.sukisu.ultra.ui.viewmodel.SettingsViewModel] instead of on every recomposition.
 *
 * The fields are plain values, so [SettingsUiState] no longer needs to be read from the screen
 * to build the preview, and the enum parsing that used to run per recomposition happens when the
 * setting actually changes.
 */
@Immutable
data class ColorPaletteUiState(
    val loading: Boolean = true,
    // Preview inputs, all committed values; the in-flight slider drafts are folded in on top.
    val keyColor: Int = 0,
    val miuixMonet: Boolean = false,
    val currentColorMode: ColorMode = ColorMode.SYSTEM,
    val currentPaletteStyle: PaletteStyle = PaletteStyle.TonalSpot,
    val currentColorSpec: ColorSpec.SpecVersion = ColorSpec.SpecVersion.SPEC_2025,
    val backgroundPath: String = "",
    val backgroundUpdatedAt: Long = 0L,
    val useSystemWallpaper: Boolean = false,
    val isSystemWallpaperBusy: Boolean = false,
    val customBackgroundUri: String = "",
    val cardBackgroundAlphaPercent: Int = 60,
    val customBackgroundBlurPercent: Int = 50,
    val customBackgroundScrimPercent: Int = -35,
    val enableProgressiveBlur: Boolean = false,
    val enableFloatingBottomBar: Boolean = false,
    val enableFloatingBottomBarBlur: Boolean = false,
    val enableNavigationBadge: Boolean = true,
    val pageScale: Float = 1f,
    val customHomeTitle: String = "",
    val homeCardImagePath: String = "",
    val hideHomeCardStatusText: Boolean = false,
    val hideHomeCardDecoration: Boolean = false,
    val homeCardStickers: List<HomeCardSticker> = emptyList(),
    val homeLayout: HomeLayout = HomeLayout.CLASSIC,
    val homeStatusAlignment: HomeStatusAlignment = HomeStatusAlignment.START,
    val homeStatusScale: Float = 1f,
    val homePillScale: Float = 1f,
    val homeStatusWidthFraction: Float = 1f,
    val homeCardImageStyle: HomeCardImageStyle = HomeCardImageStyle.BANNER,
    val showHomeCardImageWithoutBackground: Boolean = false,
    
    val adaptiveThemeActive: Boolean = false,
    val adaptiveDraftLightCaptured: Boolean = false,
    val adaptiveDraftDarkCaptured: Boolean = false,
    val adaptiveDraftComplete: Boolean = false,
    // The rows below the preview.
    val themeMode: Int = 0,
    val colorStyle: String = "",
    val colorSpec: String = "",
    val extractColorFromBackground: Boolean = false,
    val backgroundAppearanceExpanded: Boolean = false,
    val backgroundSectionExpanded: Boolean = true,
    val themePackageSectionExpanded: Boolean = true,
    val appearanceSectionExpanded: Boolean = true,
    val homeCardSectionExpanded: Boolean = true,
    val colorsSectionExpanded: Boolean = true,
    val bottomBarSectionExpanded: Boolean = true,
    val interactionSectionExpanded: Boolean = true,
    val detailsSectionExpanded: Boolean = true,
    val showFullStatus: Boolean = false,
    val hideHomeWarnings: Boolean = false,
    val showAiHomeCard: Boolean = false,
    val moduleDescriptionMaxLines: Int = 4,
    /** Resolved static overlay used by the preview; null when no overlay is active. */
    val appearance: ResolvedAppearance? = null,
    val customAppearanceJson: String = "",
    val customColorsPresent: Boolean = false,
    val imageEffectsPresent: Boolean = false,
)

@Immutable
data class ColorPaletteScreenActions(
    val onBack: () -> Unit,
    val onSetThemeMode: (Int) -> Unit,
    val onSetMiuixMonet: (Boolean) -> Unit,
    val onSetKeyColor: (Int) -> Unit,
    val onSetColorMode: (ColorMode) -> Unit,
    val onSetColorStyle: (String) -> Unit,
    val onSetColorSpec: (String) -> Unit,
    val onSetEnableBlur: (Boolean) -> Unit,
    val onSetEnableProgressiveBlur: (Boolean) -> Unit,
    val onSetEnableFloatingBottomBar: (Boolean) -> Unit,
    val onSetEnableFloatingBottomBarBlur: (Boolean) -> Unit,
    val onSetEnableNavigationBadge: (Boolean) -> Unit,
    val onSetEnablePredictiveBack: (Boolean) -> Unit,
    val onSetEnableSwipeDismiss: (Boolean) -> Unit,
    val onSetPagerInterceptionMode: (Int) -> Unit,
    val onSetPageScale: (Float) -> Unit,
    val onSetModuleDescriptionMaxLines: (Int) -> Unit,
    val onSetShowFullStatus: (Boolean) -> Unit,
    val onSetHideHomeWarnings: (Boolean) -> Unit,
    val onSetShowAiHomeCard: (Boolean) -> Unit,
    val onOpenAppIcon: () -> Unit,
    val onSetBackgroundAppearanceExpanded: (Boolean) -> Unit = {},
    val onSetBackgroundSectionExpanded: (Boolean) -> Unit = {},
    val onSetThemePackageSectionExpanded: (Boolean) -> Unit = {},
    val onSetAppearanceSectionExpanded: (Boolean) -> Unit = {},
    val onSetHomeCardSectionExpanded: (Boolean) -> Unit = {},
    val onSetColorsSectionExpanded: (Boolean) -> Unit = {},
    val onSetBottomBarSectionExpanded: (Boolean) -> Unit = {},
    val onSetInteractionSectionExpanded: (Boolean) -> Unit = {},
    val onSetDetailsSectionExpanded: (Boolean) -> Unit = {},
    val onSetCustomHomeTitle: (String) -> Unit = {},
    val onPickCustomBackground: (android.content.Context, android.net.Uri) -> Unit = { _, _ -> },
    val onCropCurrentBackground: (android.content.Context) -> Unit = {},
    val onClearCustomBackground: (android.content.Context) -> Unit = {},
    val onPickHomeCardImage: (android.content.Context, android.net.Uri) -> Unit = { _, _ -> },
    val onClearHomeCardImage: () -> Unit = {},
    val onSetHideHomeCardStatusText: (Boolean) -> Unit = {},
    val onSetHideHomeCardDecoration: (Boolean) -> Unit = {},
    val onSetHomeLayout: (HomeLayout) -> Unit = {},
    val onSetHomeStatusAlignment: (HomeStatusAlignment) -> Unit = {},
    val onSetHomeStatusScale: (Float) -> Unit = {},
    val onSetHomePillScale: (Float) -> Unit = {},
    val onSetHomeStatusWidthFraction: (Float) -> Unit = {},
    val onSetHomeCardImageStyle: (HomeCardImageStyle) -> Unit = {},
    val onSetShowHomeCardImageWithoutBackground: (Boolean) -> Unit = {},
    val onPickHomeCardSticker: (android.content.Context, android.net.Uri) -> Unit = { _, _ -> },
    val onRemoveHomeCardSticker: (Int) -> Unit = {},
    val onUpdateHomeCardStickerTransform: (Int, HomeCardStickerTransform) -> Unit = { _, _ -> },
    val onSetUseSystemWallpaper: (android.content.Context, Boolean) -> Unit = { _, _ -> },
    val onSetExtractColorFromBackground: (Boolean) -> Unit = {},
    val onSetCardBackgroundAlphaPercent: (Int) -> Unit = {},
    val onSetCustomBackgroundBlurPercent: (Int) -> Unit = {},
    val onSetCustomBackgroundScrimPercent: (Int) -> Unit = {},
    val onExportTheme: (android.content.Context, android.net.Uri, ThemePackageOptions) -> Unit = { _, _, _ -> },
    val onImportTheme: (android.content.Context, android.net.Uri) -> Unit = { _, _ -> },
    val onExportImages: (android.content.Context, android.net.Uri) -> Unit = { _, _ -> },
    val onExportCustomBackground: (android.content.Context, android.net.Uri) -> Unit = { _, _ -> },
    val onConfirmImportTheme: (android.content.Context, ThemePackageOptions) -> Unit = { _, _ -> },
    val onDismissImportThemeDialog: () -> Unit = {},
    val onSetCustomText: (String, String) -> Unit = { _, _ -> },
    val onResetAllCustomTexts: () -> Unit = {},
    val onOpenCustomTexts: () -> Unit = {},
    val onOpenThemeStore: () -> Unit = {},
    val onOpenAdaptiveThemeBuilder: () -> Unit = {},
    val onResetBackgroundAppearance: () -> Unit = {},
    val onClearAllAppearance: () -> Unit = {},
    val onOpenAppearanceEditor: () -> Unit = {},
    val onPickBottomBarIcon: (android.content.Context, BottomBarIconSlot, android.net.Uri) -> Unit =
        { _, _, _ -> },
    val onClearBottomBarIcon: (android.content.Context, BottomBarIconSlot) -> Unit = { _, _ -> },
    val onUploadTheme: (android.content.Context, ThemePackageOptions) -> Unit = { _, _ -> },
)
