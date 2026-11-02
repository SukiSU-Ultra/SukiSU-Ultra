package com.sukisu.ultra.ui.screen.colorpalette

import com.sukisu.ultra.ui.component.miuix.MiuixTextButtonAffectedByBackground
import com.sukisu.ultra.ai.api.R as AiR
import com.sukisu.ultra.ai.api.AiFeatureBridge
import android.net.Uri
import java.io.File
import android.os.Build
import com.sukisu.ultra.ui.util.customText
import com.sukisu.ultra.ui.util.customTextGroupsIn
import com.sukisu.ultra.ui.util.CustomTextKey
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.relocation.BringIntoViewRequester
import androidx.compose.foundation.relocation.bringIntoViewRequester
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.captionBar
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AutoAwesome
import androidx.compose.material.icons.automirrored.rounded.MenuOpen
import androidx.compose.material.icons.rounded.AspectRatio
import androidx.compose.material.icons.rounded.BlurOn
import androidx.compose.material.icons.rounded.CallToAction
import androidx.compose.material.icons.rounded.Colorize
import androidx.compose.material.icons.rounded.Crop
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Image
import androidx.compose.material.icons.rounded.KeyboardArrowDown
import androidx.compose.material.icons.rounded.DesignServices
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.material.icons.rounded.FileUpload
import androidx.compose.material.icons.rounded.Home
import androidx.compose.material.icons.rounded.Pin
import androidx.compose.material.icons.rounded.Palette
import androidx.compose.material.icons.rounded.Restore
import androidx.compose.material.icons.rounded.Star
import androidx.compose.material.icons.rounded.Style
import androidx.compose.material.icons.rounded.Wallpaper
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material.icons.rounded.WaterDrop
import androidx.compose.material.icons.rounded.Swipe
import androidx.compose.material.icons.rounded.ViewCarousel
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import kotlin.math.roundToInt
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.component.miuix.AppScaffold
import com.sukisu.ultra.ui.component.miuix.ScaleDialog
import com.sukisu.ultra.ui.component.HomeCardStickerStage
import com.sukisu.ultra.ui.component.HomeCardStickerThumbnail
import com.sukisu.ultra.ui.component.themeimport.ThemeExportDialog
import com.sukisu.ultra.ui.screen.appicon.BuiltinAppIconPreview
import com.sukisu.ultra.ui.screen.settings.ThemePackageOptions
import com.sukisu.ultra.ui.screen.settings.ThemePackageOptionsSaver
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.theme.keyColorOptions
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.BuiltinAppIcons
import com.sukisu.ultra.ui.util.HomeCardSticker
import com.sukisu.ultra.ui.util.HomeCardStickerTransform
import com.sukisu.ultra.ui.util.ImageStorage
import com.sukisu.ultra.ui.util.ThemePackageStorage
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import com.sukisu.ultra.ui.viewmodel.SettingsViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.HorizontalDivider
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Slider
import top.yukonga.miuix.kmp.basic.SliderDefaults
import top.yukonga.miuix.kmp.basic.TabRowDefaults
import top.yukonga.miuix.kmp.basic.TabRowWithContour
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import com.sukisu.ultra.ui.theme.backgroundAwareCardColors
import com.sukisu.ultra.ui.theme.backgroundAwareColor
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.preference.OverlayDropdownPreference
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic
import kotlin.time.Duration.Companion.milliseconds

@Composable
fun ColorPaletteScreenMiuix(
    state: ColorPaletteUiState,
    actions: ColorPaletteScreenActions,
    section: String? = null,
) {
    val scrollBehavior = MiuixScrollBehavior()
    val sectionRequesters = remember { mutableMapOf<String, BringIntoViewRequester>() }
    fun sectionRequester(anchor: String): BringIntoViewRequester =
        sectionRequesters.getOrPut(anchor) { BringIntoViewRequester() }

    LaunchedEffect(section) {
        val anchor = section?.trim()?.lowercase()?.replace('-', '_')?.takeIf { it.isNotEmpty() }
            ?: return@LaunchedEffect
        kotlinx.coroutines.delay(120.milliseconds)
        val target = sectionRequesters[anchor]
            ?: sectionRequesters[when (anchor) {
                "color_mode", "theme_mode", "palette" -> "colors"
                "sticker" -> "home_card"
                "gestures", "predictive_back", "scale" -> "behavior"
                else -> anchor
            }]
            ?: sectionRequesters["appearance"]
            ?: return@LaunchedEffect
        target.bringIntoView()
    }
    val enableBlurState = LocalEnableBlur.current
    val backdrop = rememberBlurBackdrop(enableBlurState)
    val blurActive = backdrop != null
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val barColor = if (blurActive || hasCustomBackground) Color.Transparent else colorScheme.surface
    val isDark = state.currentColorMode.isDark ||
        state.currentColorMode.isSystem && isSystemInDarkTheme()
    val context = LocalContext.current
    // Rows outside the preview still read the shared settings (app icon, predictive back, ...).
    val uiState by viewModel<SettingsViewModel>().uiState.collectAsStateWithLifecycle()
    // Live drag values: the preview follows the sliders before they commit to the repository.
    // The drafts start from the committed value but are not reset by it, so a slider does not
    // jump back while its own commit round-trips.
    var cardAlphaDraft by remember { mutableFloatStateOf(state.cardBackgroundAlphaPercent.toFloat()) }
    var blurDraft by remember { mutableFloatStateOf(state.customBackgroundBlurPercent.toFloat()) }
    var scrimDraft by remember { mutableFloatStateOf(state.customBackgroundScrimPercent.toFloat()) }
    val sliderCommitted = remember { mutableIntStateOf(0) }
    // Values changed outside the sliders (import, reset, AI bridge) replace the drafts. Reads the
    // counter so finishing a drag does not re-run this and yank the thumbs.
    LaunchedEffect(
        state.cardBackgroundAlphaPercent,
        state.customBackgroundBlurPercent,
        state.customBackgroundScrimPercent,
        sliderCommitted.intValue,
    ) {
        if (cardAlphaDraft.roundToInt() != state.cardBackgroundAlphaPercent) {
            cardAlphaDraft = state.cardBackgroundAlphaPercent.toFloat()
        }
        if (blurDraft.roundToInt() != state.customBackgroundBlurPercent) {
            blurDraft = state.customBackgroundBlurPercent.toFloat()
        }
        if (scrimDraft.roundToInt() != state.customBackgroundScrimPercent) {
            scrimDraft = state.customBackgroundScrimPercent.toFloat()
        }
    }
    // Same trap as the drafts: a remembered value computed once would freeze the preview at the
    // first frame, so this is remembered on the committed inputs and reads the live drafts.
    val previewSpec: ThemePreviewSpec = remember(
        state.keyColor,
        state.miuixMonet,
        state.currentColorMode,
        isDark,
        state.currentPaletteStyle,
        state.currentColorSpec,
        state.backgroundPath,
        state.backgroundUpdatedAt,
        cardAlphaDraft.roundToInt(),
        blurDraft.roundToInt(),
        scrimDraft.roundToInt(),
        state.enableFloatingBottomBar,
        state.enableFloatingBottomBarBlur,
        state.enableNavigationBadge,
        state.pageScale,
        state.customHomeTitle,
        state.homeCardImagePath,
        state.hideHomeCardStatusText,
        state.hideHomeCardDecoration,
        state.homeCardStickers,
    ) {
        ThemePreviewSpec(
            keyColor = state.keyColor,
            isDark = isDark,
            miuixMonet = state.miuixMonet,
            paletteStyle = state.currentPaletteStyle,
            colorSpec = state.currentColorSpec,
            backgroundPath = state.backgroundPath,
            backgroundUpdatedAt = state.backgroundUpdatedAt,
            cardAlpha = cardAlphaDraft / 100f,
            backgroundBlurPercent = blurDraft.roundToInt(),
            backgroundScrimPercent = scrimDraft.roundToInt(),
            floatingBottomBar = state.enableFloatingBottomBar,
            floatingBottomBarBlur = state.enableFloatingBottomBarBlur,
            navigationBadge = state.enableNavigationBadge,
            pageScale = state.pageScale,
            customHomeTitle = state.customHomeTitle,
            homeCardImagePath = state.homeCardImagePath,
            hideHomeCardText = state.hideHomeCardStatusText,
            hideHomeCardDecoration = state.hideHomeCardDecoration,
            homeCardStickers = state.homeCardStickers,
        )
    }
    var showExportDialog by rememberSaveable { mutableStateOf(false) }
    var pendingExportOptions by rememberSaveable(stateSaver = ThemePackageOptionsSaver) {
        mutableStateOf(ThemePackageOptions())
    }
    val exportThemeLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("*/*")
    ) { uri: Uri? ->
        uri?.let { actions.onExportTheme(context, it, pendingExportOptions) }
    }
    val exportImagesLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("*/*")
    ) { uri: Uri? ->
        uri?.let { actions.onExportImages(context, it) }
    }
    val importThemeLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri?.let { actions.onImportTheme(context, it) }
    }
    val homeCardImageLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.PickVisualMedia()
    ) { uri: Uri? ->
        uri?.let { actions.onPickHomeCardImage(context, it) }
    }
    val homeCardStickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.PickVisualMedia()
    ) { uri: Uri? ->
        uri?.let { actions.onPickHomeCardSticker(context, it) }
    }

    AppScaffold(
        topBar = {
            // Hand the scroll behavior to BlurredBar: without it the bar blurs/tints at the
            // top of the list as if it were already scrolled.
            BlurredBar(backdrop, scrollBehavior = scrollBehavior) {
                TopAppBar(
                    color = barColor,
                    title = customText(CustomTextKey.PAGE_APPEARANCE),
                    navigationIcon = {
                        IconButton(
                            onClick = actions.onBack
                        ) {
                            val layoutDirection = LocalLayoutDirection.current
                            Icon(
                                modifier = Modifier.graphicsLayer {
                                    if (layoutDirection == LayoutDirection.Rtl) scaleX = -1f
                                },
                                imageVector = MiuixIcons.Back,
                                contentDescription = null,
                                tint = colorScheme.onBackground
                            )
                        }
                    },
                    scrollBehavior = scrollBehavior,
                )
            }
        },
        popupHost = { },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal)
    ) { innerPadding ->
        val showScaleDialog = rememberSaveable { mutableStateOf(false) }
        val showResetThemeDialog = rememberSaveable { mutableStateOf(false) }
        val showClearAllDialog = rememberSaveable { mutableStateOf(false) }
        var showHomeTitleDialog by rememberSaveable { mutableStateOf(false) }
        var homeTitleDraft by rememberSaveable { mutableStateOf("") }
        val appearanceExpanded = state.backgroundAppearanceExpanded
        val backgroundSectionExpanded = state.backgroundSectionExpanded
        val themePackageSectionExpanded = state.themePackageSectionExpanded
        val appearanceSectionExpanded = state.appearanceSectionExpanded
        val homeCardSectionExpanded = state.homeCardSectionExpanded
        val colorsSectionExpanded = state.colorsSectionExpanded
        var stickerEditorExpanded by rememberSaveable { mutableStateOf(false) }
        var stickerDraft by remember { mutableStateOf(state.homeCardStickers) }
        var selectedSticker by rememberSaveable { mutableIntStateOf(0) }
        var lastStickerCount by remember { mutableIntStateOf(state.homeCardStickers.size) }
        LaunchedEffect(state.homeCardStickers) {
            stickerDraft = state.homeCardStickers
        }
        LaunchedEffect(stickerDraft.size) {
            if (stickerDraft.size > lastStickerCount) {
                selectedSticker = stickerDraft.lastIndex.coerceAtLeast(0)
            }
            lastStickerCount = stickerDraft.size
            if (selectedSticker > stickerDraft.lastIndex) {
                selectedSticker = stickerDraft.lastIndex.coerceAtLeast(0)
            }
        }

        Box(modifier = if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxHeight()
                    .scrollEndHaptic()
                    .overScrollVertical()
                    .nestedScroll(scrollBehavior.nestedScrollConnection)
                    .padding(horizontal = 12.dp),
                contentPadding = innerPadding,
                overscrollEffect = null,
            ) {
                item {
                    Spacer(modifier = Modifier.height(20.dp))
                    ThemePreviewMiuix(
                        spec = previewSpec,
                        modifier = Modifier.bringIntoViewRequester(sectionRequester("preview")),
                    )
                    Spacer(modifier = Modifier.height(28.dp))

                    val pickImageLauncher = rememberLauncherForActivityResult(
                        contract = ActivityResultContracts.PickVisualMedia()
                    ) { uri: Uri? ->
                        uri?.let { actions.onPickCustomBackground(context, it) }
                    }
                    val hasCustomBg = state.customBackgroundUri.isNotEmpty()
                    val usingSystemWallpaper = state.useSystemWallpaper

                    AppCard(
                        modifier = Modifier
                            .bringIntoViewRequester(sectionRequester("background"))
                            .padding(bottom = 12.dp)
                            .fillMaxWidth(),
                        colors = backgroundAwareCardColors(),
                    ) {
                        MiuixSectionHeader(
                            title = stringResource(R.string.settings_section_background),
                            summary = stringResource(R.string.settings_section_background_summary),
                            icon = Icons.Rounded.Wallpaper,
                            expanded = backgroundSectionExpanded,
                            onClick = {
                                actions.onSetBackgroundSectionExpanded(!backgroundSectionExpanded)
                            },
                        )
                        AnimatedVisibility(
                            visible = backgroundSectionExpanded,
                            enter = expandVertically() + fadeIn(),
                            exit = shrinkVertically() + fadeOut(),
                        ) {
                            Column {
                                HorizontalDivider()
                                SwitchPreference(
                                    title = stringResource(id = R.string.settings_use_system_wallpaper),
                                    summary = stringResource(
                                        id = if (state.isSystemWallpaperBusy) {
                                            R.string.settings_use_system_wallpaper_reading
                                        } else {
                                            R.string.settings_use_system_wallpaper_summary
                                        }
                                    ),
                                    startAction = {
                                        Icon(
                                            imageVector = Icons.Rounded.Wallpaper,
                                            modifier = Modifier.padding(end = 6.dp),
                                            contentDescription = stringResource(id = R.string.settings_use_system_wallpaper),
                                            tint = colorScheme.onBackground
                                        )
                                    },
                                    checked = usingSystemWallpaper,
                                    enabled = !state.isSystemWallpaperBusy,
                                    onCheckedChange = { actions.onSetUseSystemWallpaper(context, it) },
                                )

                                if (!usingSystemWallpaper) {
                                    HorizontalDivider()
                                    BasicComponent(
                                        title = stringResource(id = R.string.settings_custom_background),
                                        summary = stringResource(id = R.string.settings_custom_background_summary),
                                        startAction = {
                                            Icon(
                                                imageVector = Icons.Rounded.Image,
                                                modifier = Modifier.padding(end = 6.dp),
                                                contentDescription = stringResource(id = R.string.settings_custom_background),
                                                tint = colorScheme.onBackground
                                            )
                                        },
                                        endActions = {
                                            if (hasCustomBg) {
                                                MiuixTextButtonAffectedByBackground(
                                                    text = stringResource(id = R.string.settings_clear),
                                                    onClick = { actions.onClearCustomBackground(context) }
                                                )
                                            }
                                        },
                                        onClick = {
                                            pickImageLauncher.launch(
                                                PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)
                                            )
                                        }
                                    )

                                    if (hasCustomBg) {
                                        HorizontalDivider()
                                        BasicComponent(
                                            title = stringResource(id = R.string.settings_crop_background),
                                            summary = stringResource(id = R.string.settings_crop_background_summary),
                                            startAction = {
                                                Icon(
                                                    imageVector = Icons.Rounded.Crop,
                                                    modifier = Modifier.padding(end = 6.dp),
                                                    contentDescription = stringResource(id = R.string.settings_crop_background),
                                                    tint = colorScheme.onBackground
                                                )
                                            },
                                            onClick = { actions.onCropCurrentBackground(context) }
                                        )
                                    }
                                }

                                val hasCustomBgFile = hasCustomBg && !usingSystemWallpaper
                                val hasCardBgFile = state.homeCardImagePath.isNotBlank() && File(state.homeCardImagePath).isFile
                                val hasStickerFile = state.homeCardStickers.any { File(it.path).isFile }
                                if (hasCustomBgFile || hasCardBgFile || hasStickerFile) {
                                    HorizontalDivider()
                                    ArrowPreference(
                                        title = stringResource(id = R.string.settings_export_images),
                                        summary = stringResource(id = R.string.settings_export_images_summary),
                                        startAction = {
                                            Icon(
                                                imageVector = Icons.Rounded.FileDownload,
                                                modifier = Modifier.padding(end = 6.dp),
                                                contentDescription = stringResource(id = R.string.settings_export_images),
                                                tint = colorScheme.onBackground
                                            )
                                        },
                                        onClick = {
                                            val fileName = ImageStorage.exportImagesFileName(
                                                hasBackground = hasCustomBgFile,
                                                hasCardBackground = hasCardBgFile,
                                                stickerCount = state.homeCardStickers.count { File(it.path).isFile },
                                            )
                                            exportImagesLauncher.launch(fileName)
                                        }
                                    )
                                }

                                if (usingSystemWallpaper || hasCustomBg) {
                                    HorizontalDivider()
                                    SwitchPreference(
                                        title = stringResource(id = R.string.settings_extract_background_color),
                                        // Without Monet the Miuix theme ignores the seed entirely, so the
                                        // switch would look enabled while changing nothing.
                                        summary = stringResource(
                                            id = if (state.miuixMonet) {
                                                R.string.settings_extract_background_color_summary
                                            } else {
                                                R.string.settings_extract_background_color_disabled
                                            }
                                        ),
                                        startAction = {
                                            Icon(
                                                imageVector = Icons.Rounded.Colorize,
                                                modifier = Modifier.padding(end = 6.dp),
                                                contentDescription = stringResource(id = R.string.settings_extract_background_color),
                                                tint = colorScheme.onBackground
                                            )
                                        },
                                        checked = state.extractColorFromBackground,
                                        onCheckedChange = actions.onSetExtractColorFromBackground,
                                    )
                                    HorizontalDivider()
                                    BasicComponent(
                                        title = stringResource(id = R.string.settings_background_appearance),
                                        summary = stringResource(id = R.string.settings_background_appearance_summary),
                                        startAction = {
                                            Icon(
                                                imageVector = Icons.Rounded.Tune,
                                                modifier = Modifier.padding(end = 6.dp),
                                                contentDescription = stringResource(id = R.string.settings_background_appearance),
                                                tint = colorScheme.onBackground
                                            )
                                        },
                                        endActions = {
                                            Icon(
                                                imageVector = Icons.Rounded.KeyboardArrowDown,
                                                contentDescription = null,
                                                modifier = Modifier.graphicsLayer {
                                                    rotationZ = if (appearanceExpanded) 180f else 0f
                                                },
                                                tint = colorScheme.onBackground
                                            )
                                        },
                                        onClick = {
                                            actions.onSetBackgroundAppearanceExpanded(!appearanceExpanded)
                                        },
                                    )
                                    AnimatedVisibility(
                                        visible = appearanceExpanded,
                                        enter = expandVertically() + fadeIn(),
                                        exit = shrinkVertically() + fadeOut(),
                                    ) {
                                        Column {
                                            HorizontalDivider()
                                            MiuixBackgroundSliderSection(
                                                title = stringResource(id = R.string.settings_card_background_alpha),
                                                summary = stringResource(
                                                    id = R.string.settings_card_background_alpha_summary,
                                                    cardAlphaDraft.roundToInt(),
                                                ),
                                                value = cardAlphaDraft,
                                                valueRange = 10f..91f,
                                                onValueChange = { cardAlphaDraft = it },
                                                onValueChangeFinished = {
                                                    val percent = cardAlphaDraft.roundToInt()
                                                    cardAlphaDraft = percent.toFloat()
                                                    sliderCommitted.intValue += 1
                                                    actions.onSetCardBackgroundAlphaPercent(percent)
                                                },
                                            )
                                            HorizontalDivider()
                                            MiuixBackgroundSliderSection(
                                                title = stringResource(id = R.string.settings_background_blur),
                                                summary = stringResource(
                                                    id = R.string.settings_background_blur_summary,
                                                    blurDraft.roundToInt(),
                                                ),
                                                value = blurDraft,
                                                valueRange = 0f..100f,
                                                onValueChange = { blurDraft = it },
                                                onValueChangeFinished = {
                                                    val percent = blurDraft.roundToInt()
                                                    blurDraft = percent.toFloat()
                                                    sliderCommitted.intValue += 1
                                                    actions.onSetCustomBackgroundBlurPercent(percent)
                                                },
                                            )
                                            HorizontalDivider()
                                            MiuixBackgroundSliderSection(
                                                title = stringResource(id = R.string.settings_background_scrim),
                                                summary = stringResource(
                                                    id = R.string.settings_background_scrim_summary,
                                                    scrimDraft.roundToInt(),
                                                ),
                                                value = scrimDraft,
                                                valueRange = -100f..100f,
                                                onValueChange = { scrimDraft = it },
                                                onValueChangeFinished = {
                                                    val percent = scrimDraft.roundToInt()
                                                    scrimDraft = percent.toFloat()
                                                    sliderCommitted.intValue += 1
                                                    actions.onSetCustomBackgroundScrimPercent(percent)
                                                },
                                                startLabel = stringResource(id = R.string.settings_background_scrim_darker),
                                                endLabel = stringResource(id = R.string.settings_background_scrim_lighter),
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }

                    AppCard(
                        modifier = Modifier
                            .bringIntoViewRequester(sectionRequester("appearance"))
                            .fillMaxWidth(),
                    ) {
                        MiuixSectionHeader(
                            title = stringResource(R.string.settings_section_appearance),
                            summary = stringResource(R.string.settings_section_appearance_summary),
                            icon = Icons.Rounded.Home,
                            expanded = appearanceSectionExpanded,
                            onClick = {
                                actions.onSetAppearanceSectionExpanded(!appearanceSectionExpanded)
                            },
                        )
                        AnimatedVisibility(
                            visible = appearanceSectionExpanded,
                            enter = expandVertically() + fadeIn(),
                            exit = shrinkVertically() + fadeOut(),
                        ) {
                            Column {
                                HorizontalDivider()
                                SwitchPreference(
                                    title = stringResource(id = R.string.settings_show_fullstatus),
                                    summary = stringResource(id = R.string.settings_show_fullstatus_summary),
                                    startAction = {
                                        Icon(
                                            Icons.Rounded.Fingerprint,
                                            modifier = Modifier.padding(end = 6.dp),
                                            contentDescription = stringResource(id = R.string.settings_show_fullstatus),
                                            tint = colorScheme.onBackground
                                        )
                                    },
                                    checked = state.showFullStatus,
                                    onCheckedChange = {
                                        actions.onSetShowFullStatus(it)
                                    }
                                )

                                SwitchPreference(
                                    title = stringResource(id = R.string.settings_hide_home_warnings),
                                    summary = stringResource(id = R.string.settings_hide_home_warnings_summary),
                                    startAction = {
                                        Icon(
                                            Icons.Rounded.Warning,
                                            modifier = Modifier.padding(end = 6.dp),
                                            contentDescription = stringResource(id = R.string.settings_hide_home_warnings),
                                            tint = colorScheme.onBackground
                                        )
                                    },
                                    checked = state.hideHomeWarnings,
                                    onCheckedChange = {
                                        actions.onSetHideHomeWarnings(it)
                                    }
                                )

                                if (AiFeatureBridge.isAvailable) {
                                    SwitchPreference(
                                        title = stringResource(id = AiR.string.ai_show_home_card),
                                        summary = stringResource(id = AiR.string.ai_show_home_card_summary),
                                        startAction = {
                                            Icon(
                                                Icons.Rounded.AutoAwesome,
                                                modifier = Modifier.padding(end = 6.dp),
                                                contentDescription = stringResource(id = AiR.string.ai_show_home_card),
                                                tint = colorScheme.onBackground
                                            )
                                        },
                                        checked = state.showAiHomeCard,
                                        onCheckedChange = {
                                            actions.onSetShowAiHomeCard(it)
                                        }
                                    )
                                }

                                ArrowPreference(
                                    title = customText(CustomTextKey.PAGE_APP_ICON),
                                    summary = stringResource(
                                        id = BuiltinAppIcons.find(uiState.appIconId).nameRes
                                    ),
                                    startAction = {
                                        BuiltinAppIconPreview(
                                            icon = BuiltinAppIcons.find(uiState.appIconId),
                                            modifier = Modifier
                                                .padding(end = 8.dp)
                                                .size(28.dp)
                                                .clip(RoundedCornerShape(8.dp)),
                                        )
                                    },
                                    onClick = actions.onOpenAppIcon,
                                )
                                val customTextsTitle = customText(CustomTextKey.PAGE_CUSTOM_TEXTS)
                                ArrowPreference(
                                    title = customTextsTitle,
                                    summary = stringResource(id = R.string.settings_custom_texts_summary),
                                    startAction = {
                                        Icon(
                                            Icons.Rounded.Edit,
                                            modifier = Modifier.padding(end = 8.dp),
                                            contentDescription = customTextsTitle,
                                            tint = colorScheme.onBackground,
                                        )
                                    },
                                    onClick = actions.onOpenCustomTexts,
                                )
                            }
                        }
                    }
                    AppCard(
                        modifier = Modifier
                            .bringIntoViewRequester(sectionRequester("home_card"))
                            .padding(top = 12.dp)
                            .fillMaxWidth(),
                    ) {
                        MiuixSectionHeader(
                            title = stringResource(R.string.settings_section_home_card),
                            summary = stringResource(R.string.settings_section_home_card_summary),
                            icon = Icons.Rounded.Home,
                            expanded = homeCardSectionExpanded,
                            onClick = {
                                actions.onSetHomeCardSectionExpanded(!homeCardSectionExpanded)
                            },
                        )
                        AnimatedVisibility(
                            visible = homeCardSectionExpanded,
                            enter = expandVertically() + fadeIn(),
                            exit = shrinkVertically() + fadeOut(),
                        ) {
                            Column {
                                HorizontalDivider()
                                ArrowPreference(
                                    title = stringResource(id = R.string.settings_home_card_image),
                                    summary = if (state.homeCardImagePath.isBlank()) {
                                        stringResource(R.string.settings_home_card_image_default)
                                    } else {
                                        stringResource(R.string.settings_home_card_image_set)
                                    },
                                    startAction = {
                                        Icon(
                                            Icons.Rounded.Image,
                                            modifier = Modifier.padding(end = 8.dp),
                                            contentDescription = stringResource(R.string.settings_home_card_image),
                                            tint = colorScheme.onBackground,
                                        )
                                    },
                                    onClick = {
                                        homeCardImageLauncher.launch(
                                            PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)
                                        )
                                    },
                                )
                                BasicComponent(
                                    title = stringResource(R.string.settings_home_card_sticker),
                                    summary = (if (state.homeCardStickers.isEmpty()) {
                                        stringResource(R.string.settings_home_card_sticker_not_set)
                                    } else {
                                        stringResource(
                                            R.string.settings_home_card_sticker_count,
                                            state.homeCardStickers.size,
                                        )
                                    }) + " · " + stringResource(R.string.settings_home_card_sticker_summary),
                                    startAction = {
                                        Icon(
                                            Icons.Rounded.Star,
                                            modifier = Modifier.padding(end = 8.dp),
                                            contentDescription = stringResource(R.string.settings_home_card_sticker),
                                            tint = colorScheme.onBackground,
                                        )
                                    },
                                    endActions = {
                                        Icon(
                                            Icons.Rounded.KeyboardArrowDown,
                                            contentDescription = null,
                                            modifier = Modifier.graphicsLayer {
                                                rotationZ = if (stickerEditorExpanded) 180f else 0f
                                            },
                                            tint = colorScheme.onBackground,
                                        )
                                    },
                                    onClick = { stickerEditorExpanded = !stickerEditorExpanded },
                                )
                                AnimatedVisibility(
                                    visible = stickerEditorExpanded,
                                    enter = expandVertically() + fadeIn(),
                                    exit = shrinkVertically() + fadeOut(),
                                ) {
                                    Column {
                                        HorizontalDivider()
                                        Column(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .padding(horizontal = 16.dp, vertical = 12.dp),
                                            verticalArrangement = Arrangement.spacedBy(12.dp),
                                        ) {
                                            HomeCardStickerStage(
                                                backgroundImagePath = state.homeCardImagePath,
                                                stickers = stickerDraft,
                                                selectedIndex = selectedSticker,
                                                onSelect = { selectedSticker = it },
                                                onTransformChange = { index, transform ->
                                                    stickerDraft = stickerDraft.mapIndexed { i, sticker ->
                                                        if (i == index) sticker.copy(transform = transform) else sticker
                                                    }
                                                },
                                                onTransformCommit = { index, transform ->
                                                    actions.onUpdateHomeCardStickerTransform(index, transform)
                                                },
                                                containerColor = colorScheme.secondaryContainer,
                                                contentColor = colorScheme.onSecondaryContainer,
                                                accentColor = colorScheme.primary,
                                                accentContentColor = colorScheme.onPrimary,
                                            )
                                            Row(
                                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                                verticalAlignment = Alignment.CenterVertically,
                                            ) {
                                                stickerDraft.forEachIndexed { index, sticker ->
                                                    HomeCardStickerThumbnail(
                                                        path = sticker.path,
                                                        selected = index == selectedSticker,
                                                        accentColor = colorScheme.primary,
                                                        onClick = { selectedSticker = index },
                                                    )
                                                }
                                            }
                                            Row(
                                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                                verticalAlignment = Alignment.CenterVertically,
                                            ) {
                                                if (stickerDraft.size < HomeCardSticker.MAX_COUNT) {
                                                    TextButton(
                                                        text = stringResource(R.string.settings_home_card_sticker_add),
                                                        onClick = {
                                                            homeCardStickerLauncher.launch(
                                                                PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)
                                                            )
                                                        },
                                                        minWidth = 0.dp,
                                                        minHeight = 0.dp,
                                                        cornerRadius = 100.dp,
                                                        insideMargin = PaddingValues(horizontal = 14.dp, vertical = 6.dp),
                                                        colors = ButtonDefaults.textButtonColorsPrimary(),
                                                    )
                                                } else {
                                                    Text(
                                                        text = stringResource(R.string.settings_home_card_sticker_limit),
                                                        fontSize = 12.sp,
                                                        color = colorScheme.onSurfaceVariantSummary,
                                                    )
                                                }
                                                if (stickerDraft.isNotEmpty()) {
                                                    TextButton(
                                                        text = stringResource(R.string.settings_home_card_sticker_remove),
                                                        onClick = {
                                                            actions.onRemoveHomeCardSticker(
                                                                selectedSticker.coerceIn(0, stickerDraft.lastIndex)
                                                            )
                                                        },
                                                        minWidth = 0.dp,
                                                        minHeight = 0.dp,
                                                        cornerRadius = 100.dp,
                                                        insideMargin = PaddingValues(horizontal = 14.dp, vertical = 6.dp),
                                                    )
                                                }
                                            }
                                        }
                                        if (stickerDraft.isNotEmpty()) {
                                            val editIndex = selectedSticker.coerceIn(0, stickerDraft.lastIndex)
                                            val editTransform = stickerDraft[editIndex].transform
                                            MiuixBackgroundSliderSection(
                                                title = stringResource(R.string.settings_home_card_sticker_rotation),
                                                summary = "${editTransform.rotation.roundToInt()}°",
                                                value = editTransform.rotation,
                                                valueRange = HomeCardStickerTransform.ROTATION_MIN..HomeCardStickerTransform.ROTATION_MAX,
                                                onValueChange = { value ->
                                                    stickerDraft = stickerDraft.mapIndexed { i, sticker ->
                                                        if (i == editIndex) {
                                                            sticker.copy(transform = sticker.transform.copy(rotation = value))
                                                        } else {
                                                            sticker
                                                        }
                                                    }
                                                },
                                                onValueChangeFinished = {
                                                    val latest = stickerDraft.getOrNull(editIndex)?.transform
                                                        ?: editTransform
                                                    val snapped = latest.copy(
                                                        rotation = latest.rotation.roundToInt().toFloat()
                                                    )
                                                    stickerDraft = stickerDraft.mapIndexed { i, sticker ->
                                                        if (i == editIndex) sticker.copy(transform = snapped) else sticker
                                                    }
                                                    actions.onUpdateHomeCardStickerTransform(editIndex, snapped)
                                                },
                                            )
                                            HorizontalDivider()
                                            MiuixBackgroundSliderSection(
                                                title = stringResource(R.string.settings_home_card_sticker_size),
                                                summary = "${(editTransform.size * 100).roundToInt()}%",
                                                value = editTransform.size,
                                                valueRange = HomeCardStickerTransform.SIZE_MIN..HomeCardStickerTransform.SIZE_MAX,
                                                onValueChange = { value ->
                                                    stickerDraft = stickerDraft.mapIndexed { i, sticker ->
                                                        if (i == editIndex) {
                                                            sticker.copy(transform = sticker.transform.copy(size = value))
                                                        } else {
                                                            sticker
                                                        }
                                                    }
                                                },
                                                onValueChangeFinished = {
                                                    val latest = stickerDraft.getOrNull(editIndex)?.transform
                                                        ?: editTransform
                                                    actions.onUpdateHomeCardStickerTransform(editIndex, latest)
                                                },
                                            )
                                        }
                                    }
                                }
                                if (state.homeCardImagePath.isNotBlank()) {
                                    SwitchPreference(
                                        title = stringResource(id = R.string.settings_hide_home_card_decoration),
                                        summary = stringResource(R.string.settings_hide_home_card_decoration_summary),
                                        startAction = {
                                            Icon(
                                                Icons.Rounded.Star,
                                                modifier = Modifier.padding(end = 8.dp),
                                                contentDescription = stringResource(R.string.settings_hide_home_card_decoration),
                                                tint = colorScheme.onBackground,
                                            )
                                        },
                                        checked = state.hideHomeCardDecoration,
                                        onCheckedChange = actions.onSetHideHomeCardDecoration,
                                    )
                                    SwitchPreference(
                                        title = stringResource(id = R.string.settings_hide_home_card_status_text),
                                        summary = stringResource(R.string.settings_hide_home_card_status_text_summary),
                                        startAction = {
                                            Icon(
                                                Icons.Rounded.Home,
                                                modifier = Modifier.padding(end = 8.dp),
                                                contentDescription = stringResource(R.string.settings_hide_home_card_status_text),
                                                tint = colorScheme.onBackground,
                                            )
                                        },
                                        checked = state.hideHomeCardStatusText,
                                        onCheckedChange = actions.onSetHideHomeCardStatusText,
                                    )
                                    ArrowPreference(
                                        title = stringResource(id = R.string.settings_home_card_image_clear),
                                        summary = stringResource(R.string.settings_home_card_image_clear_summary),
                                        startAction = {
                                            Icon(
                                                Icons.Rounded.Restore,
                                                modifier = Modifier.padding(end = 8.dp),
                                                contentDescription = stringResource(R.string.settings_home_card_image_clear),
                                                tint = colorScheme.onBackground,
                                            )
                                        },
                                        onClick = actions.onClearHomeCardImage,
                                    )
                                }
                            }
                        }
                    }
                    AppCard(
                        modifier = Modifier
                            .bringIntoViewRequester(sectionRequester("colors"))
                            .padding(top = 12.dp)
                            .fillMaxWidth(),
                    ) {
                        MiuixSectionHeader(
                            title = stringResource(R.string.settings_section_colors),
                            summary = stringResource(R.string.settings_section_colors_summary),
                            icon = Icons.Rounded.Colorize,
                            expanded = colorsSectionExpanded,
                            onClick = {
                                actions.onSetColorsSectionExpanded(!colorsSectionExpanded)
                            },
                        )
                        AnimatedVisibility(
                            visible = colorsSectionExpanded,
                            enter = expandVertically() + fadeIn(),
                            exit = shrinkVertically() + fadeOut(),
                        ) {
                            Column {
                                val themeItems = listOf(
                                    stringResource(id = R.string.settings_theme_mode_system),
                                    stringResource(id = R.string.settings_theme_mode_light),
                                    stringResource(id = R.string.settings_theme_mode_dark),
                                )
                                TabRowWithContour(
                                    tabs = themeItems,
                                    selectedTabIndex = (if (state.themeMode >= 3) state.themeMode - 3 else state.themeMode).coerceIn(0, 2),
                                    onTabSelected = { index ->
                                        actions.onSetThemeMode(index)
                                    },
                                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                                    colors = TabRowDefaults.tabRowColors(
                                        // The selector sits inside a surface-container card, where the
                                        // default surface track is invisible. Use the highest container
                                        // as the track and the card color as the thumb; both follow the
                                        // shared card opacity so they stay legible over a custom
                                        // background as well.
                                        backgroundColor = backgroundAwareColor(colorScheme.surfaceContainerHighest),
                                        selectedBackgroundColor = backgroundAwareColor(colorScheme.surfaceContainer),
                                    ),
                                )
                                HorizontalDivider()
                                SwitchPreference(
                                    title = stringResource(id = R.string.settings_monet),
                                    startAction = {
                                        Icon(
                                            Icons.Rounded.Wallpaper,
                                            modifier = Modifier.padding(end = 6.dp),
                                            contentDescription = stringResource(id = R.string.settings_monet),
                                            tint = colorScheme.onBackground
                                        )
                                    },
                                    checked = state.miuixMonet,
                                    onCheckedChange = {
                                        actions.onSetMiuixMonet(it)
                                    }
                                )

                                AnimatedVisibility(
                                    visible = state.miuixMonet
                                ) {
                                    Column {
                                        val colorItems = listOf(
                                            stringResource(id = R.string.settings_key_color_default),
                                            stringResource(id = R.string.color_red),
                                            stringResource(id = R.string.color_pink),
                                            stringResource(id = R.string.color_purple),
                                            stringResource(id = R.string.color_deep_purple),
                                            stringResource(id = R.string.color_indigo),
                                            stringResource(id = R.string.color_blue),
                                            stringResource(id = R.string.color_cyan),
                                            stringResource(id = R.string.color_teal),
                                            stringResource(id = R.string.color_green),
                                            stringResource(id = R.string.color_yellow),
                                            stringResource(id = R.string.color_amber),
                                            stringResource(id = R.string.color_orange),
                                            stringResource(id = R.string.color_brown),
                                            stringResource(id = R.string.color_blue_grey),
                                            stringResource(id = R.string.color_sakura),
                                        )
                                        val colorValues = listOf(0) + keyColorOptions
                                        OverlayDropdownPreference(
                                            title = stringResource(id = R.string.settings_key_color),
                                            items = colorItems,
                                            startAction = {
                                                Icon(
                                                    Icons.Rounded.Colorize,
                                                    modifier = Modifier.padding(end = 6.dp),
                                                    contentDescription = stringResource(id = R.string.settings_key_color),
                                                    tint = colorScheme.onBackground
                                                )
                                            },
                                            // A background-derived seed is not one of the fixed options, so it
                                            // shows up as the default pick rather than a stale color.
                                            selectedIndex = colorValues.indexOf(
                                                if (state.extractColorFromBackground) 0 else state.keyColor
                                            ).takeIf { it >= 0 } ?: 0,
                                            onSelectedIndexChange = { index ->
                                                actions.onSetKeyColor(colorValues[index])
                                            }
                                        )

                                        AnimatedVisibility(
                                            visible = state.keyColor != 0
                                        ) {
                                            Column {
                                                val styles = PaletteStyle.entries
                                                OverlayDropdownPreference(
                                                    title = stringResource(R.string.settings_color_style),
                                                    startAction = {
                                                        Icon(
                                                            Icons.Rounded.Style,
                                                            modifier = Modifier.padding(end = 6.dp),
                                                            contentDescription = stringResource(id = R.string.settings_color_style),
                                                            tint = colorScheme.onBackground
                                                        )
                                                    },
                                                    items = styles.map { it.name },
                                                    selectedIndex = styles.indexOfFirst { it.name == state.colorStyle }.coerceAtLeast(0),
                                                    onSelectedIndexChange = { index ->
                                                        actions.onSetColorStyle(styles[index].name)
                                                    }
                                                )

                                                val specs = ColorSpec.SpecVersion.entries
                                                OverlayDropdownPreference(
                                                    title = stringResource(R.string.settings_color_spec),
                                                    startAction = {
                                                        Icon(
                                                            Icons.Rounded.DesignServices,
                                                            modifier = Modifier.padding(end = 6.dp),
                                                            contentDescription = stringResource(id = R.string.settings_color_spec),
                                                            tint = colorScheme.onBackground
                                                        )
                                                    },
                                                    items = specs.map { it.name },
                                                    selectedIndex = specs.indexOfFirst { it.name == state.colorSpec }.coerceAtLeast(0),
                                                    onSelectedIndexChange = { index ->
                                                        actions.onSetColorSpec(specs[index].name)
                                                    }
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    AppCard(
                        modifier = Modifier
                            .bringIntoViewRequester(sectionRequester("theme_package"))
                            .padding(top = 12.dp)
                            .fillMaxWidth(),
                    ) {
                        MiuixSectionHeader(
                            title = stringResource(R.string.settings_section_theme_package),
                            summary = stringResource(R.string.settings_section_theme_package_summary),
                            icon = Icons.Rounded.Palette,
                            expanded = themePackageSectionExpanded,
                            onClick = {
                                actions.onSetThemePackageSectionExpanded(!themePackageSectionExpanded)
                            },
                        )
                        AnimatedVisibility(
                            visible = themePackageSectionExpanded,
                            enter = expandVertically() + fadeIn(),
                            exit = shrinkVertically() + fadeOut(),
                        ) {
                            Column {
                                HorizontalDivider()
                                BasicComponent(
                                    title = customText(CustomTextKey.PAGE_THEME_STORE),
                                    summary = stringResource(id = R.string.theme_store_summary),
                                    startAction = {
                                        Icon(
                                            Icons.Rounded.Palette,
                                            modifier = Modifier.padding(end = 6.dp),
                                            contentDescription = customText(CustomTextKey.PAGE_THEME_STORE),
                                            tint = colorScheme.onBackground
                                        )
                                    },
                                    onClick = actions.onOpenThemeStore,
                                )
                                BasicComponent(
                                    title = stringResource(id = R.string.theme_reset),
                                    summary = stringResource(id = R.string.theme_reset_summary),
                                    startAction = {
                                        Icon(
                                            Icons.Rounded.Restore,
                                            modifier = Modifier.padding(end = 6.dp),
                                            contentDescription = stringResource(id = R.string.theme_reset),
                                            tint = colorScheme.onBackground
                                        )
                                    },
                                    onClick = { showResetThemeDialog.value = true },
                                )
                                BasicComponent(
                                    title = stringResource(id = R.string.theme_clear_all),
                                    summary = stringResource(id = R.string.theme_clear_all_summary),
                                    startAction = {
                                        Icon(
                                            Icons.Rounded.Delete,
                                            modifier = Modifier.padding(end = 6.dp),
                                            contentDescription = stringResource(id = R.string.theme_clear_all),
                                            tint = colorScheme.onBackground
                                        )
                                    },
                                    onClick = { showClearAllDialog.value = true },
                                )
                                BasicComponent(
                                    title = stringResource(id = R.string.theme_import),
                                    summary = stringResource(id = R.string.theme_import_summary),
                                    startAction = {
                                        Icon(
                                            Icons.Rounded.FileDownload,
                                            modifier = Modifier.padding(end = 6.dp),
                                            contentDescription = stringResource(id = R.string.theme_import),
                                            tint = colorScheme.onBackground
                                        )
                                    },
                                    onClick = {
                                        importThemeLauncher.launch(
                                                arrayOf(
                                                    ThemePackageStorage.THEME_MIME_TYPE,
                                                    "application/octet-stream",
                                                    "application/zip",
                                                    "application/x-zip-compressed",
                                                    "*/*"
                                                )
                                            )
                                    },
                                )
                                BasicComponent(
                                    title = stringResource(id = R.string.theme_export),
                                    summary = stringResource(id = R.string.theme_export_summary),
                                    startAction = {
                                        Icon(
                                            Icons.Rounded.FileUpload,
                                            modifier = Modifier.padding(end = 6.dp),
                                            contentDescription = stringResource(id = R.string.theme_export),
                                            tint = colorScheme.onBackground
                                        )
                                    },
                                    onClick = {
                                        showExportDialog = true
                                    },
                                )
                            }
                        }
                    }

                    AppCard(
                        modifier = Modifier
                            .padding(top = 12.dp)
                            .bringIntoViewRequester(sectionRequester("chrome"))
                            .fillMaxWidth(),
                    ) {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            SwitchPreference(
                                title = stringResource(id = R.string.settings_enable_blur),
                                summary = stringResource(id = R.string.settings_enable_blur_summary),
                                startAction = {
                                    Icon(
                                        Icons.Rounded.BlurOn,
                                        modifier = Modifier.padding(end = 6.dp),
                                        contentDescription = stringResource(id = R.string.settings_enable_blur),
                                        tint = colorScheme.onBackground
                                    )
                                },
                                checked = uiState.enableBlur,
                                onCheckedChange = {
                                    actions.onSetEnableBlur(it)
                                }
                            )
                        }
                        SwitchPreference(
                            title = stringResource(id = R.string.settings_floating_bottom_bar),
                            summary = stringResource(id = R.string.settings_floating_bottom_bar_summary),
                            startAction = {
                                Icon(
                                    Icons.Rounded.CallToAction,
                                    modifier = Modifier.padding(end = 6.dp),
                                    contentDescription = stringResource(id = R.string.settings_floating_bottom_bar),
                                    tint = colorScheme.onBackground
                                )
                            },
                            checked = state.enableFloatingBottomBar,
                            onCheckedChange = {
                                actions.onSetEnableFloatingBottomBar(it)
                            }
                        )
                        AnimatedVisibility(visible = state.enableFloatingBottomBar && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            SwitchPreference(
                                title = stringResource(id = R.string.settings_enable_glass),
                                summary = stringResource(id = R.string.settings_enable_glass_summary),
                                startAction = {
                                    Icon(
                                        Icons.Rounded.WaterDrop,
                                        modifier = Modifier.padding(end = 6.dp),
                                        contentDescription = stringResource(id = R.string.settings_enable_glass),
                                        tint = colorScheme.onBackground
                                    )
                                },
                                checked = state.enableFloatingBottomBarBlur,
                                onCheckedChange = {
                                    actions.onSetEnableFloatingBottomBarBlur(it)
                                }
                            )
                        }
                        SwitchPreference(
                            title = stringResource(id = R.string.settings_navigation_badge),
                            summary = stringResource(id = R.string.settings_navigation_badge_summary),
                            startAction = {
                                Icon(
                                    Icons.Rounded.Pin,
                                    modifier = Modifier.padding(end = 6.dp),
                                    contentDescription = stringResource(id = R.string.settings_navigation_badge),
                                    tint = colorScheme.onBackground
                                )
                            },
                            checked = state.enableNavigationBadge,
                            onCheckedChange = {
                                actions.onSetEnableNavigationBadge(it)
                            }
                        )
                    }

                    AppCard(
                        modifier = Modifier
                            .padding(top = 12.dp)
                            .bringIntoViewRequester(sectionRequester("behavior"))
                            .fillMaxWidth(),
                    ) {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                            SwitchPreference(
                                title = stringResource(id = R.string.settings_enable_predictive_back),
                                summary = stringResource(id = R.string.settings_enable_predictive_back_summary),
                                startAction = {
                                    Icon(
                                        Icons.AutoMirrored.Rounded.MenuOpen,
                                        modifier = Modifier.padding(end = 6.dp),
                                        contentDescription = stringResource(id = R.string.settings_enable_predictive_back),
                                        tint = colorScheme.onBackground
                                    )
                                },
                                checked = uiState.enablePredictiveBack,
                                onCheckedChange = {
                                    actions.onSetEnablePredictiveBack(it)
                                }
                            )
                        }
                        SwitchPreference(
                            title = stringResource(id = R.string.settings_enable_swipe_dismiss),
                            summary = stringResource(id = R.string.settings_enable_swipe_dismiss_summary),
                            startAction = {
                                Icon(
                                    Icons.Rounded.Swipe,
                                    modifier = Modifier.padding(end = 6.dp),
                                    contentDescription = stringResource(id = R.string.settings_enable_swipe_dismiss),
                                    tint = colorScheme.onBackground,
                                )
                            },
                            checked = uiState.enableSwipeDismiss,
                            onCheckedChange = actions.onSetEnableSwipeDismiss,
                        )
                        OverlayDropdownPreference(
                            title = stringResource(id = R.string.settings_pager_gesture_mode),
                            items = listOf(
                                stringResource(id = R.string.settings_pager_gesture_native),
                                stringResource(id = R.string.settings_pager_gesture_cross_axis),
                                stringResource(id = R.string.settings_pager_gesture_ios_like),
                            ),
                            startAction = {
                                Icon(
                                    Icons.Rounded.ViewCarousel,
                                    modifier = Modifier.padding(end = 6.dp),
                                    contentDescription = stringResource(id = R.string.settings_pager_gesture_mode),
                                    tint = colorScheme.onBackground,
                                )
                            },
                            selectedIndex = uiState.pagerInterceptionMode.coerceIn(0, 2),
                            onSelectedIndexChange = actions.onSetPagerInterceptionMode,
                        )


                        var sliderValue by remember(state.pageScale) { mutableFloatStateOf(state.pageScale) }
                        ArrowPreference(
                            title = stringResource(id = R.string.settings_page_scale),
                            summary = stringResource(id = R.string.settings_page_scale_summary),
                            startAction = {
                                Icon(
                                    Icons.Rounded.AspectRatio,
                                    modifier = Modifier.padding(end = 6.dp),
                                    contentDescription = stringResource(id = R.string.settings_page_scale),
                                    tint = colorScheme.onBackground
                                )
                            },
                            endActions = {
                                Text(
                                    text = "${(sliderValue * 100).toInt()}%",
                                    color = colorScheme.onSurfaceVariantActions,
                                )
                            },
                            onClick = { showScaleDialog.value = !showScaleDialog.value },
                            holdDownState = showScaleDialog.value,
                            bottomAction = {
                                Slider(
                                    value = sliderValue,
                                    onValueChange = {
                                        sliderValue = it
                                    },
                                    onValueChangeFinished = {
                                        actions.onSetPageScale(sliderValue)
                                    },
                                    valueRange = 0.8f..1.1f,
                                    showKeyPoints = true,
                                    keyPoints = listOf(0.8f, 0.9f, 1f, 1.1f),
                                    magnetThreshold = 0.01f,
                                    hapticEffect = SliderDefaults.SliderHapticEffect.Step,
                                )
                            },
                        )
                        ScaleDialog(
                            show = showScaleDialog.value,
                            onDismissRequest = { showScaleDialog.value = false },
                            volumeState = { state.pageScale },
                            onVolumeChange = {
                                actions.onSetPageScale(it)
                            }
                        )
                    }

                    AppCard(
                        modifier = Modifier
                            .padding(top = 12.dp)
                            .bringIntoViewRequester(sectionRequester("module_description"))
                            .fillMaxWidth(),
                    ) {
                        var linesValue by remember(state.moduleDescriptionMaxLines) { mutableIntStateOf(state.moduleDescriptionMaxLines) }
                        BasicComponent(
                            title = stringResource(id = R.string.settings_module_description_max_lines),
                            summary = stringResource(id = R.string.settings_module_description_max_lines_summary),
                            startAction = {
                                Icon(
                                    Icons.Rounded.Description,
                                    modifier = Modifier.padding(end = 6.dp),
                                    contentDescription = stringResource(id = R.string.settings_module_description_max_lines),
                                    tint = colorScheme.onBackground
                                )
                            },
                            endActions = {
                                Text(
                                    text = "$linesValue " + stringResource(R.string.unit_lines),
                                    color = colorScheme.onSurfaceVariantActions,
                                )
                            },
                            bottomAction = {
                                Slider(
                                    value = linesValue.toFloat(),
                                    onValueChange = {
                                        linesValue = it.roundToInt()
                                    },
                                    onValueChangeFinished = {
                                        actions.onSetModuleDescriptionMaxLines(linesValue)
                                    },
                                    valueRange = 1f..5f,
                                    showKeyPoints = true,
                                    keyPoints = listOf(1f, 2f, 3f, 4f, 5f),
                                    magnetThreshold = 0.25f,
                                    hapticEffect = SliderDefaults.SliderHapticEffect.Step,
                                )
                            },
                        )
                    }

                }
                item {
                    Spacer(
                        Modifier.height(
                            WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding() +
                                    WindowInsets.captionBar.asPaddingValues().calculateBottomPadding() +
                                    12.dp
                        )
                    )
                }
            }
        }

        if (showHomeTitleDialog) {
            OverlayDialog(
                show = true,
                title = stringResource(R.string.settings_home_title),
                summary = stringResource(R.string.settings_home_title_hint),
                onDismissRequest = { showHomeTitleDialog = false },
                content = {
                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        TextField(
                            value = homeTitleDraft,
                            onValueChange = { homeTitleDraft = it },
                            label = stringResource(R.string.settings_home_title),
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            useLabelAsPlaceholder = homeTitleDraft.isEmpty(),
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            TextButton(
                                text = stringResource(android.R.string.cancel),
                                onClick = { showHomeTitleDialog = false },
                                modifier = Modifier.weight(1f),
                            )
                            TextButton(
                                text = stringResource(android.R.string.ok),
                                onClick = {
                                    actions.onSetCustomHomeTitle(homeTitleDraft)
                                    showHomeTitleDialog = false
                                },
                                modifier = Modifier.weight(1f),
                                colors = ButtonDefaults.textButtonColorsPrimary(),
                            )
                        }
                    }
                },
            )
        }

        if (showResetThemeDialog.value) {
            OverlayDialog(
                show = true,
                title = stringResource(R.string.theme_reset_confirm_title),
                summary = stringResource(R.string.theme_reset_confirm_message),
                onDismissRequest = { showResetThemeDialog.value = false },
                content = {
                    Row(horizontalArrangement = Arrangement.SpaceBetween) {
                        TextButton(
                            text = stringResource(android.R.string.cancel),
                            onClick = { showResetThemeDialog.value = false },
                            modifier = Modifier.weight(1f),
                        )
                        Spacer(Modifier.width(20.dp))
                        TextButton(
                            text = stringResource(R.string.theme_reset),
                            onClick = {
                                showResetThemeDialog.value = false
                                actions.onResetBackgroundAppearance()
                            },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.textButtonColorsPrimary(),
                        )
                    }
                },
            )
        }

        if (showClearAllDialog.value) {
            OverlayDialog(
                show = true,
                title = stringResource(R.string.theme_clear_all_confirm_title),
                summary = stringResource(R.string.theme_clear_all_confirm_message),
                onDismissRequest = { showClearAllDialog.value = false },
                content = {
                    Row(horizontalArrangement = Arrangement.SpaceBetween) {
                        TextButton(
                            text = stringResource(android.R.string.cancel),
                            onClick = { showClearAllDialog.value = false },
                            modifier = Modifier.weight(1f),
                        )
                        Spacer(Modifier.width(20.dp))
                        TextButton(
                            text = stringResource(R.string.theme_clear_all),
                            onClick = {
                                showClearAllDialog.value = false
                                actions.onClearAllAppearance()
                            },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.textButtonColorsPrimary(),
                        )
                    }
                },
            )
        }
    }

    ThemeExportDialog(
        show = showExportDialog,
        hasBackgroundImage = state.useSystemWallpaper || state.customBackgroundUri.isNotBlank(),
        hasCardImage = state.homeCardImagePath.isNotBlank(),
        hasStickers = state.homeCardStickers.isNotEmpty(),
        hasAppIcon = true,
        availableCustomTextGroups = customTextGroupsIn(uiState.customTexts, uiState.customHomeTitle),
        onDismissRequest = { showExportDialog = false },
        onConfirm = { options ->
            showExportDialog = false
            pendingExportOptions = options
            exportThemeLauncher.launch(ThemePackageStorage.packageFileName())
        },
    )
}

@Composable
private fun MiuixSectionHeader(
    title: String,
    summary: String,
    icon: ImageVector,
    expanded: Boolean,
    onClick: () -> Unit,
) {
    val rotation by animateFloatAsState(
        targetValue = if (expanded) 180f else 0f,
        label = "MiuixSectionChevron",
    )
    BasicComponent(
        title = title,
        summary = summary,
        startAction = {
            Icon(
                imageVector = icon,
                modifier = Modifier.padding(end = 6.dp),
                contentDescription = title,
                tint = colorScheme.onBackground,
            )
        },
        endActions = {
            Icon(
                imageVector = Icons.Rounded.KeyboardArrowDown,
                contentDescription = null,
                modifier = Modifier.graphicsLayer { rotationZ = rotation },
                tint = colorScheme.onBackground,
            )
        },
        onClick = onClick,
    )
}

@Composable
private fun MiuixBackgroundSliderSection(
    title: String,
    summary: String,
    value: Float,
    valueRange: ClosedFloatingPointRange<Float>,
    onValueChange: (Float) -> Unit,
    onValueChangeFinished: () -> Unit,
    startLabel: String? = null,
    endLabel: String? = null,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp)
    ) {
        Text(
            text = title,
            fontSize = 16.sp,
            fontWeight = FontWeight.Medium,
            color = colorScheme.onSurface
        )
        Text(
            text = summary,
            fontSize = 13.sp,
            color = colorScheme.onSurfaceVariantSummary
        )
        Spacer(Modifier.height(8.dp))
        Slider(
            value = value,
            onValueChange = onValueChange,
            onValueChangeFinished = onValueChangeFinished,
            valueRange = valueRange,
        )
        if (startLabel != null && endLabel != null) {
            Row(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = startLabel,
                    fontSize = 12.sp,
                    color = colorScheme.onSurfaceVariantSummary
                )
                Spacer(Modifier.weight(1f))
                Text(
                    text = endLabel,
                    fontSize = 12.sp,
                    color = colorScheme.onSurfaceVariantSummary
                )
            }
        }
    }
}

