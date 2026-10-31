package com.sukisu.ultra.ui.screen.colorpalette

import com.sukisu.ultra.ai.api.R as AiR
import com.sukisu.ultra.ai.api.AiFeatureBridge
import android.net.Uri
import java.io.File
import android.os.Build
import com.sukisu.ultra.ui.util.customText
import com.sukisu.ultra.ui.util.CustomTextKey
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
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
import androidx.compose.material.icons.rounded.Image
import androidx.compose.material.icons.rounded.KeyboardArrowDown
import androidx.compose.material.icons.rounded.DesignServices
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.material.icons.rounded.FileUpload
import androidx.compose.material.icons.rounded.Pin
import androidx.compose.material.icons.rounded.Restore
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
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
import com.sukisu.ultra.ui.screen.appicon.BuiltinAppIconPreview
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.theme.keyColorOptions
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.BuiltinAppIcons
import com.sukisu.ultra.ui.util.ThemePackageStorage
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.HorizontalDivider
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Slider
import top.yukonga.miuix.kmp.basic.SliderDefaults
import top.yukonga.miuix.kmp.basic.TabRow
import top.yukonga.miuix.kmp.basic.TabRowDefaults
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
            ?: sectionRequesters["appearance"]
            ?: return@LaunchedEffect
        target.bringIntoView()
    }
    val enableBlurState = LocalEnableBlur.current
    val backdrop = rememberBlurBackdrop(enableBlurState)
    val blurActive = backdrop != null
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val barColor = if (blurActive || hasCustomBackground) Color.Transparent else colorScheme.surface
    val uiState = state.uiState
    val currentColorMode = state.currentColorMode
    val isDark = currentColorMode.isDark || currentColorMode.isSystem && isSystemInDarkTheme()
    val context = LocalContext.current
    // Live drag values: the preview follows the sliders before they commit to the repository.
    var cardAlphaDraft by remember(uiState.cardBackgroundAlphaPercent) {
        mutableFloatStateOf(uiState.cardBackgroundAlphaPercent.toFloat())
    }
    var blurDraft by remember(uiState.customBackgroundBlurPercent) {
        mutableFloatStateOf(uiState.customBackgroundBlurPercent.toFloat())
    }
    var scrimDraft by remember(uiState.customBackgroundScrimPercent) {
        mutableFloatStateOf(uiState.customBackgroundScrimPercent.toFloat())
    }
    val exportThemeLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("*/*")
    ) { uri: Uri? ->
        uri?.let { actions.onExportTheme(context, it) }
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
        var showHomeTitleDialog by rememberSaveable { mutableStateOf(false) }
        var homeTitleDraft by rememberSaveable { mutableStateOf("") }
        val appearanceExpanded = uiState.backgroundAppearanceExpanded

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
                        spec = ThemePreviewSpec(
                            keyColor = uiState.keyColor,
                            isDark = isDark,
                            miuixMonet = uiState.miuixMonet,
                            paletteStyle = state.currentPaletteStyle,
                            colorSpec = state.currentColorSpec,
                            backgroundPath = if (uiState.useSystemWallpaper) {
                                uiState.systemWallpaperPath
                            } else {
                                uiState.customBackgroundUri
                            },
                            backgroundUpdatedAt = uiState.customBackgroundUpdatedAt,
                            cardAlpha = cardAlphaDraft / 100f,
                            backgroundBlurPercent = blurDraft.roundToInt(),
                            backgroundScrimPercent = scrimDraft.roundToInt(),
                            floatingBottomBar = uiState.enableFloatingBottomBar,
                            floatingBottomBarBlur = uiState.enableFloatingBottomBarBlur,
                            navigationBadge = uiState.enableNavigationBadge,
                            pageScale = uiState.pageScale,
                            customHomeTitle = uiState.customHomeTitle,
                            homeCardImagePath = uiState.homeCardImagePath,
                        ),
                    )
                    Spacer(modifier = Modifier.height(28.dp))

                    val pickImageLauncher = rememberLauncherForActivityResult(
                        contract = ActivityResultContracts.PickVisualMedia()
                    ) { uri: Uri? ->
                        uri?.let { actions.onPickCustomBackground(context, it) }
                    }
                    val hasCustomBg = uiState.customBackgroundUri.isNotEmpty()
                    val usingSystemWallpaper = uiState.useSystemWallpaper

                    AppCard(
                        modifier = Modifier
                            .bringIntoViewRequester(sectionRequester("background"))
                            .padding(bottom = 12.dp)
                            .fillMaxWidth(),
                        colors = backgroundAwareCardColors(),
                    ) {
                        SwitchPreference(
                            title = stringResource(id = R.string.settings_use_system_wallpaper),
                            summary = stringResource(
                                id = if (uiState.isSystemWallpaperBusy) {
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
                            enabled = !uiState.isSystemWallpaperBusy,
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
                                        TextButton(
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
                        val hasCardBgFile = uiState.homeCardImagePath.isNotBlank() && File(uiState.homeCardImagePath).isFile
                        if (hasCustomBgFile || hasCardBgFile) {
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
                                    val fileName = when {
                                        hasCustomBgFile && hasCardBgFile -> "SukiSU-images.zip"
                                        hasCardBgFile -> "SukiSU-home-card.png"
                                        else -> "SukiSU-background.png"
                                    }
                                    exportImagesLauncher.launch(fileName)
                                }
                            )
                        }

                        if (usingSystemWallpaper || hasCustomBg) {
                            HorizontalDivider()
                            SwitchPreference(
                                title = stringResource(id = R.string.settings_extract_background_color),
                                summary = stringResource(id = R.string.settings_extract_background_color_summary),
                                startAction = {
                                    Icon(
                                        imageVector = Icons.Rounded.Colorize,
                                        modifier = Modifier.padding(end = 6.dp),
                                        contentDescription = stringResource(id = R.string.settings_extract_background_color),
                                        tint = colorScheme.onBackground
                                    )
                                },
                                checked = uiState.extractColorFromBackground,
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
                                            actions.onSetCustomBackgroundScrimPercent(percent)
                                        },
                                        startLabel = stringResource(id = R.string.settings_background_scrim_darker),
                                        endLabel = stringResource(id = R.string.settings_background_scrim_lighter),
                                    )
                                }
                            }
                        }
                    }

                    AppCard(
                        modifier = Modifier
                            .bringIntoViewRequester(sectionRequester("theme_package"))
                            .padding(bottom = 12.dp)
                            .fillMaxWidth(),
                    ) {
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
                                exportThemeLauncher.launch(ThemePackageStorage.packageFileName())
                            },
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
                    }
                    AppCard(
                        modifier = Modifier
                            .bringIntoViewRequester(sectionRequester("appearance"))
                            .padding(bottom = 12.dp)
                            .fillMaxWidth(),
                    ) {
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
                            title = stringResource(id = R.string.app_icon_title),
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
                        ArrowPreference(
                            title = stringResource(id = R.string.settings_custom_texts),
                            summary = stringResource(id = R.string.settings_custom_texts_summary),
                            startAction = {
                                Icon(
                                    Icons.Rounded.Edit,
                                    modifier = Modifier.padding(end = 8.dp),
                                    contentDescription = stringResource(R.string.settings_custom_texts),
                                    tint = colorScheme.onBackground,
                                )
                            },
                            onClick = actions.onOpenCustomTexts,
                        )
                        ArrowPreference(
                            title = stringResource(id = R.string.settings_home_card_image),
                            summary = if (uiState.homeCardImagePath.isBlank()) {
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
                        if (uiState.homeCardImagePath.isNotBlank()) {
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
                    val themeItems = listOf(
                        stringResource(id = R.string.settings_theme_mode_system),
                        stringResource(id = R.string.settings_theme_mode_light),
                        stringResource(id = R.string.settings_theme_mode_dark),
                    )
                    TabRow(
                        tabs = themeItems,
                        selectedTabIndex = (if (uiState.themeMode >= 3) uiState.themeMode - 3 else uiState.themeMode).coerceIn(0, 2),
                        onTabSelected = { index ->
                            actions.onSetThemeMode(index)
                        },
                        colors = TabRowDefaults.tabRowColors(
                            backgroundColor = if (hasCustomBackground) Color.Transparent else colorScheme.surface,
                            selectedBackgroundColor = backgroundAwareColor(colorScheme.surfaceContainer),
                        ),
                    )

                    AppCard(
                        modifier = Modifier
                            .bringIntoViewRequester(sectionRequester("colors"))
                            .padding(top = 12.dp)
                            .fillMaxWidth(),
                    ) {
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
                            checked = uiState.miuixMonet,
                            onCheckedChange = {
                                actions.onSetMiuixMonet(it)
                            }
                        )

                        AnimatedVisibility(
                            visible = uiState.miuixMonet
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
                                    selectedIndex = colorValues.indexOf(uiState.keyColor).takeIf { it >= 0 } ?: 0,
                                    onSelectedIndexChange = { index ->
                                        actions.onSetKeyColor(colorValues[index])
                                    }
                                )

                                AnimatedVisibility(
                                    visible = uiState.keyColor != 0
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
                                            selectedIndex = styles.indexOfFirst { it.name == uiState.colorStyle }.coerceAtLeast(0),
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
                                            selectedIndex = specs.indexOfFirst { it.name == uiState.colorSpec }.coerceAtLeast(0),
                                            onSelectedIndexChange = { index ->
                                                actions.onSetColorSpec(specs[index].name)
                                            }
                                        )
                                    }
                                }
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
                            checked = uiState.enableFloatingBottomBar,
                            onCheckedChange = {
                                actions.onSetEnableFloatingBottomBar(it)
                            }
                        )
                        AnimatedVisibility(visible = uiState.enableFloatingBottomBar && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
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
                                checked = uiState.enableFloatingBottomBarBlur,
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
                            checked = uiState.enableNavigationBadge,
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


                        var sliderValue by remember(uiState.pageScale) { mutableFloatStateOf(uiState.pageScale) }
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
                            volumeState = { uiState.pageScale },
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
                        var linesValue by remember(uiState.moduleDescriptionMaxLines) { mutableIntStateOf(uiState.moduleDescriptionMaxLines) }
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
    }
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

