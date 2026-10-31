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
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.captionBar
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AutoAwesome
import androidx.compose.material.icons.automirrored.rounded.MenuOpen
import androidx.compose.material.icons.filled.Brightness1
import androidx.compose.material.icons.filled.Brightness3
import androidx.compose.material.icons.filled.Brightness4
import androidx.compose.material.icons.filled.Brightness7
import androidx.compose.material.icons.rounded.AspectRatio
import androidx.compose.material.icons.rounded.BlurOn
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.ChevronRight
import androidx.compose.material.icons.rounded.Colorize
import androidx.compose.material.icons.rounded.KeyboardArrowDown
import androidx.compose.material.icons.rounded.KeyboardArrowUp
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material.icons.rounded.Contrast
import androidx.compose.material.icons.rounded.Crop
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.DesignServices
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.material.icons.rounded.FileUpload
import androidx.compose.material.icons.rounded.Opacity
import androidx.compose.material.icons.rounded.Pin
import androidx.compose.material.icons.rounded.Restore
import androidx.compose.material.icons.rounded.WaterDrop
import androidx.compose.material.icons.rounded.Style
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.Image
import androidx.compose.material.icons.rounded.Swipe
import androidx.compose.material.icons.rounded.ViewCarousel
import androidx.compose.material.icons.rounded.Wallpaper
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonGroupDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberSliderState
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlin.math.roundToInt
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.material.ExpressiveConfirmDialog
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.CapsuleSlider
import com.sukisu.ultra.ui.component.material.ExpressiveToggleButton
import com.sukisu.ultra.ui.component.material.IconTile
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedDropdownItem
import com.sukisu.ultra.ui.component.material.SegmentedListItem
import com.sukisu.ultra.ui.component.material.SegmentedSwitchItem
import com.sukisu.ultra.ui.component.material.TonalCard
import com.sukisu.ultra.ui.component.material.TopBarBackButton
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.screen.appicon.BuiltinAppIconPreview
import com.sukisu.ultra.ui.theme.ColorMode
import com.sukisu.ultra.ui.theme.keyColorOptions
import com.sukisu.ultra.ui.theme.rememberKernelSUColorScheme
import com.sukisu.ultra.ui.util.BuiltinAppIcons
import com.sukisu.ultra.ui.util.ThemePackageStorage

@Composable
fun ColorPaletteScreenMaterial(
    state: ColorPaletteUiState,
    actions: ColorPaletteScreenActions,
    section: String? = null,
) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior(rememberTopAppBarState())
    val listState = rememberLazyListState()
    val uiState = state.uiState
    val currentColorMode = state.currentColorMode

    LaunchedEffect(section) {
        val index = appearanceSectionIndex(section) ?: return@LaunchedEffect
        listState.animateScrollToItem(index)
    }
    val currentKeyColor = uiState.keyColor
    val colorStyle = state.currentPaletteStyle
    val colorSpec = state.currentColorSpec
    val haptic = LocalHapticFeedback.current
    val context = LocalContext.current
    var showResetThemeDialog by rememberSaveable { mutableStateOf(false) }
    var showHomeTitleDialog by rememberSaveable { mutableStateOf(false) }
    var homeTitleDraft by rememberSaveable { mutableStateOf("") }
    val appearanceExpanded = uiState.backgroundAppearanceExpanded
    // Kept above the list so the preview reflects the thumb position before the value commits.
    val alphaSliderState = rememberSliderState(
        value = uiState.cardBackgroundAlphaPercent.toFloat(),
        trackRange = 10f..91f,
    )
    val blurSliderState = rememberSliderState(
        value = uiState.customBackgroundBlurPercent.toFloat(),
        trackRange = 0f..100f,
    )
    val scrimSliderState = rememberSliderState(
        value = uiState.customBackgroundScrimPercent.toFloat(),
        trackRange = -100f..100f,
    )
    // Imported/reset values change outside the sliders, whose states are remembered.
    LaunchedEffect(
        uiState.cardBackgroundAlphaPercent,
        uiState.customBackgroundBlurPercent,
        uiState.customBackgroundScrimPercent,
    ) {
        if (alphaSliderState.value.roundToInt() != uiState.cardBackgroundAlphaPercent) {
            alphaSliderState.value = uiState.cardBackgroundAlphaPercent.toFloat()
        }
        if (blurSliderState.value.roundToInt() != uiState.customBackgroundBlurPercent) {
            blurSliderState.value = uiState.customBackgroundBlurPercent.toFloat()
        }
        if (scrimSliderState.value.roundToInt() != uiState.customBackgroundScrimPercent) {
            scrimSliderState.value = uiState.customBackgroundScrimPercent.toFloat()
        }
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

    ExpressiveScaffold(
        topBar = {
            LargeFlexibleTopAppBar(
                navigationIcon = {
                    TopBarBackButton(onClick = actions.onBack)
                },
                title = { Text(customText(CustomTextKey.PAGE_APPEARANCE)) },
                colors = expressiveTopAppBarColors(),
                windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
                scrollBehavior = scrollBehavior
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal)
    ) { paddingValues ->
        val navBars = WindowInsets.navigationBars.asPaddingValues()
        val captionBar = WindowInsets.captionBar.asPaddingValues()
        val isDark = currentColorMode.isDark || currentColorMode.isSystem && isSystemInDarkTheme()
        val isAmoled = currentColorMode.isAmoled

        LazyColumn(
            state = listState,
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .nestedScroll(scrollBehavior.nestedScrollConnection),
            verticalArrangement = Arrangement.spacedBy(13.dp)
        ) {
            item {
                ThemePreviewMaterial(
                    spec = ThemePreviewSpec(
                        keyColor = currentKeyColor,
                        isDark = isDark,
                        isAmoled = isAmoled,
                        paletteStyle = colorStyle,
                        colorSpec = colorSpec,
                        backgroundPath = if (uiState.useSystemWallpaper) {
                            uiState.systemWallpaperPath
                        } else {
                            uiState.customBackgroundUri
                        },
                        backgroundUpdatedAt = uiState.customBackgroundUpdatedAt,
                        cardAlpha = alphaSliderState.value / 100f,
                        backgroundBlurPercent = blurSliderState.value.roundToInt(),
                        backgroundScrimPercent = scrimSliderState.value.roundToInt(),
                        floatingBottomBar = true,
                        floatingBottomBarBlur = uiState.enableFloatingBottomBarBlur,
                        navigationBadge = uiState.enableNavigationBadge,
                        pageScale = uiState.pageScale,
                        customHomeTitle = uiState.customHomeTitle,
                        homeCardImagePath = uiState.homeCardImagePath,
                    ),
                )
            }

            item {
                val pickImageLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.PickVisualMedia()
                ) { uri: Uri? ->
                    uri?.let { actions.onPickCustomBackground(context, it) }
                }
                val hasCustomBg = uiState.customBackgroundUri.isNotEmpty()
                val usingSystemWallpaper = uiState.useSystemWallpaper

                SegmentedColumn(
                    modifier = Modifier.padding(horizontal = 16.dp),
                    content = buildList<@Composable () -> Unit> {
                        add {
                            SegmentedSwitchItem(
                                icon = Icons.Rounded.Wallpaper,
                                title = stringResource(id = R.string.settings_use_system_wallpaper),
                                summary = stringResource(
                                    id = if (uiState.isSystemWallpaperBusy) {
                                        R.string.settings_use_system_wallpaper_reading
                                    } else {
                                        R.string.settings_use_system_wallpaper_summary
                                    }
                                ),
                                checked = usingSystemWallpaper,
                                enabled = !uiState.isSystemWallpaperBusy,
                                onCheckedChange = { actions.onSetUseSystemWallpaper(context, it) },
                            )
                        }
                        if (!usingSystemWallpaper) {
                            add {
                                SegmentedListItem(
                                    onClick = {
                                        pickImageLauncher.launch(
                                            PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)
                                        )
                                    },
                                    headlineContent = { Text(stringResource(id = R.string.settings_custom_background)) },
                                    supportingContent = { Text(stringResource(id = R.string.settings_custom_background_summary)) },
                                    leadingContent = { IconTile(Icons.Rounded.Image, stringResource(id = R.string.settings_custom_background)) },
                                    trailingContent = if (hasCustomBg) {
                                        {
                                            TextButton(onClick = { actions.onClearCustomBackground(context) }) {
                                                Text(stringResource(id = R.string.settings_clear))
                                            }
                                        }
                                    } else null
                                )
                            }
                            if (hasCustomBg) {
                                add {
                                    SegmentedListItem(
                                        onClick = { actions.onCropCurrentBackground(context) },
                                        headlineContent = { Text(stringResource(id = R.string.settings_crop_background)) },
                                        supportingContent = { Text(stringResource(id = R.string.settings_crop_background_summary)) },
                                        leadingContent = { IconTile(Icons.Rounded.Crop, stringResource(id = R.string.settings_crop_background)) },
                                    )
                                }
                            }
                            val hasCustomBgFile = hasCustomBg && !usingSystemWallpaper
                            val hasCardBgFile = uiState.homeCardImagePath.isNotBlank() && File(uiState.homeCardImagePath).isFile
                            if (hasCustomBgFile || hasCardBgFile) {
                                add {
                                    SegmentedListItem(
                                        onClick = {
                                            val fileName = when {
                                                hasCustomBgFile && hasCardBgFile -> "SukiSU-images.zip"
                                                hasCardBgFile -> "SukiSU-home-card.png"
                                                else -> "SukiSU-background.png"
                                            }
                                            exportImagesLauncher.launch(fileName)
                                        },
                                        headlineContent = { Text(stringResource(id = R.string.settings_export_images)) },
                                        supportingContent = { Text(stringResource(id = R.string.settings_export_images_summary)) },
                                        leadingContent = { IconTile(Icons.Rounded.FileDownload, stringResource(id = R.string.settings_export_images)) },
                                    )
                                }
                            }
                        }
                        if (usingSystemWallpaper || hasCustomBg) {
                            add {
                                SegmentedSwitchItem(
                                    icon = Icons.Rounded.Colorize,
                                    title = stringResource(id = R.string.settings_extract_background_color),
                                    summary = stringResource(id = R.string.settings_extract_background_color_summary),
                                    checked = uiState.extractColorFromBackground,
                                    onCheckedChange = actions.onSetExtractColorFromBackground,
                                )
                            }
                        }
                    }
                )

                if (usingSystemWallpaper || hasCustomBg) {
                    Spacer(Modifier.height(12.dp))
                    TonalCard(modifier = Modifier.padding(horizontal = 16.dp)) {
                        Column {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp))
                                    .clickable {
                                        actions.onSetBackgroundAppearanceExpanded(!appearanceExpanded)
                                    }
                                    .padding(16.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Icon(
                                    imageVector = Icons.Rounded.Tune,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Spacer(Modifier.width(12.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = stringResource(R.string.settings_background_appearance),
                                        style = MaterialTheme.typography.titleMedium,
                                        fontWeight = FontWeight.Medium,
                                        color = MaterialTheme.colorScheme.onSurface,
                                    )
                                    Text(
                                        text = stringResource(R.string.settings_background_appearance_summary),
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                                Icon(
                                    imageVector = if (appearanceExpanded) {
                                        Icons.Rounded.KeyboardArrowUp
                                    } else {
                                        Icons.Rounded.KeyboardArrowDown
                                    },
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            AnimatedVisibility(
                                visible = appearanceExpanded,
                                enter = expandVertically() + fadeIn(),
                                exit = shrinkVertically() + fadeOut(),
                            ) {
                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(start = 16.dp, end = 16.dp, bottom = 16.dp)
                                ) {
                                    BackgroundSliderHeader(
                                        icon = Icons.Rounded.Opacity,
                                        title = stringResource(id = R.string.settings_card_background_alpha),
                                        summary = stringResource(
                                            id = R.string.settings_card_background_alpha_summary,
                                            alphaSliderState.value.roundToInt(),
                                        ),
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    CapsuleSlider(
                                        state = alphaSliderState,
                                        onValueChangeFinished = {
                                            val percent = alphaSliderState.value.roundToInt()
                                            alphaSliderState.value = percent.toFloat()
                                            actions.onSetCardBackgroundAlphaPercent(percent)
                                        },
                                        modifier = Modifier.fillMaxWidth(),
                                    )
                                    HorizontalDivider(modifier = Modifier.padding(vertical = 16.dp))
                                    BackgroundSliderHeader(
                                        icon = Icons.Rounded.BlurOn,
                                        title = stringResource(id = R.string.settings_background_blur),
                                        summary = stringResource(
                                            id = R.string.settings_background_blur_summary,
                                            blurSliderState.value.roundToInt(),
                                        ),
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    CapsuleSlider(
                                        state = blurSliderState,
                                        onValueChangeFinished = {
                                            val percent = blurSliderState.value.roundToInt()
                                            blurSliderState.value = percent.toFloat()
                                            actions.onSetCustomBackgroundBlurPercent(percent)
                                        },
                                        modifier = Modifier.fillMaxWidth(),
                                    )
                                    HorizontalDivider(modifier = Modifier.padding(vertical = 16.dp))
                                    BackgroundSliderHeader(
                                        icon = Icons.Rounded.Contrast,
                                        title = stringResource(id = R.string.settings_background_scrim),
                                        summary = stringResource(
                                            id = R.string.settings_background_scrim_summary,
                                            scrimSliderState.value.roundToInt(),
                                        ),
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    CapsuleSlider(
                                        state = scrimSliderState,
                                        onValueChangeFinished = {
                                            val percent = scrimSliderState.value.roundToInt()
                                            scrimSliderState.value = percent.toFloat()
                                            actions.onSetCustomBackgroundScrimPercent(percent)
                                        },
                                        modifier = Modifier.fillMaxWidth(),
                                    )
                                    Row(modifier = Modifier.fillMaxWidth()) {
                                        Text(
                                            text = stringResource(id = R.string.settings_background_scrim_darker),
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                        Spacer(modifier = Modifier.weight(1f))
                                        Text(
                                            text = stringResource(id = R.string.settings_background_scrim_lighter),
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }

            item {
                SegmentedColumn(
                    modifier = Modifier.padding(horizontal = 16.dp),
                    content = listOf<@Composable () -> Unit>(
                        {
                            SegmentedListItem(
                                onClick = {
                                    exportThemeLauncher.launch(ThemePackageStorage.packageFileName())
                                },
                                headlineContent = { Text(stringResource(id = R.string.theme_export)) },
                                supportingContent = { Text(stringResource(id = R.string.theme_export_summary)) },
                                leadingContent = { IconTile(Icons.Rounded.FileUpload, stringResource(id = R.string.theme_export)) },
                            )
                        },
                        {
                            SegmentedListItem(
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
                                headlineContent = { Text(stringResource(id = R.string.theme_import)) },
                                supportingContent = { Text(stringResource(id = R.string.theme_import_summary)) },
                                leadingContent = { IconTile(Icons.Rounded.FileDownload, stringResource(id = R.string.theme_import)) },
                            )
                        },
                        {
                            SegmentedListItem(
                                onClick = { showResetThemeDialog = true },
                                headlineContent = { Text(stringResource(id = R.string.theme_reset)) },
                                supportingContent = { Text(stringResource(id = R.string.theme_reset_summary)) },
                                leadingContent = { IconTile(Icons.Rounded.Restore, stringResource(id = R.string.theme_reset)) },
                            )
                        }
                    )
                )
            }
            item {
                SegmentedColumn(
                    modifier = Modifier.padding(horizontal = 16.dp),
                    content = listOf<@Composable () -> Unit>(
                        {
                            SegmentedSwitchItem(
                                icon = Icons.Rounded.Fingerprint,
                                title = stringResource(id = R.string.settings_show_fullstatus),
                                summary = stringResource(id = R.string.settings_show_fullstatus_summary),
                                checked = state.showFullStatus,
                                onCheckedChange = actions.onSetShowFullStatus
                            )
                        },
                        {
                            SegmentedSwitchItem(
                                icon = Icons.Rounded.Warning,
                                title = stringResource(id = R.string.settings_hide_home_warnings),
                                summary = stringResource(id = R.string.settings_hide_home_warnings_summary),
                                checked = state.hideHomeWarnings,
                                onCheckedChange = actions.onSetHideHomeWarnings
                            )
                        },
                        {
                            if (AiFeatureBridge.isAvailable) {
                                SegmentedSwitchItem(
                                    icon = Icons.Rounded.AutoAwesome,
                                    title = stringResource(id = AiR.string.ai_show_home_card),
                                    summary = stringResource(id = AiR.string.ai_show_home_card_summary),
                                    checked = state.showAiHomeCard,
                                    onCheckedChange = actions.onSetShowAiHomeCard
                                )
                            }
                        },
                        {
                            val currentIcon = BuiltinAppIcons.find(uiState.appIconId)
                            SegmentedListItem(
                                onClick = actions.onOpenAppIcon,
                                headlineContent = { Text(stringResource(R.string.app_icon_title)) },
                                supportingContent = {
                                    Text(stringResource(R.string.app_icon_summary))
                                },
                                leadingContent = {
                                    BuiltinAppIconPreview(
                                        icon = currentIcon,
                                        modifier = Modifier
                                            .size(36.dp)
                                            .clip(RoundedCornerShape(12.dp)),
                                    )
                                },
                                trailingContent = {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text(
                                            text = stringResource(currentIcon.nameRes),
                                            color = MaterialTheme.colorScheme.primary,
                                        )
                                        Icon(
                                            imageVector = Icons.Rounded.ChevronRight,
                                            contentDescription = null,
                                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                    }
                                },
                            )
                        },
                        {
                            SegmentedListItem(
                                onClick = actions.onOpenCustomTexts,
                                headlineContent = { Text(stringResource(R.string.settings_custom_texts)) },
                                supportingContent = { Text(stringResource(R.string.settings_custom_texts_summary)) },
                                leadingContent = {
                                    IconTile(
                                        Icons.Rounded.Edit,
                                        stringResource(R.string.settings_custom_texts),
                                    )
                                },
                                trailingContent = {
                                    Icon(
                                        imageVector = Icons.Rounded.ChevronRight,
                                        contentDescription = null,
                                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                },
                            )
                        },
                        {
                            SegmentedListItem(
                                onClick = {
                                    homeCardImageLauncher.launch(
                                        PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)
                                    )
                                },
                                headlineContent = { Text(stringResource(R.string.settings_home_card_image)) },
                                supportingContent = {
                                    Text(
                                        if (uiState.homeCardImagePath.isBlank()) {
                                            stringResource(R.string.settings_home_card_image_default)
                                        } else {
                                            stringResource(R.string.settings_home_card_image_set)
                                        }
                                    )
                                },
                                leadingContent = {
                                    IconTile(
                                        Icons.Rounded.Image,
                                        stringResource(R.string.settings_home_card_image),
                                    )
                                },
                            )
                        }
                    ) + if (uiState.homeCardImagePath.isNotBlank()) {
                        listOf<@Composable () -> Unit>(
                            {
                                SegmentedListItem(
                                    onClick = actions.onClearHomeCardImage,
                                    headlineContent = { Text(stringResource(R.string.settings_home_card_image_clear)) },
                                    supportingContent = {
                                        Text(stringResource(R.string.settings_home_card_image_clear_summary))
                                    },
                                    leadingContent = {
                                        IconTile(
                                            Icons.Rounded.Restore,
                                            stringResource(R.string.settings_home_card_image_clear),
                                        )
                                    },
                                )
                            }
                        )
                    } else {
                        emptyList()
                    }
                )
            }

            item {
                LazyRow(
                    modifier = Modifier.fillMaxWidth(),
                    contentPadding = PaddingValues(horizontal = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    item {
                        ColorButtonMaterial(
                            color = Color.Unspecified,
                            isSelected = currentKeyColor == 0,
                            isDark = isDark,
                            isAmoled = isAmoled,
                            paletteStyle = colorStyle,
                            colorSpec = colorSpec,
                            onClick = {
                                actions.onSetKeyColor(0)
                            }
                        )
                    }

                    items(keyColorOptions) { color ->
                        ColorButtonMaterial(
                            color = Color(color),
                            isSelected = currentKeyColor == color,
                            isDark = isDark,
                            isAmoled = isAmoled,
                            paletteStyle = colorStyle,
                            colorSpec = colorSpec,
                            onClick = {
                                actions.onSetKeyColor(color)
                            }
                        )
                    }
                }
            }

            item {
                val options = listOf(
                    listOf(ColorMode.SYSTEM) to stringResource(R.string.settings_theme_mode_system),
                    listOf(ColorMode.LIGHT) to stringResource(R.string.settings_theme_mode_light),
                    listOf(ColorMode.DARK) to stringResource(R.string.settings_theme_mode_dark),
                    listOf(ColorMode.DARK_AMOLED) to stringResource(R.string.settings_theme_mode_dark)
                )

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    options.chunked(4).forEach { rowOptions ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(ButtonGroupDefaults.ConnectedSpaceBetween)
                        ) {
                            rowOptions.forEachIndexed { index, (modes, label) ->
                                ExpressiveToggleButton(
                                    checked = currentColorMode in modes,
                                    onCheckedChange = {
                                        if (it) {
                                            haptic.performHapticFeedback(HapticFeedbackType.ContextClick)
                                            actions.onSetColorMode(modes.first())
                                        }
                                    },
                                    modifier = Modifier
                                        .weight(1f)
                                        .semantics { role = Role.RadioButton },
                                    shapes = when (index) {
                                        0 -> ButtonGroupDefaults.connectedLeadingButtonShapes()
                                        rowOptions.lastIndex -> ButtonGroupDefaults.connectedTrailingButtonShapes()
                                        else -> ButtonGroupDefaults.connectedMiddleButtonShapes()
                                    },
                                ) {
                                    Icon(
                                        imageVector = when (modes.first()) {
                                            ColorMode.SYSTEM -> Icons.Filled.Brightness4
                                            ColorMode.LIGHT -> Icons.Filled.Brightness7
                                            ColorMode.DARK -> Icons.Filled.Brightness3
                                            ColorMode.DARK_AMOLED -> Icons.Filled.Brightness1
                                            else -> Icons.Filled.Brightness4
                                        },
                                        contentDescription = label
                                    )
                                }
                            }
                        }
                    }
                }
            }

            item {
                SegmentedColumn(
                    modifier = Modifier.padding(horizontal = 16.dp),
                    content = listOf<@Composable () -> Unit>(
                        {
                            val styles = PaletteStyle.entries
                            SegmentedDropdownItem(
                                icon = Icons.Rounded.Style,
                                title = stringResource(R.string.settings_color_style),
                                items = styles.map { it.name },
                                selectedIndex = styles.indexOf(colorStyle),
                                onItemSelected = { index ->
                                    actions.onSetColorStyle(styles[index].name)
                                }
                            )
                        },
                        {
                            val specs = ColorSpec.SpecVersion.entries
                            SegmentedDropdownItem(
                                icon = Icons.Rounded.DesignServices,
                                title = stringResource(R.string.settings_color_spec),
                                items = specs.map { it.name },
                                selectedIndex = specs.indexOf(colorSpec).coerceAtLeast(0),
                                onItemSelected = { index ->
                                    actions.onSetColorSpec(specs[index].name)
                                }
                            )
                        }
                    )
                )
            }

            item {
                SegmentedColumn(
                    modifier = Modifier.padding(horizontal = 16.dp),
                    content = buildList<@Composable () -> Unit> {
                        // The liquid glass bar relies on RenderEffect blur, same gate as the Miuix toggle.
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) add {
                            SegmentedSwitchItem(
                                icon = Icons.Rounded.WaterDrop,
                                title = stringResource(id = R.string.settings_enable_glass),
                                summary = stringResource(id = R.string.settings_enable_glass_summary),
                                checked = uiState.enableFloatingBottomBarBlur,
                                onCheckedChange = actions.onSetEnableFloatingBottomBarBlur
                            )
                        }
                        add {
                            SegmentedSwitchItem(
                                icon = Icons.Rounded.Pin,
                                title = stringResource(id = R.string.settings_navigation_badge),
                                summary = stringResource(id = R.string.settings_navigation_badge_summary),
                                checked = uiState.enableNavigationBadge,
                                onCheckedChange = actions.onSetEnableNavigationBadge
                            )
                        }
                    }
                )
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                item {
                    SegmentedColumn(
                        modifier = Modifier.padding(horizontal = 16.dp),
                        content = listOf<@Composable () -> Unit>(
                            {
                                SegmentedSwitchItem(
                                    icon = Icons.AutoMirrored.Rounded.MenuOpen,
                                    title = stringResource(id = R.string.settings_enable_predictive_back),
                                    summary = stringResource(id = R.string.settings_enable_predictive_back_summary),
                                    checked = uiState.enablePredictiveBack,
                                    onCheckedChange = actions.onSetEnablePredictiveBack
                                )
                            }
                        )
                    )
                }
            }


            item {
                SegmentedColumn(
                    modifier = Modifier.padding(horizontal = 16.dp),
                    content = listOf<@Composable () -> Unit>(
                        {
                            SegmentedSwitchItem(
                                icon = Icons.Rounded.Swipe,
                                title = stringResource(id = R.string.settings_enable_swipe_dismiss),
                                summary = stringResource(id = R.string.settings_enable_swipe_dismiss_summary),
                                checked = uiState.enableSwipeDismiss,
                                onCheckedChange = actions.onSetEnableSwipeDismiss,
                            )
                        },
                        {
                            SegmentedDropdownItem(
                                icon = Icons.Rounded.ViewCarousel,
                                title = stringResource(id = R.string.settings_pager_gesture_mode),
                                items = listOf(
                                    stringResource(id = R.string.settings_pager_gesture_native),
                                    stringResource(id = R.string.settings_pager_gesture_cross_axis),
                                    stringResource(id = R.string.settings_pager_gesture_ios_like),
                                ),
                                selectedIndex = uiState.pagerInterceptionMode.coerceIn(0, 2),
                                onItemSelected = actions.onSetPagerInterceptionMode,
                            )
                        },
                    ),
                )
            }

            item {
                TonalCard(modifier = Modifier.padding(horizontal = 16.dp)) {
                    val sliderState = rememberSliderState(
                        value = uiState.pageScale,
                        trackRange = 0.8f..1.1f
                    )

                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                Icons.Rounded.AspectRatio,
                                contentDescription = stringResource(id = R.string.settings_page_scale),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                            Column(
                                modifier = Modifier.weight(1f)
                            ) {
                                Text(
                                    text = stringResource(R.string.settings_page_scale),
                                    style = MaterialTheme.typography.titleMedium,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                                Text(
                                    text = stringResource(id = R.string.settings_page_scale_summary),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            Text(
                                text = "${(sliderState.value * 100).toInt()}%",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }

                        CapsuleSlider(
                            state = sliderState,
                            onValueChangeFinished = { actions.onSetPageScale(sliderState.value) },
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }
            }

            item {
                TonalCard(modifier = Modifier.padding(horizontal = 16.dp)) {
                    val sliderState = rememberSliderState(
                        value = uiState.moduleDescriptionMaxLines.toFloat(),
                        steps = 3,
                        trackRange = 1f..5f
                    )

                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                Icons.Rounded.Description,
                                contentDescription = stringResource(id = R.string.settings_module_description_max_lines),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                            Column(
                                modifier = Modifier.weight(1f)
                            ) {
                                Text(
                                    text = stringResource(R.string.settings_module_description_max_lines),
                                    style = MaterialTheme.typography.titleMedium,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                                Text(
                                    text = stringResource(id = R.string.settings_module_description_max_lines_summary),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            Text(
                                text = "${sliderState.value.roundToInt()} " + stringResource(R.string.unit_lines),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }

                        CapsuleSlider(
                            state = sliderState,
                            onValueChangeFinished = {
                                actions.onSetModuleDescriptionMaxLines(sliderState.value.roundToInt())
                            },
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }
            }


            item {
                Spacer(modifier = Modifier.height(16.dp + navBars.calculateBottomPadding() + captionBar.calculateBottomPadding()))
            }
        }
    }

    if (showHomeTitleDialog) {
        AlertDialog(
            onDismissRequest = { showHomeTitleDialog = false },
            title = { Text(stringResource(R.string.settings_home_title)) },
            text = {
                Column {
                    Text(
                        text = stringResource(R.string.settings_home_title_hint),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(12.dp))
                    OutlinedTextField(
                        value = homeTitleDraft,
                        onValueChange = { homeTitleDraft = it },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        label = { Text(stringResource(R.string.settings_home_title)) },
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        actions.onSetCustomHomeTitle(homeTitleDraft)
                        showHomeTitleDialog = false
                    },
                ) {
                    Text(stringResource(android.R.string.ok))
                }
            },
            dismissButton = {
                TextButton(onClick = { showHomeTitleDialog = false }) {
                    Text(stringResource(android.R.string.cancel))
                }
            },
        )
    }

    if (showResetThemeDialog) {
        ExpressiveConfirmDialog(
            title = stringResource(R.string.theme_reset_confirm_title),
            message = stringResource(R.string.theme_reset_confirm_message),
            confirmText = stringResource(R.string.theme_reset),
            dismissText = stringResource(android.R.string.cancel),
            onConfirm = {
                showResetThemeDialog = false
                actions.onResetBackgroundAppearance()
            },
            onDismiss = { showResetThemeDialog = false },
        )
    }
}

@Composable
private fun BackgroundSliderHeader(
    icon: ImageVector,
    title: String,
    summary: String,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = title,
            tint = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = summary,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}


@Composable
private fun ColorButtonMaterial(
    color: Color,
    isSelected: Boolean,
    isDark: Boolean,
    isAmoled: Boolean = false,
    paletteStyle: PaletteStyle = PaletteStyle.TonalSpot,
    colorSpec: ColorSpec.SpecVersion = ColorSpec.SpecVersion.SPEC_2025,
    onClick: () -> Unit
) {
    val haptic = LocalHapticFeedback.current
    val colorScheme = rememberKernelSUColorScheme(
        seedColor = color,
        isDark = isDark,
        isAmoled = isAmoled,
        paletteStyle = paletteStyle,
        colorSpec = colorSpec,
    )

    Surface(
        onClick = {
            haptic.performHapticFeedback(HapticFeedbackType.VirtualKey)
            onClick()
        },
        shape = RoundedCornerShape(20.dp),
        color = colorScheme.surfaceContainer,
        modifier = Modifier.size(72.dp)
    ) {
        Box(contentAlignment = Alignment.Center) {
            Canvas(modifier = Modifier.size(48.dp)) {
                drawArc(
                    color = colorScheme.primaryContainer,
                    startAngle = 180f,
                    sweepAngle = 180f,
                    useCenter = true
                )
                drawArc(
                    color = colorScheme.tertiaryContainer,
                    startAngle = 0f,
                    sweepAngle = 180f,
                    useCenter = true
                )
            }

            val scale by animateFloatAsState(targetValue = if (isSelected) 1.1f else 1.0f)
            Box(
                modifier = Modifier.graphicsLayer {
                    scaleX = scale
                    scaleY = scale
                },
                contentAlignment = Alignment.Center
            ) {
                AnimatedVisibility(
                    visible = isSelected,
                    enter = fadeIn() + scaleIn(initialScale = 0.8f),
                    exit = fadeOut() + scaleOut(targetScale = 0.8f)
                ) {
                    Box(
                        modifier = Modifier
                            .size(56.dp)
                            .border(2.dp, colorScheme.primary, CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Box(
                            modifier = Modifier
                                .size(24.dp)
                                .clip(CircleShape)
                                .background(colorScheme.primary, CircleShape)
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.Check,
                                contentDescription = null,
                                tint = colorScheme.onPrimary,
                                modifier = Modifier
                                    .align(Alignment.Center)
                                    .size(16.dp)
                            )
                        }
                    }
                }
                AnimatedVisibility(
                    visible = !isSelected,
                    enter = fadeIn() + scaleIn(initialScale = 0.8f),
                    exit = fadeOut() + scaleOut(targetScale = 0.8f)
                ) {
                    Box(
                        modifier = Modifier
                            .size(20.dp)
                            .background(colorScheme.primary, CircleShape)
                    )
                }
            }
        }
    }
}

/** Item index of an appearance section; conditional items shift later indices. */
private fun appearanceSectionIndex(section: String?): Int? {
    val id = section?.trim()?.lowercase()?.replace('-', '_') ?: return null
    val hasPredictive = Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
    return when (id) {
        "preview" -> 0
        "background" -> 1
        "theme_package" -> 2
        "appearance" -> 3
        "colors" -> 4
        "color_mode" -> 5
        "palette" -> 6
        "chrome", "bottom_bar" -> 7
        "predictive_back" -> if (hasPredictive) 8 else 7
        "behavior", "gestures" -> if (hasPredictive) 9 else 8
        "scale" -> if (hasPredictive) 10 else 9
        "module_description" -> if (hasPredictive) 11 else 10
        else -> null
    }
}
