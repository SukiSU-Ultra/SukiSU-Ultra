package com.sukisu.ultra.ui.screen.colorpalette

import com.sukisu.ultra.ui.component.miuix.MiuixTextButtonAffectedByBackground
import com.sukisu.ultra.ai.api.R as AiR
import com.sukisu.ultra.ai.api.AiFeatureBridge
import android.annotation.SuppressLint
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
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.selection.selectable
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
import com.sukisu.ultra.ui.component.Storefront
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
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.component.miuix.AppScaffold
import com.sukisu.ultra.ui.component.miuix.ScaleDialog
import com.sukisu.ultra.ui.component.bottombar.BottomBarDestination
import com.sukisu.ultra.ui.util.BottomBarIconSlot
import coil.compose.AsyncImage
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
import com.sukisu.ultra.ui.util.HomeCardImageStyle
import com.sukisu.ultra.ui.util.HomeLayout
import com.sukisu.ultra.ui.util.HomeStatusAlignment
import com.sukisu.ultra.ui.util.HomeStatusStyle
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
import top.yukonga.miuix.kmp.utils.PressFeedbackType
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@SuppressLint("ConfigurationScreenWidthHeight")
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
    var homeStatusScaleDraft by remember { mutableFloatStateOf(state.homeStatusScale) }
    var homePillScaleDraft by remember { mutableFloatStateOf(state.homePillScale) }
    var homeStatusWidthDraft by remember { mutableFloatStateOf(state.homeStatusWidthFraction) }
    val sliderCommitted = remember { mutableIntStateOf(0) }
    // Values changed outside the sliders (import, reset, AI bridge) replace the drafts. Reads the
    // counter so finishing a drag does not re-run this and yank the thumbs.
    LaunchedEffect(
        state.cardBackgroundAlphaPercent,
        state.customBackgroundBlurPercent,
        state.customBackgroundScrimPercent,
        state.homeStatusScale,
        state.homePillScale,
        state.homeStatusWidthFraction,
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
        if (homeStatusScaleDraft != state.homeStatusScale) {
            homeStatusScaleDraft = state.homeStatusScale
        }
        if (homePillScaleDraft != state.homePillScale) {
            homePillScaleDraft = state.homePillScale
        }
        if (homeStatusWidthDraft != state.homeStatusWidthFraction) {
            homeStatusWidthDraft = state.homeStatusWidthFraction
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
        state.homeLayout,
        state.homeStatusAlignment,
        homeStatusScaleDraft,
        homePillScaleDraft,
        homeStatusWidthDraft,
        state.homeCardImageStyle,
        state.showHomeCardImageWithoutBackground,
        state.appearance,
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
            homeLayout = state.homeLayout,
            homeStatusAlignment = state.homeStatusAlignment,
            homeStatusScale = homeStatusScaleDraft,
            homePillScale = homePillScaleDraft,
            homeStatusWidthFraction = homeStatusWidthDraft,
            homeCardImageStyle = state.homeCardImageStyle,
            showHomeCardImageWithoutBackground = state.showHomeCardImageWithoutBackground,
            appearance = state.appearance,
        )
    }
    // The category box replaces the old accordion list: only one category is composed at a time.
    var selectedCategoryKey by rememberSaveable {
        mutableStateOf(
            (ThemeSettingsCategory.fromSection(section) ?: ThemeSettingsCategory.COLORS).name
        )
    }
    val selectedCategory = ThemeSettingsCategory.entries
        .firstOrNull { it.name == selectedCategoryKey }
        ?: ThemeSettingsCategory.COLORS
    LaunchedEffect(section) {
        ThemeSettingsCategory.fromSection(section)?.let { selectedCategoryKey = it.name }
    }
    val contentListState = rememberLazyListState()
    val pinnedHeader = LocalConfiguration.current.screenHeightDp >= 600
    var categorySelectionSeen by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(selectedCategory) {
        if (categorySelectionSeen) {
            // Short screens keep the preview and the category box inside the list.
            contentListState.scrollToItem(if (pinnedHeader) 0 else 1)
        } else {
            categorySelectionSeen = true
        }
    }
    val compactModeLabel = stringResource(
        when {
            state.currentColorMode.isSystem -> R.string.settings_theme_mode_system
            state.currentColorMode.isAmoled -> R.string.theme_mode_amoled
            state.currentColorMode.isDark -> R.string.settings_theme_mode_dark
            else -> R.string.settings_theme_mode_light
        }
    ) + " · " + state.currentPaletteStyle.name
    var showExportDialog by rememberSaveable { mutableStateOf(false) }
    var showFullPreview by rememberSaveable { mutableStateOf(false) }
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
    var pendingBottomBarIconSlot by rememberSaveable { mutableStateOf<String?>(null) }
    val bottomBarIconLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.PickVisualMedia()
    ) { uri: Uri? ->
        val slot = pendingBottomBarIconSlot?.let(BottomBarIconSlot::fromKey)
        if (uri != null && slot != null) {
            actions.onPickBottomBarIcon(context, slot, uri)
        }
        pendingBottomBarIconSlot = null
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
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
            ) {
                if (pinnedHeader) {
                    MiuixCompactPreviewCard(
                        spec = previewSpec,
                        modeLabel = compactModeLabel,
                        onClick = { showFullPreview = true },
                        modifier = Modifier
                            .padding(horizontal = 12.dp)
                            .padding(top = 8.dp),
                    )
                    MiuixCategoryGrid(
                        selected = selectedCategory,
                        onSelect = { selectedCategoryKey = it.name },
                        modifier = Modifier
                            .padding(horizontal = 12.dp)
                            .padding(top = 8.dp),
                    )
                }
                LazyColumn(
                    state = contentListState,
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                        .scrollEndHaptic()
                        .overScrollVertical()
                        .nestedScroll(scrollBehavior.nestedScrollConnection)
                        .padding(horizontal = 12.dp),
                    contentPadding = PaddingValues(top = 12.dp),
                    overscrollEffect = null,
                ) {
                    if (!pinnedHeader) {
                        item {
                            MiuixCompactPreviewCard(
                                spec = previewSpec,
                                modeLabel = compactModeLabel,
                                onClick = { showFullPreview = true },
                            )
                            MiuixCategoryGrid(
                                selected = selectedCategory,
                                onSelect = { selectedCategoryKey = it.name },
                                modifier = Modifier.padding(top = 8.dp, bottom = 12.dp),
                            )
                        }
                    }
                    item {
                        val pickImageLauncher = rememberLauncherForActivityResult(
                            contract = ActivityResultContracts.PickVisualMedia()
                        ) { uri: Uri? ->
                            uri?.let { actions.onPickCustomBackground(context, it) }
                        }
                        val hasCustomBg = state.customBackgroundUri.isNotEmpty()
                        val usingSystemWallpaper = state.useSystemWallpaper

                    if (selectedCategory == ThemeSettingsCategory.COLORS) {
                    AppCard(
                        modifier = Modifier
                            .bringIntoViewRequester(sectionRequester("colors"))
                            .fillMaxWidth(),
                    ) {
                        MiuixCategoryHeader(
                            title = stringResource(selectedCategory.titleRes),
                            summary = stringResource(selectedCategory.summaryRes),
                            icon = Icons.Rounded.Colorize,
                            expanded = colorsSectionExpanded,
                            onClick = {
                                actions.onSetColorsSectionExpanded(!colorsSectionExpanded)
                            },
                        )
                        AnimatedVisibility(
                            visible = true,
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
                                HorizontalDivider()
                                ArrowPreference(
                                    title = stringResource(R.string.appearance_overlay_title),
                                    summary = stringResource(
                                        if (state.customAppearanceJson.isNotBlank()) {
                                            R.string.appearance_overlay_active
                                        } else {
                                            R.string.appearance_overlay_summary
                                        }
                                    ),
                                    startAction = {
                                        Icon(
                                            imageVector = Icons.Rounded.Palette,
                                            modifier = Modifier.padding(end = 6.dp),
                                            contentDescription = stringResource(R.string.appearance_overlay_title),
                                            tint = colorScheme.onBackground,
                                        )
                                    },
                                    onClick = actions.onOpenAppearanceEditor,
                                )
                            }
                        }
                    }
                    }

                    if (selectedCategory == ThemeSettingsCategory.BACKGROUND) {
                    AppCard(
                        modifier = Modifier
                            .bringIntoViewRequester(sectionRequester("background"))
                            .fillMaxWidth(),
                        colors = backgroundAwareCardColors(),
                    ) {
                        MiuixCategoryHeader(
                            title = stringResource(selectedCategory.titleRes),
                            summary = stringResource(selectedCategory.summaryRes),
                            icon = Icons.Rounded.Wallpaper,
                            expanded = backgroundSectionExpanded,
                            onClick = {
                                actions.onSetBackgroundSectionExpanded(!backgroundSectionExpanded)
                            },
                        )
                        AnimatedVisibility(
                            visible = true,
                            enter = expandVertically() + fadeIn(),
                            exit = shrinkVertically() + fadeOut(),
                        ) {
                            Column {
                                HorizontalDivider()
                                // A bar treatment, not a wallpaper property: keep it available with
                                // and without a custom background image.
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                    SwitchPreference(
                                        title = stringResource(id = R.string.settings_progressive_blur),
                                        summary = stringResource(id = R.string.settings_progressive_blur_summary),
                                        startAction = {
                                            Icon(
                                                imageVector = Icons.Rounded.BlurOn,
                                                modifier = Modifier.padding(end = 6.dp),
                                                contentDescription = stringResource(id = R.string.settings_progressive_blur),
                                                tint = colorScheme.onBackground
                                            )
                                        },
                                        checked = state.enableProgressiveBlur,
                                        onCheckedChange = actions.onSetEnableProgressiveBlur,
                                    )
                                    HorizontalDivider()
                                }
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
                    }

                    if (selectedCategory == ThemeSettingsCategory.ICON_TEXT) {
                    AppCard(
                        modifier = Modifier
                            .bringIntoViewRequester(sectionRequester("appearance"))
                            .fillMaxWidth(),
                    ) {
                        MiuixCategoryHeader(
                            title = stringResource(selectedCategory.titleRes),
                            summary = stringResource(selectedCategory.summaryRes),
                            icon = Icons.Rounded.Home,
                            expanded = appearanceSectionExpanded,
                            onClick = {
                                actions.onSetAppearanceSectionExpanded(!appearanceSectionExpanded)
                            },
                        )
                        AnimatedVisibility(
                            visible = true,
                            enter = expandVertically() + fadeIn(),
                            exit = shrinkVertically() + fadeOut(),
                        ) {
                            Column {
                                HorizontalDivider()
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

                            }
                        }
                    }
                    }
                    if (selectedCategory == ThemeSettingsCategory.HOME_CARD) {
                    AppCard(
                        modifier = Modifier
                            .bringIntoViewRequester(sectionRequester("home_card"))
                            .fillMaxWidth(),
                    ) {
                        MiuixCategoryHeader(
                            title = stringResource(selectedCategory.titleRes),
                            summary = stringResource(selectedCategory.summaryRes),
                            icon = Icons.Rounded.Home,
                            expanded = homeCardSectionExpanded,
                            onClick = {
                                actions.onSetHomeCardSectionExpanded(!homeCardSectionExpanded)
                            },
                        )
                        AnimatedVisibility(
                            visible = true,
                            enter = expandVertically() + fadeIn(),
                            exit = shrinkVertically() + fadeOut(),
                        ) {
                            Column {
                                HorizontalDivider()
                                TabRowWithContour(
                                    tabs = listOf(
                                        stringResource(R.string.home_layout_classic),
                                        stringResource(R.string.home_layout_immersive),
                                    ),
                                    selectedTabIndex = if (state.homeLayout == HomeLayout.IMMERSIVE) 1 else 0,
                                    onTabSelected = { index ->
                                        actions.onSetHomeLayout(
                                            if (index == 1) HomeLayout.IMMERSIVE else HomeLayout.CLASSIC
                                        )
                                    },
                                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                                    colors = TabRowDefaults.tabRowColors(
                                        backgroundColor = backgroundAwareColor(colorScheme.surfaceContainerHighest),
                                        selectedBackgroundColor = backgroundAwareColor(colorScheme.surfaceContainer),
                                    ),
                                )
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
                                if (state.homeLayout == HomeLayout.CLASSIC && state.homeCardImagePath.isNotBlank()) {
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
                                }
                                if (state.homeLayout == HomeLayout.IMMERSIVE) {
                                    if (state.homeCardImagePath.isNotBlank()) {
                                        OverlayDropdownPreference(
                                            title = stringResource(R.string.settings_home_card_image_position),
                                            items = listOf(
                                                stringResource(R.string.home_card_image_position_banner),
                                                stringResource(R.string.home_card_image_position_off),
                                            ),
                                            startAction = {
                                                Icon(
                                                    Icons.Rounded.AspectRatio,
                                                    modifier = Modifier.padding(end = 8.dp),
                                                    contentDescription = stringResource(R.string.settings_home_card_image_position),
                                                    tint = colorScheme.onBackground,
                                                )
                                            },
                                            selectedIndex = when (state.homeCardImageStyle) {
                                                HomeCardImageStyle.BANNER -> 0
                                                HomeCardImageStyle.OFF -> 1
                                            },
                                            onSelectedIndexChange = { index ->
                                                actions.onSetHomeCardImageStyle(
                                                    if (index == 0) {
                                                        HomeCardImageStyle.BANNER
                                                    } else {
                                                        HomeCardImageStyle.OFF
                                                    }
                                                )
                                            },
                                        )
                                        if (state.homeCardImageStyle == HomeCardImageStyle.BANNER) {
                                        SwitchPreference(
                                            title = stringResource(R.string.settings_show_home_card_image_without_background),
                                            summary = stringResource(R.string.settings_show_home_card_image_without_background_summary),
                                            startAction = {
                                                Icon(
                                                    Icons.Rounded.Wallpaper,
                                                    modifier = Modifier.padding(end = 8.dp),
                                                    contentDescription = stringResource(R.string.settings_show_home_card_image_without_background),
                                                    tint = colorScheme.onBackground,
                                                )
                                            },
                                            checked = state.showHomeCardImageWithoutBackground,
                                            onCheckedChange = actions.onSetShowHomeCardImageWithoutBackground,
                                        )
                                        }
                                    }
                                    OverlayDropdownPreference(
                                        title = stringResource(R.string.settings_home_status_alignment),
                                        items = listOf(
                                            stringResource(R.string.home_status_alignment_start),
                                            stringResource(R.string.home_status_alignment_end),
                                        ),
                                        startAction = {
                                            Icon(
                                                Icons.Rounded.AspectRatio,
                                                modifier = Modifier.padding(end = 8.dp),
                                                contentDescription = stringResource(R.string.settings_home_status_alignment),
                                                tint = colorScheme.onBackground,
                                            )
                                        },
                                        selectedIndex = if (
                                            state.homeStatusAlignment == HomeStatusAlignment.END
                                        ) {
                                            1
                                        } else {
                                            0
                                        },
                                        onSelectedIndexChange = { index ->
                                            actions.onSetHomeStatusAlignment(
                                                if (index == 1) {
                                                    HomeStatusAlignment.END
                                                } else {
                                                    HomeStatusAlignment.START
                                                }
                                            )
                                        },
                                    )
                                    MiuixBackgroundSliderSection(
                                        title = stringResource(R.string.settings_home_pill_scale),
                                        summary = stringResource(
                                            R.string.settings_home_pill_scale_summary,
                                            (homePillScaleDraft * 100).roundToInt(),
                                        ),
                                        value = homePillScaleDraft,
                                        valueRange = HomeStatusStyle.PILL_SCALE_MIN..HomeStatusStyle.PILL_SCALE_MAX,
                                        onValueChange = { homePillScaleDraft = it },
                                        onValueChangeFinished = {
                                            actions.onSetHomePillScale(homePillScaleDraft)
                                        },
                                        startLabel = "50%",
                                        endLabel = "150%",
                                    )
                                    if (state.homeCardImageStyle == HomeCardImageStyle.BANNER) {
                                    MiuixBackgroundSliderSection(
                                        title = stringResource(R.string.settings_home_status_scale),
                                        summary = stringResource(
                                            R.string.settings_home_status_scale_summary,
                                            (homeStatusScaleDraft * 100).roundToInt(),
                                        ),
                                        value = homeStatusScaleDraft,
                                        valueRange = HomeStatusStyle.SCALE_MIN..HomeStatusStyle.SCALE_MAX,
                                        onValueChange = { homeStatusScaleDraft = it },
                                        onValueChangeFinished = {
                                            actions.onSetHomeStatusScale(homeStatusScaleDraft)
                                        },
                                        startLabel = "50%",
                                        endLabel = "300%",
                                    )
                                    MiuixBackgroundSliderSection(
                                        title = stringResource(R.string.settings_home_status_width),
                                        summary = stringResource(
                                            R.string.settings_home_status_width_summary,
                                            (homeStatusWidthDraft * 100).roundToInt(),
                                        ),
                                        value = homeStatusWidthDraft,
                                        valueRange = HomeStatusStyle.WIDTH_MIN..HomeStatusStyle.WIDTH_MAX,
                                        onValueChange = { homeStatusWidthDraft = it },
                                        onValueChangeFinished = {
                                            actions.onSetHomeStatusWidthFraction(homeStatusWidthDraft)
                                        },
                                        startLabel = "45%",
                                        endLabel = "100%",
                                    )
                                    }
                                }
                                val canUseStickers = state.homeLayout == HomeLayout.CLASSIC || (
                                    state.homeCardImageStyle == HomeCardImageStyle.BANNER &&
                                        state.homeCardImagePath.isNotBlank() &&
                                        (state.backgroundPath.isNotBlank() ||
                                            state.showHomeCardImageWithoutBackground)
                                    )
                                val stickerBlockedByBackground =
                                    state.homeCardImageStyle == HomeCardImageStyle.BANNER &&
                                        state.homeCardImagePath.isNotBlank() &&
                                        state.backgroundPath.isBlank() &&
                                        !state.showHomeCardImageWithoutBackground
                                if (canUseStickers) {
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
                                                containerColor = if (state.homeLayout == HomeLayout.IMMERSIVE) {
                                                    colorScheme.surfaceContainer
                                                } else {
                                                    colorScheme.secondaryContainer
                                                },
                                                contentColor = if (state.homeLayout == HomeLayout.IMMERSIVE) {
                                                    colorScheme.onSurface
                                                } else {
                                                    colorScheme.onSecondaryContainer
                                                },
                                                accentColor = colorScheme.primary,
                                                accentContentColor = colorScheme.onPrimary,
                                                layout = state.homeLayout,
                                                imageStyle = state.homeCardImageStyle,
                                                statusScale = state.homeStatusScale,
                                                statusWidthFraction = state.homeStatusWidthFraction,
                                                pillScale = state.homePillScale,
                                                statusAlignment = state.homeStatusAlignment,
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
                                            val stickerSizeMax = if (state.homeLayout == HomeLayout.IMMERSIVE) {
                                                minOf(
                                                    HomeCardStickerTransform.SIZE_MAX,
                                                    0.9f * HomeStatusStyle.BannerHeight.value *
                                                        state.homeStatusScale / 360f,
                                                )
                                            } else {
                                                HomeCardStickerTransform.SIZE_MAX
                                            }
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
                                                value = editTransform.size.coerceIn(
                                                    HomeCardStickerTransform.SIZE_MIN,
                                                    stickerSizeMax,
                                                ),
                                                valueRange = HomeCardStickerTransform.SIZE_MIN..stickerSizeMax,
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
                                } else if (state.homeCardImageStyle == HomeCardImageStyle.BANNER) {
                                    BasicComponent(
                                        title = stringResource(R.string.settings_home_card_sticker),
                                        summary = stringResource(
                                            if (stickerBlockedByBackground) {
                                                R.string.settings_home_card_sticker_hidden
                                            } else {
                                                R.string.settings_home_card_sticker_banner_only
                                            }
                                        ),
                                        startAction = {
                                            Icon(
                                                Icons.Rounded.Star,
                                                modifier = Modifier.padding(end = 8.dp),
                                                contentDescription = stringResource(R.string.settings_home_card_sticker),
                                                tint = colorScheme.onBackground,
                                            )
                                        },
                                    )
                                }
                                if (state.homeCardImagePath.isNotBlank()) {
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
                    }

                    if (selectedCategory == ThemeSettingsCategory.BOTTOM_BAR) {
                    AppCard(
                        modifier = Modifier
                            .bringIntoViewRequester(sectionRequester("bottom_bar"))
                            .fillMaxWidth(),
                    ) {
                        MiuixCategoryHeader(
                            title = stringResource(selectedCategory.titleRes),
                            summary = stringResource(selectedCategory.summaryRes),
                            icon = Icons.Rounded.CallToAction,
                            expanded = state.bottomBarSectionExpanded,
                            onClick = {
                                actions.onSetBottomBarSectionExpanded(
                                    !state.bottomBarSectionExpanded,
                                )
                            },
                        )
                        AnimatedVisibility(
                            visible = true,
                            enter = expandVertically() + fadeIn(),
                            exit = shrinkVertically() + fadeOut(),
                        ) {
                            Column {
                                HorizontalDivider()
                        val bottomBarIconPaths = uiState.bottomBarIcons
                        val bottomBarSlots = listOf(
                            BottomBarIconSlot.Home to R.string.settings_bottom_bar_icon_home,
                            BottomBarIconSlot.SuperUser to R.string.settings_bottom_bar_icon_superuser,
                            BottomBarIconSlot.Module to R.string.settings_bottom_bar_icon_module,
                            BottomBarIconSlot.Setting to R.string.settings_bottom_bar_icon_setting,
                        )
                        bottomBarSlots.forEach { (slot, labelRes) ->
                            val path = bottomBarIconPaths[slot.key]
                            val destination = BottomBarDestination.entries
                                .firstOrNull { it.key == slot.key }
                            ArrowPreference(
                                title = stringResource(labelRes),
                                summary = stringResource(
                                    if (path != null) {
                                        R.string.settings_bottom_bar_icon_custom_summary
                                    } else {
                                        R.string.settings_bottom_bar_icon_default_summary
                                    },
                                ),
                                startAction = {
                                    if (path != null) {
                                        AsyncImage(
                                            model = File(path),
                                            contentDescription = null,
                                            modifier = Modifier
                                                .padding(end = 6.dp)
                                                .size(24.dp),
                                        )
                                    } else if (destination != null) {
                                        Icon(
                                            imageVector = destination.icon,
                                            contentDescription = null,
                                            modifier = Modifier.padding(end = 6.dp),
                                            tint = colorScheme.onBackground,
                                        )
                                    }
                                },
                                endActions = {
                                    if (path != null) {
                                        MiuixTextButtonAffectedByBackground(
                                            text = stringResource(R.string.settings_clear),
                                            onClick = { actions.onClearBottomBarIcon(context, slot) },
                                        )
                                    }
                                },
                                onClick = {
                                    pendingBottomBarIconSlot = slot.key
                                    bottomBarIconLauncher.launch(
                                        PickVisualMediaRequest(
                                            ActivityResultContracts.PickVisualMedia.ImageOnly,
                                        ),
                                    )
                                },
                            )
                        }
                        HorizontalDivider()
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
                        }
                    }
                    }

                    if (selectedCategory == ThemeSettingsCategory.INTERACTION) {
                    AppCard(
                        modifier = Modifier
                            .bringIntoViewRequester(sectionRequester("behavior"))
                            .fillMaxWidth(),
                    ) {
                        MiuixCategoryHeader(
                            title = stringResource(selectedCategory.titleRes),
                            summary = stringResource(selectedCategory.summaryRes),
                            icon = Icons.Rounded.Swipe,
                            expanded = state.interactionSectionExpanded,
                            onClick = {
                                actions.onSetInteractionSectionExpanded(
                                    !state.interactionSectionExpanded,
                                )
                            },
                        )
                        AnimatedVisibility(
                            visible = true,
                            enter = expandVertically() + fadeIn(),
                            exit = shrinkVertically() + fadeOut(),
                        ) {
                            Column {
                                HorizontalDivider()
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
                        }
                    }
                    }

                    if (selectedCategory == ThemeSettingsCategory.DETAILS) {
                    AppCard(
                        modifier = Modifier
                            .bringIntoViewRequester(sectionRequester("module_description"))
                            .fillMaxWidth(),
                    ) {
                        MiuixCategoryHeader(
                            title = stringResource(selectedCategory.titleRes),
                            summary = stringResource(selectedCategory.summaryRes),
                            icon = Icons.Rounded.Description,
                            expanded = state.detailsSectionExpanded,
                            onClick = {
                                actions.onSetDetailsSectionExpanded(
                                    !state.detailsSectionExpanded,
                                )
                            },
                        )
                        AnimatedVisibility(
                            visible = true,
                            enter = expandVertically() + fadeIn(),
                            exit = shrinkVertically() + fadeOut(),
                        ) {
                            Column {
                                HorizontalDivider()
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
                    }
                    }

                    if (selectedCategory == ThemeSettingsCategory.THEME_PACKAGE) {
                    AppCard(
                        modifier = Modifier
                            .bringIntoViewRequester(sectionRequester("theme_package"))
                            .fillMaxWidth(),
                    ) {
                        MiuixCategoryHeader(
                            title = stringResource(selectedCategory.titleRes),
                            summary = when {
                                state.adaptiveDraftComplete ->
                                    stringResource(R.string.theme_adaptive_draft_ready)

                                state.adaptiveThemeActive && !state.currentColorMode.isSystem ->
                                    stringResource(
                                        R.string.theme_adaptive_active_forced,
                                        stringResource(
                                            if (state.currentColorMode.isDark) {
                                                R.string.theme_adaptive_mode_dark
                                            } else {
                                                R.string.theme_adaptive_mode_light
                                            },
                                        ),
                                    )

                                state.adaptiveThemeActive ->
                                    stringResource(R.string.theme_adaptive_active)

                                else ->
                                    stringResource(selectedCategory.summaryRes)
                            },
                            icon = Icons.Rounded.Palette,
                            expanded = themePackageSectionExpanded,
                            onClick = {
                                actions.onSetThemePackageSectionExpanded(!themePackageSectionExpanded)
                            },
                        )
                        AnimatedVisibility(
                            visible = true,
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
                                            Icons.Rounded.Storefront,
                                            modifier = Modifier.padding(end = 6.dp),
                                            contentDescription = customText(CustomTextKey.PAGE_THEME_STORE),
                                            tint = colorScheme.onBackground
                                        )
                                    },
                                    onClick = actions.onOpenThemeStore,
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
                                BasicComponent(
                                    title = stringResource(id = R.string.theme_adaptive_builder_title),
                                    summary = stringResource(id = R.string.theme_adaptive_builder_summary),
                                    startAction = {
                                        Icon(
                                            Icons.Rounded.AutoAwesome,
                                            modifier = Modifier.padding(end = 6.dp),
                                            contentDescription = stringResource(
                                                id = R.string.theme_adaptive_builder_title,
                                            ),
                                            tint = colorScheme.onBackground
                                        )
                                    },
                                    onClick = actions.onOpenAdaptiveThemeBuilder,
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
                            }
                        }
                    }
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
        adaptive = state.adaptiveThemeActive || state.adaptiveDraftComplete,
        hasCustomColors = state.customColorsPresent,
        hasImageEffects = state.imageEffectsPresent,
        immersiveHome = state.homeLayout == HomeLayout.IMMERSIVE,
        hasBottomBarIcons = uiState.bottomBarIcons.isNotEmpty(),
        onUpload = { options ->
            showExportDialog = false
            actions.onUploadTheme(context, options)
        },
    )

    ThemeFullscreenPreviewDialog(
        show = showFullPreview,
        onDismiss = { showFullPreview = false },
    ) { previewModifier, page ->
        if (page == 0) {
            ThemePreviewMiuix(
                spec = previewSpec,
                modifier = previewModifier,
                expanded = true,
            )
        } else {
            ThemePreviewMaterial(
                spec = previewSpec,
                modifier = previewModifier,
                expanded = true,
            )
        }
    }
}

@Composable
private fun MiuixCompactPreviewCard(
    spec: ThemePreviewSpec,
    modeLabel: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    AppCard(
        modifier = modifier.fillMaxWidth(),
        insideMargin = PaddingValues(0.dp),
        onClick = onClick,
        pressFeedbackType = PressFeedbackType.Sink,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            ThemePreviewMiuix(
                spec = spec,
                modifier = Modifier.width(88.dp),
                compact = true,
            )
            Spacer(modifier = Modifier.width(16.dp))
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(
                    text = stringResource(R.string.theme_preview_caption_miuix),
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = colorScheme.onSurface,
                )
                Text(
                    text = modeLabel,
                    fontSize = 12.sp,
                    color = colorScheme.onSurfaceVariantSummary,
                )
                ThemePaletteSwatches(
                    colors = listOf(
                        colorScheme.primary,
                        colorScheme.secondaryContainer,
                        colorScheme.tertiaryContainer,
                        colorScheme.surfaceContainerHighest,
                    ),
                )
                Text(
                    text = stringResource(R.string.theme_preview_compact_summary),
                    fontSize = 11.sp,
                    color = colorScheme.onSurfaceVariantSummary,
                )
            }
        }
    }
}

@Composable
private fun MiuixCategoryGrid(
    selected: ThemeSettingsCategory,
    onSelect: (ThemeSettingsCategory) -> Unit,
    modifier: Modifier = Modifier,
) {
    AppCard(
        modifier = modifier.fillMaxWidth(),
        insideMargin = PaddingValues(8.dp),
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            ThemeSettingsCategory.entries.chunked(4).forEach { row ->
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    row.forEach { category ->
                        MiuixCategoryTile(
                            category = category,
                            selected = category == selected,
                            onClick = { onSelect(category) },
                            modifier = Modifier.weight(1f),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun MiuixCategoryTile(
    category: ThemeSettingsCategory,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val background by animateColorAsState(
        targetValue = backgroundAwareColor(
            if (selected) colorScheme.primary else colorScheme.surfaceContainerHighest
        ),
        label = "ThemeCategoryBackground",
    )
    val contentColor = if (selected) colorScheme.onPrimary else colorScheme.onSurface
    val haptic = LocalHapticFeedback.current
    Column(
        modifier = modifier
            .height(48.dp)
            .clip(RoundedCornerShape(14.dp))
            .background(background)
            .selectable(
                selected = selected,
                onClick = {
                    haptic.performHapticFeedback(HapticFeedbackType.ContextClick)
                    onClick()
                },
                role = Role.Tab,
            )
            .padding(horizontal = 4.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            imageVector = category.icon,
            contentDescription = null,
            tint = contentColor,
            modifier = Modifier.size(18.dp),
        )
        Spacer(Modifier.height(2.dp))
        Text(
            text = stringResource(category.labelRes),
            fontSize = 11.sp,
            color = contentColor,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun MiuixCategoryHeader(
    title: String,
    summary: String,
    icon: ImageVector,
    @Suppress("UNUSED_PARAMETER") expanded: Boolean,
    @Suppress("UNUSED_PARAMETER") onClick: () -> Unit,
) {
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

