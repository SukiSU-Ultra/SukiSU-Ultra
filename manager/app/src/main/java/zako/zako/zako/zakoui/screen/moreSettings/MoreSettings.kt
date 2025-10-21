package zako.zako.zako.zakoui.screen.moreSettings

import android.annotation.SuppressLint
import android.content.Context
import android.net.Uri
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import zako.zako.zako.zakoui.screen.moreSettings.util.LocaleHelper
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.theme.component.ImageEditorDialog
import com.sukisu.ultra.ui.component.KsuIsValid
import com.sukisu.ultra.ui.theme.*
import com.sukisu.ultra.ui.util.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import zako.zako.zako.zakoui.screen.moreSettings.component.ColorCircle
import zako.zako.zako.zakoui.screen.moreSettings.component.LanguageSelectionDialog
import zako.zako.zako.zakoui.screen.moreSettings.component.MoreSettingsDialogs
import zako.zako.zako.zakoui.screen.moreSettings.component.SettingItem
import zako.zako.zako.zakoui.screen.moreSettings.component.SettingsCard
import zako.zako.zako.zakoui.screen.moreSettings.component.SettingsDivider
import zako.zako.zako.zakoui.screen.moreSettings.component.SwitchSettingItem
import zako.zako.zako.zakoui.screen.moreSettings.state.MoreSettingsState
import kotlin.math.roundToInt

@SuppressLint("LocalContextConfigurationRead", "LocalContextResourcesRead", "ObsoleteSdkInt")
@OptIn(ExperimentalMaterial3Api::class)
@Destination<RootGraph>
@Composable
fun MoreSettingsScreen(
    navigator: DestinationsNavigator
) {
    // 顶部滚动行为
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val prefs = remember { context.getSharedPreferences("settings", Context.MODE_PRIVATE) }
    val systemIsDark = isSystemInDarkTheme()

    // 创建设置状态管理器
    val settingsState = remember { MoreSettingsState(context, prefs, systemIsDark) }
    val settingsHandlers = remember { MoreSettingsHandlers(context, prefs, settingsState) }

    // 图片选择器
    val pickImageLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            settingsState.selectedImageUri = it
            settingsState.showImageEditor = true
        }
    }

    // 初始化设置
    LaunchedEffect(Unit) {
        settingsHandlers.initializeSettings()
    }

    // 显示图片编辑对话框
    if (settingsState.showImageEditor && settingsState.selectedImageUri != null) {
        ImageEditorDialog(
            imageUri = settingsState.selectedImageUri!!,
            onDismiss = {
                settingsState.showImageEditor = false
                settingsState.selectedImageUri = null
            },
            onConfirm = { transformedUri ->
                settingsHandlers.handleCustomBackground(transformedUri)
                settingsState.showImageEditor = false
                settingsState.selectedImageUri = null
            }
        )
    }

    // 各种设置对话框
    MoreSettingsDialogs(
        state = settingsState,
        handlers = settingsHandlers
    )

    Scaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = stringResource(R.string.more_settings),
                        style = MaterialTheme.typography.titleLarge
                    )
                },
                navigationIcon = {
                    IconButton(onClick = { navigator.popBackStack() }) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.back)
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerLow.copy(alpha = CardConfig.cardAlpha),
                    scrolledContainerColor = MaterialTheme.colorScheme.surfaceContainerLow.copy(alpha = CardConfig.cardAlpha)
                ),
                windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
                scrollBehavior = scrollBehavior
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal)
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp)
                .padding(top = 8.dp)
        ) {
            // 外观设置
            AppearanceSettings(
                state = settingsState,
                handlers = settingsHandlers,
                pickImageLauncher = pickImageLauncher,
                coroutineScope = coroutineScope
            )

            // 自定义设置
            CustomizationSettings(
                state = settingsState,
                handlers = settingsHandlers
            )

            // 高级设置
            KsuIsValid {
                AdvancedSettings(
                    state = settingsState,
                    handlers = settingsHandlers
                )
            }
        }
    }
}

@Composable
private fun AppearanceSettings(
    state: MoreSettingsState,
    handlers: MoreSettingsHandlers,
    pickImageLauncher: ActivityResultLauncher<String>,
    coroutineScope: CoroutineScope
) {
    SettingsCard(title = stringResource(R.string.appearance_settings)) {
        // 语言设置
        LanguageSetting(state = state)

        // 主题模式
        SettingItem(
            icon = Icons.Default.DarkMode,
            title = stringResource(R.string.theme_mode),
            subtitle = state.themeOptions[state.themeMode],
            onClick = { state.showThemeModeDialog = true }
        )

        // 动态颜色开关
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            SwitchSettingItem(
                icon = Icons.Filled.ColorLens,
                title = stringResource(R.string.dynamic_color_title),
                summary = stringResource(R.string.dynamic_color_summary),
                checked = state.useDynamicColor,
                onChange = handlers::handleDynamicColorChange
            )
        }

        // 主题色选择
        AnimatedVisibility(
            visible = Build.VERSION.SDK_INT < Build.VERSION_CODES.S || !state.useDynamicColor,
            enter = fadeIn() + expandVertically(),
            exit = fadeOut() + shrinkVertically()
        ) {
            ThemeColorSelection(state = state)
        }

        SettingsDivider()

        // DPI 设置
        DpiSettings(state = state, handlers = handlers)

        SettingsDivider()

        // 自定义背景设置
        CustomBackgroundSettings(
            state = state,
            handlers = handlers,
            pickImageLauncher = pickImageLauncher,
            coroutineScope = coroutineScope
        )
    }
}

@Composable
private fun CustomizationSettings(
    state: MoreSettingsState,
    handlers: MoreSettingsHandlers
) {
    SettingsCard(title = stringResource(R.string.custom_settings)) {
        // 图标切换
        SwitchSettingItem(
            icon = Icons.Default.Android,
            title = stringResource(R.string.icon_switch_title),
            summary = stringResource(R.string.icon_switch_summary),
            checked = state.useAltIcon,
            onChange = handlers::handleIconChange
        )

        // 显示更多模块信息
        SwitchSettingItem(
            icon = Icons.Filled.Info,
            title = stringResource(R.string.show_more_module_info),
            summary = stringResource(R.string.show_more_module_info_summary),
            checked = state.showMoreModuleInfo,
            onChange = handlers::handleShowMoreModuleInfoChange
        )

        // 简洁模式开关
        SwitchSettingItem(
            icon = Icons.Filled.Brush,
            title = stringResource(R.string.simple_mode),
            summary = stringResource(R.string.simple_mode_summary),
            checked = state.isSimpleMode,
            onChange = handlers::handleSimpleModeChange
        )

        SwitchSettingItem(
            icon = Icons.Filled.Brush,
            title = stringResource(R.string.kernel_simple_kernel),
            summary = stringResource(R.string.kernel_simple_kernel_summary),
            checked = state.isKernelSimpleMode,
            onChange = handlers::handleKernelSimpleModeChange
        )

        // 各种隐藏选项
        HideOptionsSettings(state = state, handlers = handlers)
    }
}

@Composable
private fun HideOptionsSettings(
    state: MoreSettingsState,
    handlers: MoreSettingsHandlers
) {
    // 隐藏内核版本号
    SwitchSettingItem(
        icon = Icons.Filled.VisibilityOff,
        title = stringResource(R.string.hide_kernel_kernelsu_version),
        summary = stringResource(R.string.hide_kernel_kernelsu_version_summary),
        checked = state.isHideVersion,
        onChange = handlers::handleHideVersionChange
    )

    // 隐藏模块数量等信息
    SwitchSettingItem(
        icon = Icons.Filled.VisibilityOff,
        title = stringResource(R.string.hide_other_info),
        summary = stringResource(R.string.hide_other_info_summary),
        checked = state.isHideOtherInfo,
        onChange = handlers::handleHideOtherInfoChange
    )

    // SuSFS 状态信息
    SwitchSettingItem(
        icon = Icons.Filled.VisibilityOff,
        title = stringResource(R.string.hide_susfs_status),
        summary = stringResource(R.string.hide_susfs_status_summary),
        checked = state.isHideSusfsStatus,
        onChange = handlers::handleHideSusfsStatusChange
    )

    // Zygisk 实现状态信息
    SwitchSettingItem(
        icon = Icons.Filled.VisibilityOff,
        title = stringResource(R.string.hide_zygisk_implement),
        summary = stringResource(R.string.hide_zygisk_implement_summary),
        checked = state.isHideZygiskImplement,
        onChange = handlers::handleHideZygiskImplementChange
    )

    if (Natives.version >= Natives.MINIMAL_SUPPORTED_KPM) {
        SwitchSettingItem(
            icon = Icons.Filled.VisibilityOff,
            title = stringResource(R.string.show_kpm_info),
            summary = stringResource(R.string.show_kpm_info_summary),
            checked = state.isShowKpmInfo,
            onChange = handlers::handleShowKpmInfoChange
        )
    }

    // 隐藏链接信息
    SwitchSettingItem(
        icon = Icons.Filled.VisibilityOff,
        title = stringResource(R.string.hide_link_card),
        summary = stringResource(R.string.hide_link_card_summary),
        checked = state.isHideLinkCard,
        onChange = handlers::handleHideLinkCardChange
    )

    // 隐藏标签行
    SwitchSettingItem(
        icon = Icons.Filled.VisibilityOff,
        title = stringResource(R.string.hide_tag_card),
        summary = stringResource(R.string.hide_tag_card_summary),
        checked = state.isHideTagRow,
        onChange = handlers::handleHideTagRowChange
    )
}

@Composable
private fun AdvancedSettings(
    state: MoreSettingsState,
    handlers: MoreSettingsHandlers
) {
    SettingsCard(title = stringResource(R.string.advanced_settings)) {
        // SELinux 开关
        SwitchSettingItem(
            icon = Icons.Filled.Security,
            title = stringResource(R.string.selinux),
            summary = if (state.selinuxEnabled)
                stringResource(R.string.selinux_enabled) else
                stringResource(R.string.selinux_disabled),
            checked = state.selinuxEnabled,
            onChange = handlers::handleSelinuxChange
        )

        // SuSFS 开关（仅在支持时显示）
        SusFSSettings(state = state, handlers = handlers)

        // 动态管理器设置
        if (Natives.version >= Natives.MINIMAL_SUPPORTED_DYNAMIC_MANAGER) {
            SettingItem(
                icon = Icons.Filled.Security,
                title = stringResource(R.string.dynamic_manager_title),
                subtitle = if (state.isDynamicSignEnabled) {
                    stringResource(R.string.dynamic_manager_enabled_summary, state.dynamicSignSize)
                } else {
                    stringResource(R.string.dynamic_manager_disabled)
                },
                onClick = { state.showDynamicSignDialog = true }
            )
        }
    }
}

@Composable
private fun SusFSSettings(
    state: MoreSettingsState,
    handlers: MoreSettingsHandlers
) {
    val suSFS = getSuSFS()
    val isSUS_SU = getSuSFSFeatures()

    if (suSFS == "Supported" && isSUS_SU == "CONFIG_KSU_SUSFS_SUS_SU") {
        SwitchSettingItem(
            icon = Icons.Filled.Security,
            title = stringResource(id = R.string.settings_susfs_toggle),
            summary = stringResource(id = R.string.settings_susfs_toggle_summary),
            checked = state.isSusFSEnabled,
            onChange = handlers::handleSusFSChange
        )
    }
}

@Composable
private fun ThemeColorSelection(state: MoreSettingsState) {
    SettingItem(
        icon = Icons.Default.Palette,
        title = stringResource(R.string.theme_color),
        subtitle = when (ThemeConfig.currentTheme) {
            is ThemeColors.Green -> stringResource(R.string.color_green)
            is ThemeColors.Purple -> stringResource(R.string.color_purple)
            is ThemeColors.Orange -> stringResource(R.string.color_orange)
            is ThemeColors.Pink -> stringResource(R.string.color_pink)
            is ThemeColors.Gray -> stringResource(R.string.color_gray)
            is ThemeColors.Yellow -> stringResource(R.string.color_yellow)
            else -> stringResource(R.string.color_default)
        },
        onClick = { state.showThemeColorDialog = true },
        trailingContent = {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(start = 8.dp)
            ) {
                val theme = ThemeConfig.currentTheme
                val isDark = isSystemInDarkTheme()

                ColorCircle(
                    color = if (isDark) theme.primaryDark else theme.primaryLight,
                    isSelected = false,
                    modifier = Modifier.padding(horizontal = 2.dp)
                )
                ColorCircle(
                    color = if (isDark) theme.secondaryDark else theme.secondaryLight,
                    isSelected = false,
                    modifier = Modifier.padding(horizontal = 2.dp)
                )
                ColorCircle(
                    color = if (isDark) theme.tertiaryDark else theme.tertiaryLight,
                    isSelected = false,
                    modifier = Modifier.padding(horizontal = 2.dp)
                )
            }
        }
    )
}

@Composable
private fun DpiSettings(
    state: MoreSettingsState,
    handlers: MoreSettingsHandlers
) {
    SettingItem(
        icon = Icons.Default.FormatSize,
        title = stringResource(R.string.app_dpi_title),
        subtitle = stringResource(R.string.app_dpi_summary),
        onClick = {},
        trailingContent = {
            Text(
                text = handlers.getDpiFriendlyName(state.tempDpi),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.primary
            )
        }
    )

    // DPI 滑动条和控制
    DpiSliderControls(state = state, handlers = handlers)
}

@Composable
private fun DpiSliderControls(
    state: MoreSettingsState,
    handlers: MoreSettingsHandlers
) {
    Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
        val sliderValue by animateFloatAsState(
            targetValue = state.tempDpi.toFloat(),
            label = "DPI Slider Animation"
        )

        Slider(
            value = sliderValue,
            onValueChange = { newValue ->
                state.tempDpi = newValue.toInt()
                state.isDpiCustom = !state.dpiPresets.containsValue(state.tempDpi)
            },
            valueRange = 160f..600f,
            steps = 11,
            colors = SliderDefaults.colors(
                thumbColor = MaterialTheme.colorScheme.primary,
                activeTrackColor = MaterialTheme.colorScheme.primary,
                inactiveTrackColor = MaterialTheme.colorScheme.surfaceVariant
            )
        )

        // DPI 预设按钮行
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp),
        ) {
            state.dpiPresets.forEach { (name, dpi) ->
                val isSelected = state.tempDpi == dpi
                val buttonColor = if (isSelected)
                    MaterialTheme.colorScheme.primaryContainer
                else
                    MaterialTheme.colorScheme.surfaceVariant

                Box(
                    modifier = Modifier
                        .weight(1f)
                        .padding(horizontal = 2.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(buttonColor)
                        .clickable {
                            state.tempDpi = dpi
                            state.isDpiCustom = false
                        }
                        .padding(vertical = 8.dp, horizontal = 4.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = name,
                        style = MaterialTheme.typography.labelMedium,
                        color = if (isSelected)
                            MaterialTheme.colorScheme.onPrimaryContainer
                        else
                            MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }

        Text(
            text = if (state.isDpiCustom)
                "${stringResource(R.string.dpi_size_custom)}: ${state.tempDpi}"
            else
                "${handlers.getDpiFriendlyName(state.tempDpi)}: ${state.tempDpi}",
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 8.dp)
        )

        Button(
            onClick = { state.showDpiConfirmDialog = true },
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp),
            enabled = state.tempDpi != state.currentDpi
        ) {
            Icon(
                Icons.Default.Check,
                contentDescription = null,
                modifier = Modifier.size(16.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(stringResource(R.string.dpi_apply_settings))
        }
    }
}

@Composable
private fun CustomBackgroundSettings(
    state: MoreSettingsState,
    handlers: MoreSettingsHandlers,
    pickImageLauncher: ActivityResultLauncher<String>,
    coroutineScope: CoroutineScope
) {
    // 自定义背景开关
    SwitchSettingItem(
        icon = Icons.Filled.Wallpaper,
        title = stringResource(id = R.string.settings_custom_background),
        summary = stringResource(id = R.string.settings_custom_background_summary),
        checked = state.isCustomBackgroundEnabled,
        onChange = { isChecked ->
            if (isChecked) {
                pickImageLauncher.launch("image/*")
            } else {
                handlers.handleRemoveCustomBackground()
            }
        }
    )

    // 透明度和亮度调节
    AnimatedVisibility(
        visible = ThemeConfig.customBackgroundUri != null,
        enter = fadeIn() + slideInVertically(),
        exit = fadeOut() + slideOutVertically()
    ) {
        BackgroundAdjustmentControls(
            state = state,
            handlers = handlers,
            coroutineScope = coroutineScope
        )
    }
}

@Composable
private fun BackgroundAdjustmentControls(
    state: MoreSettingsState,
    handlers: MoreSettingsHandlers,
    coroutineScope: CoroutineScope
) {
    Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
        // 透明度滑动条
        AlphaSlider(state = state, handlers = handlers, coroutineScope = coroutineScope)

        // 亮度调节滑动条
        DimSlider(state = state, handlers = handlers, coroutineScope = coroutineScope)
    }
}

@Composable
private fun AlphaSlider(
    state: MoreSettingsState,
    handlers: MoreSettingsHandlers,
    coroutineScope: CoroutineScope
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.padding(bottom = 4.dp)
    ) {
        Icon(
            Icons.Filled.Opacity,
            contentDescription = null,
            modifier = Modifier.size(20.dp),
            tint = MaterialTheme.colorScheme.primary
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = stringResource(R.string.settings_card_alpha),
            style = MaterialTheme.typography.titleSmall
        )
        Spacer(modifier = Modifier.weight(1f))
        Text(
            text = "${(state.cardAlpha * 100).roundToInt()}%",
            style = MaterialTheme.typography.labelMedium,
        )
    }

    val alphaSliderValue by animateFloatAsState(
        targetValue = state.cardAlpha,
        label = "Alpha Slider Animation"
    )

    Slider(
        value = alphaSliderValue,
        onValueChange = { newValue ->
            handlers.handleCardAlphaChange(newValue)
        },
        onValueChangeFinished = {
            coroutineScope.launch(Dispatchers.IO) {
                saveCardConfig(handlers.context)
            }
        },
        valueRange = 0f..1f,
        steps = 20,
        colors = SliderDefaults.colors(
            thumbColor = MaterialTheme.colorScheme.primary,
            activeTrackColor = MaterialTheme.colorScheme.primary,
            inactiveTrackColor = MaterialTheme.colorScheme.surfaceVariant
        )
    )
}

@Composable
private fun DimSlider(
    state: MoreSettingsState,
    handlers: MoreSettingsHandlers,
    coroutineScope: CoroutineScope
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.padding(top = 16.dp, bottom = 4.dp)
    ) {
        Icon(
            Icons.Filled.LightMode,
            contentDescription = null,
            modifier = Modifier.size(20.dp),
            tint = MaterialTheme.colorScheme.primary
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = stringResource(R.string.settings_card_dim),
            style = MaterialTheme.typography.titleSmall
        )
        Spacer(modifier = Modifier.weight(1f))
        Text(
            text = "${(state.cardDim * 100).roundToInt()}%",
            style = MaterialTheme.typography.labelMedium,
        )
    }

    val dimSliderValue by animateFloatAsState(
        targetValue = state.cardDim,
        label = "Dim Slider Animation"
    )

    Slider(
        value = dimSliderValue,
        onValueChange = { newValue ->
            handlers.handleCardDimChange(newValue)
        },
        onValueChangeFinished = {
            coroutineScope.launch(Dispatchers.IO) {
                saveCardConfig(handlers.context)
            }
        },
        valueRange = 0f..1f,
        steps = 20,
        colors = SliderDefaults.colors(
            thumbColor = MaterialTheme.colorScheme.primary,
            activeTrackColor = MaterialTheme.colorScheme.primary,
            inactiveTrackColor = MaterialTheme.colorScheme.surfaceVariant
        )
    )
}

fun saveCardConfig(context: Context) {
    CardConfig.save(context)
}

@Composable
private fun LanguageSetting(state: MoreSettingsState) {
    val context = LocalContext.current
    val language = stringResource(id = R.string.settings_language)

    // Compute display name based on current app locale
    val currentLanguageDisplay = remember(state.currentAppLocale) {
        val locale = state.currentAppLocale
        if (locale != null) {
            locale.getDisplayName(locale)
        } else {
            context.getString(R.string.language_system_default)
        }
    }

    SettingItem(
        icon = Icons.Filled.Translate,
        title = language,
        subtitle = currentLanguageDisplay,
        onClick = { state.showLanguageDialog = true }
    )

    // Language Selection Dialog
    if (state.showLanguageDialog) {
        LanguageSelectionDialog(
            onLanguageSelected = { newLocale ->
                // Update local state immediately
                state.currentAppLocale = LocaleHelper.getCurrentAppLocale(context)
                // Apply locale change immediately for Android < 13
                LocaleHelper.restartActivity(context)
            },
            onDismiss = { state.showLanguageDialog = false }
        )
    }
}