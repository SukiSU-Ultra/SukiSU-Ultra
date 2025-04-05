package shirkneko.zako.sukisu.ui.screen

import androidx.compose.animation.AnimatedVisibility
import android.content.Context
import android.net.Uri
import android.os.Build
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import shirkneko.zako.sukisu.R
import shirkneko.zako.sukisu.ui.component.SwitchItem
import shirkneko.zako.sukisu.ui.theme.CardConfig
import shirkneko.zako.sukisu.ui.theme.ThemeColors
import shirkneko.zako.sukisu.ui.theme.ThemeConfig
import shirkneko.zako.sukisu.ui.theme.saveCustomBackground
import shirkneko.zako.sukisu.ui.theme.saveThemeColors
import shirkneko.zako.sukisu.ui.theme.saveThemeMode
import shirkneko.zako.sukisu.ui.theme.saveDynamicColorState
import shirkneko.zako.sukisu.ui.util.getSuSFS
import shirkneko.zako.sukisu.ui.util.getSuSFSFeatures
import shirkneko.zako.sukisu.ui.util.susfsSUS_SU_0
import shirkneko.zako.sukisu.ui.util.susfsSUS_SU_2
import shirkneko.zako.sukisu.ui.util.susfsSUS_SU_Mode
import androidx.core.content.edit


fun saveCardConfig(context: Context) {
    val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
    with(prefs.edit()) {
        putFloat("card_alpha", CardConfig.cardAlpha)
        putBoolean("custom_background_enabled", CardConfig.cardElevation == 0.dp)
        putBoolean("is_custom_alpha_set", CardConfig.isCustomAlphaSet)
        apply()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Destination<RootGraph>
@Composable
fun MoreSettingsScreen(navigator: DestinationsNavigator) {
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("settings", Context.MODE_PRIVATE) }
    // 主题模式选择
    var themeMode by remember {
        mutableIntStateOf(
            when(ThemeConfig.forceDarkMode) {
                true -> 2 // 深色
                false -> 1 // 浅色
                null -> 0 // 跟随系统
            }
        )
    }

    // 动态颜色开关状态
    var useDynamicColor by remember {
        mutableStateOf(ThemeConfig.useDynamicColor)
    }

    var showThemeModeDialog by remember { mutableStateOf(false) }
    // 主题模式选项
    val themeOptions = listOf(
        stringResource(R.string.theme_follow_system),
        stringResource(R.string.theme_light),
        stringResource(R.string.theme_dark)
    )

    // 简洁模块开关状态
    var isSimpleMode by remember {
        mutableStateOf(prefs.getBoolean("is_simple_mode", false))
    }

    // 更新简洁模块开关状态
    val onSimpleModeChange = { newValue: Boolean ->
        prefs.edit { putBoolean("is_simple_mode", newValue) }
        isSimpleMode = newValue
    }

    // 隐藏内核 KernelSU 版本号开关状态
    var isHideVersion by remember {
        mutableStateOf(prefs.getBoolean("is_hide_version", false))
    }

    // 隐藏内核 KernelSU 版本号模块开关状态
    val onHideVersionChange = { newValue: Boolean ->
        prefs.edit { putBoolean("is_hide_version", newValue) }
        isHideVersion = newValue
    }

    // 隐藏模块数量等信息开关状态
    var isHideOtherInfo by remember {
        mutableStateOf(prefs.getBoolean("is_hide_other_info", false))
    }

    // 隐藏模块数量等信息开关状态
    val onHideOtherInfoChange = { newValue: Boolean ->
        prefs.edit { putBoolean("is_hide_other_info", newValue) }
        isHideOtherInfo = newValue
    }

    // 隐藏 SuSFS 状态开关状态
    var isHideSusfsStatus by remember {
        mutableStateOf(prefs.getBoolean("is_hide_susfs_status", false))
    }

    // 隐藏 SuSFS 状态开关状态
    val onHideSusfsStatusChange = { newValue: Boolean ->
        prefs.edit { putBoolean("is_hide_susfs_status", newValue) }
        isHideSusfsStatus = newValue
    }
    
    // SELinux 状态
    var selinuxEnabled by remember {
        mutableStateOf(Shell.cmd("getenforce").exec().out.firstOrNull() == "Enforcing")
    }

    // 卡片配置状态
    var cardAlpha by rememberSaveable { mutableFloatStateOf(CardConfig.cardAlpha) }
    var showCardSettings by remember { mutableStateOf(false) }
    var isCustomBackgroundEnabled by rememberSaveable {
        mutableStateOf(ThemeConfig.customBackgroundUri != null)
    }

    // 初始化卡片配置
    val systemIsDark = isSystemInDarkTheme()
    LaunchedEffect(Unit) {
        CardConfig.apply {
            cardAlpha = prefs.getFloat("card_alpha", 0.45f)
            cardElevation = if (prefs.getBoolean("custom_background_enabled", false)) 0.dp else defaultElevation
            isCustomAlphaSet = prefs.getBoolean("is_custom_alpha_set", false)

            // 如果没有手动设置透明度，且是深色模式，则使用默认值
            if (!isCustomAlphaSet) {
                val isDarkMode = ThemeConfig.forceDarkMode ?: systemIsDark
                if (isDarkMode) {
                    cardAlpha = 0.35f
                }
            }
        }
        themeMode = when (ThemeConfig.forceDarkMode) {
            true -> 2
            false -> 1
            null -> 0
        }
    }

    // 主题色选项
    val themeColorOptions = listOf(
        stringResource(R.string.color_default) to ThemeColors.Default,
        stringResource(R.string.color_blue) to ThemeColors.Blue,
        stringResource(R.string.color_green) to ThemeColors.Green,
        stringResource(R.string.color_purple) to ThemeColors.Purple,
        stringResource(R.string.color_orange) to ThemeColors.Orange,
        stringResource(R.string.color_pink) to ThemeColors.Pink,
        stringResource(R.string.color_gray) to ThemeColors.Gray,
        stringResource(R.string.color_yellow) to ThemeColors.Yellow
    )

    var showThemeColorDialog by remember { mutableStateOf(false) }

    // 图片选择器
    val pickImageLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            context.saveCustomBackground(it)
            isCustomBackgroundEnabled = true
            CardConfig.cardElevation = 0.dp
            saveCardConfig(context)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.more_settings)) },
                navigationIcon = {
                    IconButton(onClick = { navigator.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, null)
                    }
                },
                scrollBehavior = scrollBehavior
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .padding(paddingValues)
                .verticalScroll(rememberScrollState())
                .padding(top = 12.dp)
        ) {
            // SELinux 开关
            SwitchItem(
                icon = Icons.Filled.Security,
                title = stringResource(R.string.selinux),
                summary = if (selinuxEnabled)
                    stringResource(R.string.selinux_enabled) else
                    stringResource(R.string.selinux_disabled),
                checked = selinuxEnabled
            ) { enabled ->
                val command = if (enabled) "setenforce 1" else "setenforce 0"
                Shell.getShell().newJob().add(command).exec().let { result ->
                    if (result.isSuccess) selinuxEnabled = enabled
                }
            }

            var isExpanded by remember { mutableStateOf(false) }

            ListItem(
                leadingContent = { Icon(Icons.Filled.AutoFixHigh, null) },
                headlineContent = { Text(stringResource(R.string.custom_settings)) },
                modifier = Modifier.clickable {
                    isExpanded = !isExpanded
                }
            )
            AnimatedVisibility(
                visible = isExpanded,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp)
            ) {
                // 添加简洁模块开关
                SwitchItem(
                    icon = Icons.Filled.Brush,
                    title = stringResource(R.string.simple_mode),
                    summary = stringResource(R.string.simple_mode_summary),
                    checked = isSimpleMode
                ) {
                    onSimpleModeChange(it)
                }
            }
            AnimatedVisibility(
                visible = isExpanded,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp)
            ) {
                // 隐藏内核部分版本号
                SwitchItem(
                    icon = Icons.Filled.VisibilityOff,
                    title = stringResource(R.string.hide_kernel_kernelsu_version),
                    summary = stringResource(R.string.hide_kernel_kernelsu_version_summary),
                    checked = isHideVersion
                ) {
                    onHideVersionChange(it)
                }
            }
            AnimatedVisibility(
                visible = isExpanded,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp)
            ) {
                // 模块数量等信息
                SwitchItem(
                    icon = Icons.Filled.VisibilityOff,
                    title = stringResource(R.string.hide_other_info),
                    summary = stringResource(R.string.hide_other_info_summary),
                    checked = isHideOtherInfo
                ) {
                    onHideOtherInfoChange(it)
                }
            }
            AnimatedVisibility(
                visible = isExpanded,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp)
            ) {
                // SuSFS 状态信息
                SwitchItem(
                    icon = Icons.Filled.VisibilityOff,
                    title = stringResource(R.string.hide_susfs_status),
                    summary = stringResource(R.string.hide_susfs_status_summary),
                    checked = isHideSusfsStatus
                ) {
                    onHideSusfsStatusChange(it)
                }
            }

            // region SUSFS 配置（仅在支持时显示）
            val suSFS = getSuSFS()
            val isSUS_SU = getSuSFSFeatures()
            if (suSFS == "Supported") {
                if (isSUS_SU == "CONFIG_KSU_SUSFS_SUS_SU") {
                    // 初始化时，默认启用
                    var isEnabled by rememberSaveable {
                        mutableStateOf(true) // 默认启用
                    }

                    // 在启动时检查状态
                    LaunchedEffect(Unit) {
                        // 如果当前模式不是2就强制启用
                        val currentMode = susfsSUS_SU_Mode()
                        val wasManuallyDisabled = prefs.getBoolean("enable_sus_su", true)
                        if (currentMode != "2" && wasManuallyDisabled) {
                            susfsSUS_SU_2() // 强制切换到模式2
                            prefs.edit { putBoolean("enable_sus_su", true) }
                        }
                        isEnabled = currentMode == "2"
                    }

                    SwitchItem(
                        icon = Icons.Filled.VisibilityOff,
                        title = stringResource(id = R.string.settings_susfs_toggle),
                        summary = stringResource(id = R.string.settings_susfs_toggle_summary),
                        checked = isEnabled
                    ) {
                        if (it) {
                            // 手动启用
                            susfsSUS_SU_2()
                            prefs.edit { putBoolean("enable_sus_su", true) }
                        } else {
                            // 手动关闭
                            susfsSUS_SU_0()
                            prefs.edit { putBoolean("enable_sus_su", false) }
                        }
                        isEnabled = it
                    }
                }
            }
            // endregion
            // 动态颜色开关
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                SwitchItem(
                    icon = Icons.Filled.ColorLens,
                    title = stringResource(R.string.dynamic_color_title),
                    summary = stringResource(R.string.dynamic_color_summary),
                    checked = useDynamicColor
                ) { enabled ->
                    useDynamicColor = enabled
                    context.saveDynamicColorState(enabled)
                }
            }
            // 只在未启用动态颜色时显示主题色选择
            AnimatedVisibility(
                visible = !useDynamicColor
            ) {
                ListItem(
                    leadingContent = { Icon(Icons.Default.Palette, null) },
                    headlineContent = { Text("主题颜色") },
                    supportingContent = {
                        val currentThemeName = when (ThemeConfig.currentTheme) {
                            is ThemeColors.Default -> stringResource(R.string.color_default)
                            is ThemeColors.Blue -> stringResource(R.string.color_blue)
                            is ThemeColors.Green -> stringResource(R.string.color_green)
                            is ThemeColors.Purple -> stringResource(R.string.color_purple)
                            is ThemeColors.Orange -> stringResource(R.string.color_orange)
                            is ThemeColors.Pink -> stringResource(R.string.color_pink)
                            is ThemeColors.Gray -> stringResource(R.string.color_gray)
                            is ThemeColors.Yellow -> stringResource(R.string.color_yellow)
                            else -> stringResource(R.string.color_default)
                        }
                        Text(currentThemeName)
                    },
                    modifier = Modifier.clickable { showThemeColorDialog = true }
                )

                if (showThemeColorDialog) {
                    AlertDialog(
                        onDismissRequest = { showThemeColorDialog = false },
                        title = { Text(stringResource(R.string.choose_theme_color)) },
                        text = {
                            Column {
                                themeColorOptions.forEach { (name, theme) ->
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clickable {
                                                context.saveThemeColors(when (theme) {
                                                    ThemeColors.Default -> "default"
                                                    ThemeColors.Blue -> "blue"
                                                    ThemeColors.Green -> "green"
                                                    ThemeColors.Purple -> "purple"
                                                    ThemeColors.Orange -> "orange"
                                                    ThemeColors.Pink -> "pink"
                                                    ThemeColors.Gray -> "gray"
                                                    ThemeColors.Yellow -> "yellow"
                                                    else -> "default"
                                                })
                                                showThemeColorDialog = false
                                            }
                                            .padding(vertical = 12.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        RadioButton(
                                            selected = ThemeConfig.currentTheme::class == theme::class,
                                            onClick = null
                                        )
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Box(
                                            modifier = Modifier
                                                .size(24.dp)
                                                .background(theme.Primary, shape = CircleShape)
                                        )
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Text(name)
                                    }
                                }
                            }
                        },
                        confirmButton = {}
                    )
                }
            }
            // 自定义背景开关
            ListItem(
                leadingContent = { Icon(Icons.Filled.Wallpaper, null) },
                headlineContent = { Text(stringResource(id = R.string.settings_custom_background)) },
                supportingContent = { Text(stringResource(id = R.string.settings_custom_background_summary)) },
                modifier = Modifier.clickable {
                    if (isCustomBackgroundEnabled) {
                        showCardSettings = !showCardSettings
                    }
                },
                trailingContent = {
                    Switch(
                        checked = isCustomBackgroundEnabled,
                        onCheckedChange = { isChecked ->
                            if (isChecked) {
                                pickImageLauncher.launch("image/*")
                            } else {
                                context.saveCustomBackground(null)
                                isCustomBackgroundEnabled = false
                                CardConfig.cardElevation = CardConfig.defaultElevation
                                CardConfig.cardAlpha = 0.45f
                                CardConfig.isCustomAlphaSet = false
                                saveCardConfig(context)
                                cardAlpha = 0.35f
                                themeMode = 0
                                context.saveThemeMode(null)
                                CardConfig.isUserDarkModeEnabled = false
                                CardConfig.isUserLightModeEnabled = false
                                CardConfig.save(context)
                            }
                        }
                    )
                }
            )
                // 透明度 Slider
                AnimatedVisibility(
                    visible = ThemeConfig.customBackgroundUri != null && showCardSettings,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp)
                ) {
                    ListItem(
                        leadingContent = { Icon(Icons.Filled.Opacity, null) },
                        headlineContent = { Text(stringResource(R.string.settings_card_alpha)) },
                        supportingContent = {
                            Slider(
                                value = cardAlpha,
                                onValueChange = { newValue ->
                                    cardAlpha = newValue
                                    CardConfig.cardAlpha = newValue
                                    CardConfig.isCustomAlphaSet = true
                                    prefs.edit { putBoolean("is_custom_alpha_set", true) }
                                    prefs.edit { putFloat("card_alpha", newValue) }
                                },
                                onValueChangeFinished = {
                                    CoroutineScope(Dispatchers.IO).launch {
                                        saveCardConfig(context)
                                    }
                                },
                                valueRange = 0f..1f,
                                colors = getSliderColors(cardAlpha, useCustomColors = true),
                                thumb = {
                                    SliderDefaults.Thumb(
                                        interactionSource = remember { MutableInteractionSource() },
                                        thumbSize = DpSize(0.dp, 0.dp)
                                    )
                                }
                            )
                        }
                    )
                }
                AnimatedVisibility(
                    visible = ThemeConfig.customBackgroundUri != null && showCardSettings,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp)
                ){
                ListItem(
                    leadingContent = { Icon(Icons.Filled.DarkMode, null) },
                    headlineContent = { Text(stringResource(R.string.theme_mode)) },
                    supportingContent = { Text(themeOptions[themeMode]) },
                    modifier = Modifier.clickable {
                        showThemeModeDialog = true
                    }
                )
                }

                    // 主题模式选择对话框
                    if (showThemeModeDialog) {
                        AlertDialog(
                            onDismissRequest = { showThemeModeDialog = false },
                            title = { Text(stringResource(R.string.theme_mode)) },
                            text = {
                                Column {
                                    themeOptions.forEachIndexed { index, option ->
                                        Row(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .clickable {
                                                    themeMode = index
                                                    val newThemeMode = when(index) {
                                                        0 -> null // 跟随系统
                                                        1 -> false // 浅色
                                                        2 -> true // 深色
                                                        else -> null
                                                    }
                                                    context.saveThemeMode(newThemeMode)
                                                    when (index) {
                                                        2 -> {
                                                            ThemeConfig.forceDarkMode = true
                                                            CardConfig.isUserLightModeEnabled = false
                                                            CardConfig.isUserDarkModeEnabled = true
                                                            CardConfig.save(context)
                                                        }
                                                        1 -> {
                                                            ThemeConfig.forceDarkMode = false
                                                            CardConfig.isUserLightModeEnabled = true
                                                            CardConfig.isUserDarkModeEnabled = false
                                                            CardConfig.save(context)
                                                        }
                                                        0 -> {
                                                            ThemeConfig.forceDarkMode = null
                                                            CardConfig.isUserLightModeEnabled = false
                                                            CardConfig.isUserDarkModeEnabled = false
                                                            CardConfig.save(context)
                                                        }
                                                    }
                                                    showThemeModeDialog = false
                                                }
                                                .padding(vertical = 12.dp),
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            RadioButton(
                                                selected = themeMode == index,
                                                onClick = null
                                            )
                                            Spacer(modifier = Modifier.width(8.dp))
                                            Text(option)
                                        }
                                    }
                                }
                            },
                            confirmButton = {}
                        )
                    }
                }
            }
        }


@Composable
private fun getSliderColors(cardAlpha: Float, useCustomColors: Boolean = false): SliderColors {
    val theme = ThemeConfig.currentTheme
    val isDarkTheme = ThemeConfig.forceDarkMode ?: isSystemInDarkTheme()
    val useDynamicColor = ThemeConfig.useDynamicColor

    return when {
        // 使用动态颜色时
        useDynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            SliderDefaults.colors(
                activeTrackColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.8f),
                inactiveTrackColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.3f),
                thumbColor = MaterialTheme.colorScheme.primary
            )
        }
        // 使用自定义主题色时
        useCustomColors -> {
            SliderDefaults.colors(
                activeTrackColor = theme.getCustomSliderActiveColor(),
                inactiveTrackColor = theme.getCustomSliderInactiveColor(),
                thumbColor = theme.Primary
            )
        }
        else -> {
            val activeColor = if (isDarkTheme) {
                theme.Primary.copy(alpha = cardAlpha)
            } else {
                theme.Primary.copy(alpha = cardAlpha)
            }
            val inactiveColor = if (isDarkTheme) {
                Color.DarkGray.copy(alpha = 0.3f)
            } else {
                Color.LightGray.copy(alpha = 0.3f)
            }
            SliderDefaults.colors(
                activeTrackColor = activeColor,
                inactiveTrackColor = inactiveColor,
                thumbColor = activeColor
            )
        }
    }
}
