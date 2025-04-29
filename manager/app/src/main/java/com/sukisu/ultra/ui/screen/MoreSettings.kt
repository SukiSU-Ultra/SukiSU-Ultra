package com.sukisu.ultra.ui.screen

import android.content.Context
import android.net.Uri
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.NavigateNext
import androidx.compose.material.icons.filled.Brush
import androidx.compose.material.icons.filled.ColorLens
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Opacity
import androidx.compose.material.icons.filled.Palette
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.Wallpaper
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberTopAppBarState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.edit
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.component.ImageEditorDialog
import com.sukisu.ultra.ui.component.SwitchItem
import com.sukisu.ultra.ui.theme.CardConfig
import com.sukisu.ultra.ui.theme.ThemeColors
import com.sukisu.ultra.ui.theme.ThemeConfig
import com.sukisu.ultra.ui.theme.saveAndApplyCustomBackground
import com.sukisu.ultra.ui.theme.saveCustomBackground
import com.sukisu.ultra.ui.theme.saveDynamicColorState
import com.sukisu.ultra.ui.theme.saveThemeColors
import com.sukisu.ultra.ui.theme.saveThemeMode
import com.sukisu.ultra.ui.util.getSuSFS
import com.sukisu.ultra.ui.util.getSuSFSFeatures
import com.sukisu.ultra.ui.util.susfsSUS_SU_0
import com.sukisu.ultra.ui.util.susfsSUS_SU_2
import com.sukisu.ultra.ui.util.susfsSUS_SU_Mode
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlin.math.roundToInt

fun saveCardConfig(context: Context) {
    CardConfig.save(context)
}

@OptIn(ExperimentalMaterial3Api::class)
@Destination<RootGraph>
@Composable
fun MoreSettingsScreen(navigator: DestinationsNavigator) {
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior(rememberTopAppBarState())
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val prefs = remember { context.getSharedPreferences("settings", Context.MODE_PRIVATE) }
    val systemIsDark = isSystemInDarkTheme()

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

    // 简洁模式开关状态
    var isSimpleMode by remember {
        mutableStateOf(prefs.getBoolean("is_simple_mode", false))
    }

    // 更新简洁模式开关状态
    val onSimpleModeChange = { newValue: Boolean ->
        prefs.edit { putBoolean("is_simple_mode", newValue) }
        isSimpleMode = newValue
    }

    // 隐藏内核版本号开关状态
    var isHideVersion by remember {
        mutableStateOf(prefs.getBoolean("is_hide_version", false))
    }

    // 隐藏内核版本号开关状态
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

    // 隐藏SuSFS状态开关状态
    var isHideSusfsStatus by remember {
        mutableStateOf(prefs.getBoolean("is_hide_susfs_status", false))
    }

    // 隐藏SuSFS状态开关状态
    val onHideSusfsStatusChange = { newValue: Boolean ->
        prefs.edit { putBoolean("is_hide_susfs_status", newValue) }
        isHideSusfsStatus = newValue
    }

    // SELinux状态
    var selinuxEnabled by remember {
        mutableStateOf(Shell.cmd("getenforce").exec().out.firstOrNull() == "Enforcing")
    }

    // 卡片配置状态
    var cardAlpha by rememberSaveable { mutableFloatStateOf(CardConfig.cardAlpha) }
    var showCardSettings by remember { mutableStateOf(false) }
    var isCustomBackgroundEnabled by rememberSaveable {
        mutableStateOf(ThemeConfig.customBackgroundUri != null)
    }

    // 图片编辑状态
    var showImageEditor by remember { mutableStateOf(false) }
    var selectedImageUri by remember { mutableStateOf<Uri?>(null) }

    // 展开/折叠状态
    var isCustomizeExpanded by remember { mutableStateOf(false) }
    var isAppearanceExpanded by remember { mutableStateOf(true) }
    var isAdvancedExpanded by remember { mutableStateOf(false) }

    // 初始化卡片配置
    LaunchedEffect(Unit) {
        // 加载设置
        CardConfig.load(context)
        cardAlpha = CardConfig.cardAlpha
        isCustomBackgroundEnabled = ThemeConfig.customBackgroundUri != null

        // 设置主题模式
        themeMode = when (ThemeConfig.forceDarkMode) {
            true -> 2
            false -> 1
            null -> 0
        }

        // 确保卡片样式跟随主题模式
        when (themeMode) {
            2 -> { // 深色
                CardConfig.isUserDarkModeEnabled = true
                CardConfig.isUserLightModeEnabled = false
            }
            1 -> { // 浅色
                CardConfig.isUserDarkModeEnabled = false
                CardConfig.isUserLightModeEnabled = true
            }
            0 -> { // 跟随系统
                CardConfig.isUserDarkModeEnabled = false
                CardConfig.isUserLightModeEnabled = false
            }
        }

        // 如果启用了系统跟随且系统是深色模式，应用深色模式默认值
        if (themeMode == 0 && systemIsDark) {
            CardConfig.setDarkModeDefaults()
        }

        // 保存设置
        CardConfig.save(context)
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
    val ksuIsValid = Natives.isKsuValid(ksuApp.packageName)

    // 图片选择器
    val pickImageLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            selectedImageUri = it
            showImageEditor = true
        }
    }

    // 显示图片编辑对话框
    if (showImageEditor && selectedImageUri != null) {
        ImageEditorDialog(
            imageUri = selectedImageUri!!,
            onDismiss = {
                showImageEditor = false
                selectedImageUri = null
            },
            onConfirm = { transformedUri ->
                context.saveAndApplyCustomBackground(transformedUri)
                isCustomBackgroundEnabled = true
                CardConfig.cardElevation = 0.dp
                CardConfig.isCustomBackgroundEnabled = true
                saveCardConfig(context)
                showImageEditor = false
                selectedImageUri = null

                // 显示成功提示
                Toast.makeText(
                    context,
                    context.getString(R.string.background_set_success),
                    Toast.LENGTH_SHORT
                ).show()
            }
        )
    }

    Scaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.more_settings)) },
                navigationIcon = {
                    IconButton(onClick = { navigator.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.back))
                    }
                },
                scrollBehavior = scrollBehavior,
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .padding(paddingValues)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp)
        ) {
            // 外观设置部分
            SectionHeader(
                title = stringResource(R.string.appearance_settings),
                expanded = isAppearanceExpanded,
                onToggle = { isAppearanceExpanded = !isAppearanceExpanded }
            )

            AnimatedVisibility(
                visible = isAppearanceExpanded,
                enter = fadeIn() + expandVertically(),
                exit = fadeOut() + shrinkVertically()
            ) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    tonalElevation = 1.dp,
                    modifier = Modifier.padding(bottom = 16.dp)
                ) {
                    Column {
                        // 主题模式
                        ListItem(
                            headlineContent = { Text(stringResource(R.string.theme_mode)) },
                            supportingContent = { Text(themeOptions[themeMode]) },
                            leadingContent = {
                                Icon(
                                    Icons.Default.DarkMode,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary
                                )
                            },
                            trailingContent = {
                                Icon(
                                    Icons.AutoMirrored.Filled.NavigateNext,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            },
                            colors = ListItemDefaults.colors(
                                containerColor = Color.Transparent
                            ),
                            modifier = Modifier.clickable { showThemeModeDialog = true }
                        )

                        HorizontalDivider(
                            modifier = Modifier.padding(horizontal = 16.dp),
                            color = MaterialTheme.colorScheme.outlineVariant
                        )

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

                            HorizontalDivider(
                                modifier = Modifier.padding(horizontal = 16.dp),
                                color = MaterialTheme.colorScheme.outlineVariant
                            )
                        }

                        // 只在未启用动态颜色时显示主题色选择
                        AnimatedVisibility(
                            visible = !useDynamicColor,
                            enter = fadeIn() + expandVertically(),
                            exit = fadeOut() + shrinkVertically()
                        ) {
                            Column {
                                ListItem(
                                    headlineContent = { Text(stringResource(R.string.theme_color)) },
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
                                    leadingContent = {
                                        Icon(
                                            Icons.Default.Palette,
                                            contentDescription = null,
                                            tint = MaterialTheme.colorScheme.primary
                                        )
                                    },
                                    trailingContent = {
                                        Icon(
                                            Icons.AutoMirrored.Filled.NavigateNext,
                                            contentDescription = null,
                                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    },
                                    colors = ListItemDefaults.colors(
                                        containerColor = Color.Transparent
                                    ),
                                    modifier = Modifier.clickable { showThemeColorDialog = true }
                                )

                                HorizontalDivider(
                                    modifier = Modifier.padding(horizontal = 16.dp),
                                    color = MaterialTheme.colorScheme.outlineVariant
                                )
                            }
                        }

                        // 自定义背景开关
                        ListItem(
                            headlineContent = { Text(stringResource(id = R.string.settings_custom_background)) },
                            supportingContent = { Text(stringResource(id = R.string.settings_custom_background_summary)) },
                            leadingContent = {
                                Icon(
                                    Icons.Filled.Wallpaper,
                                    contentDescription = null,
                                    tint = if (isCustomBackgroundEnabled)
                                        MaterialTheme.colorScheme.primary
                                    else
                                        MaterialTheme.colorScheme.onSurfaceVariant
                                )
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
                                            CardConfig.cardAlpha = 0.80f
                                            CardConfig.isCustomAlphaSet = false
                                            CardConfig.isCustomBackgroundEnabled = false
                                            saveCardConfig(context)
                                            cardAlpha = 0.80f

                                            // 重置其他相关设置
                                            ThemeConfig.needsResetOnThemeChange = true

                                            // 显示成功提示
                                            Toast.makeText(
                                                context,
                                                context.getString(R.string.background_removed),
                                                Toast.LENGTH_SHORT
                                            ).show()
                                        }
                                    }
                                )
                            },
                            colors = ListItemDefaults.colors(
                                containerColor = Color.Transparent
                            ),
                            modifier = Modifier.clickable {
                                if (isCustomBackgroundEnabled) {
                                    showCardSettings = !showCardSettings
                                }
                            }
                        )

                        // 透明度 Slider
                        AnimatedVisibility(
                            visible = ThemeConfig.customBackgroundUri != null && showCardSettings,
                            enter = fadeIn() + expandVertically(),
                            exit = fadeOut() + shrinkVertically(),
                            modifier = Modifier.padding(horizontal = 16.dp)
                        ) {
                            Column(modifier = Modifier.padding(vertical = 8.dp)) {
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
                                        text = "${(cardAlpha * 100).roundToInt()}%",
                                        style = MaterialTheme.typography.labelMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }

                                Slider(
                                    value = cardAlpha,
                                    onValueChange = { newValue ->
                                        cardAlpha = newValue
                                        CardConfig.cardAlpha = newValue
                                        CardConfig.isCustomAlphaSet = true
                                        prefs.edit {
                                            putBoolean("is_custom_alpha_set", true)
                                            putFloat("card_alpha", newValue)
                                        }
                                    },
                                    onValueChangeFinished = {
                                        coroutineScope.launch(Dispatchers.IO) {
                                            saveCardConfig(context)
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
                        }
                    }
                }
            }

            // 自定义设置部分
            SectionHeader(
                title = stringResource(R.string.custom_settings),
                expanded = isCustomizeExpanded,
                onToggle = { isCustomizeExpanded = !isCustomizeExpanded }
            )

            AnimatedVisibility(
                visible = isCustomizeExpanded,
                enter = fadeIn() + expandVertically(),
                exit = fadeOut() + shrinkVertically()
            ) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    tonalElevation = 1.dp,
                    modifier = Modifier.padding(bottom = 16.dp)
                ) {
                    Column {
                        // 添加简洁模式开关
                        SwitchItem(
                            icon = Icons.Filled.Brush,
                            title = stringResource(R.string.simple_mode),
                            summary = stringResource(R.string.simple_mode_summary),
                            checked = isSimpleMode
                        ) {
                            onSimpleModeChange(it)
                        }

                        HorizontalDivider(
                            modifier = Modifier.padding(horizontal = 16.dp),
                            color = MaterialTheme.colorScheme.outlineVariant
                        )

                        // 隐藏内核部分版本号
                        SwitchItem(
                            icon = Icons.Filled.VisibilityOff,
                            title = stringResource(R.string.hide_kernel_kernelsu_version),
                            summary = stringResource(R.string.hide_kernel_kernelsu_version_summary),
                            checked = isHideVersion
                        ) {
                            onHideVersionChange(it)
                        }

                        HorizontalDivider(
                            modifier = Modifier.padding(horizontal = 16.dp),
                            color = MaterialTheme.colorScheme.outlineVariant
                        )

                        // 模块数量等信息
                        SwitchItem(
                            icon = Icons.Filled.VisibilityOff,
                            title = stringResource(R.string.hide_other_info),
                            summary = stringResource(R.string.hide_other_info_summary),
                            checked = isHideOtherInfo
                        ) {
                            onHideOtherInfoChange(it)
                        }

                        HorizontalDivider(
                            modifier = Modifier.padding(horizontal = 16.dp),
                            color = MaterialTheme.colorScheme.outlineVariant
                        )

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
                }
            }

            // 高级设置部分
            SectionHeader(
                title = stringResource(R.string.advanced_settings),
                expanded = isAdvancedExpanded,
                onToggle = { isAdvancedExpanded = !isAdvancedExpanded }
            )

            AnimatedVisibility(
                visible = isAdvancedExpanded,
                enter = fadeIn() + expandVertically(),
                exit = fadeOut() + shrinkVertically()
            ) {
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    tonalElevation = 1.dp,
                    modifier = Modifier.padding(bottom = 16.dp)
                ) {
                    Column {
                        // SELinux 开关
                        if (ksuIsValid) {
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
                                    if (result.isSuccess) {
                                        selinuxEnabled = enabled
                                        // 显示成功提示
                                        val message = if (enabled)
                                            context.getString(R.string.selinux_enabled_toast)
                                        else
                                            context.getString(R.string.selinux_disabled_toast)

                                        Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
                                    } else {
                                        // 显示失败提示
                                        Toast.makeText(
                                            context,
                                            context.getString(R.string.selinux_change_failed),
                                            Toast.LENGTH_SHORT
                                        ).show()
                                    }
                                }
                            }

                            HorizontalDivider(
                                modifier = Modifier.padding(horizontal = 16.dp),
                                color = MaterialTheme.colorScheme.outlineVariant
                            )
                        }

                        // SuSFS 配置（仅在支持时显示）
                        val suSFS = getSuSFS()
                        val isSUS_SU = getSuSFSFeatures()
                        if (suSFS == "Supported" && isSUS_SU == "CONFIG_KSU_SUSFS_SUS_SU") {
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
                                icon = Icons.Filled.Security,
                                title = stringResource(id = R.string.settings_susfs_toggle),
                                summary = stringResource(id = R.string.settings_susfs_toggle_summary),
                                checked = isEnabled
                            ) {
                                if (it) {
                                    // 手动启用
                                    susfsSUS_SU_2()
                                    prefs.edit { putBoolean("enable_sus_su", true) }
                                    Toast.makeText(
                                        context,
                                        context.getString(R.string.susfs_enabled),
                                        Toast.LENGTH_SHORT
                                    ).show()
                                } else {
                                    // 手动关闭
                                    susfsSUS_SU_0()
                                    prefs.edit { putBoolean("enable_sus_su", false) }
                                    Toast.makeText(
                                        context,
                                        context.getString(R.string.susfs_disabled),
                                        Toast.LENGTH_SHORT
                                    ).show()
                                }
                                isEnabled = it
                            }
                        }
                    }
                }
            }
        }
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
                                        2 -> { // 深色
                                            ThemeConfig.forceDarkMode = true
                                            CardConfig.isUserDarkModeEnabled = true
                                            CardConfig.isUserLightModeEnabled = false
                                            if (!CardConfig.isCustomAlphaSet) {
                                                CardConfig.cardAlpha = 0.35f
                                            }
                                            CardConfig.save(context)
                                        }
                                        1 -> { // 浅色
                                            ThemeConfig.forceDarkMode = false
                                            CardConfig.isUserLightModeEnabled = true
                                            CardConfig.isUserDarkModeEnabled = false
                                            if (!CardConfig.isCustomAlphaSet) {
                                                CardConfig.cardAlpha = 0.80f
                                            }
                                            CardConfig.save(context)
                                        }
                                        0 -> { // 跟随系统
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
            confirmButton = {
                TextButton(
                    onClick = { showThemeModeDialog = false }
                ) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }

    // 主题色选择对话框
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
                            Spacer(modifier = Modifier.width(12.dp))
                            Box(
                                modifier = Modifier
                                    .size(24.dp)
                                    .clip(CircleShape)
                                    .background(theme.Primary)
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                            Text(name)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = { showThemeColorDialog = false }
                ) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}

@Composable
fun SectionHeader(
    title: String,
    expanded: Boolean,
    onToggle: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onToggle() }
            .padding(vertical = 12.dp, horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium.copy(
                fontWeight = FontWeight.Bold
            ),
            color = MaterialTheme.colorScheme.primary
        )
        Spacer(modifier = Modifier.weight(1f))
        Icon(
            imageVector = if (expanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
            contentDescription = if (expanded)
                stringResource(R.string.collapse)
            else
                stringResource(R.string.expand),
            tint = MaterialTheme.colorScheme.primary
        )
    }
}