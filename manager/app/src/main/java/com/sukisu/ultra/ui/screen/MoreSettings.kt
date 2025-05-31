package com.sukisu.ultra.ui.screen

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.res.Configuration
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.NavigateNext
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.*
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
import com.sukisu.ultra.ui.MainActivity
import com.sukisu.ultra.ui.component.ImageEditorDialog
import com.sukisu.ultra.ui.component.KsuIsValid
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
import java.util.Locale
import kotlin.math.roundToInt

/**
 * @author ShirkNeko
 * @date 2025/5/31.
 */
fun saveCardConfig(context: Context) {
    CardConfig.save(context)
}

@SuppressLint("LocalContextConfigurationRead", "ObsoleteSdkInt")
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

    // 获取当前语言设置
    var currentLanguage by remember {
        mutableStateOf(prefs.getString("app_language", "") ?: "")
    }

    // 获取支持的语言列表
    val supportedLanguages = remember {
        val languages = mutableListOf<Pair<String, String>>()
        languages.add("" to context.getString(R.string.language_follow_system))
        val locales = context.resources.configuration.locales
        for (i in 0 until locales.size()) {
            val locale = locales.get(i)
            val code = locale.toLanguageTag()
            if (!languages.any { it.first == code }) {
                languages.add(code to locale.getDisplayName(locale))
            }
        }

        val commonLocales = listOf(
            Locale.forLanguageTag("en"), // 英语
            Locale.forLanguageTag("zh-CN"), // 简体中文
            Locale.forLanguageTag("zh-HK"), // 繁体中文(香港)
            Locale.forLanguageTag("zh-TW"), // 繁体中文(台湾)
            Locale.forLanguageTag("ja"), // 日语
            Locale.forLanguageTag("fr"), // 法语
            Locale.forLanguageTag("de"), // 德语
            Locale.forLanguageTag("es"), // 西班牙语
            Locale.forLanguageTag("it"), // 意大利语
            Locale.forLanguageTag("ru"), // 俄语
            Locale.forLanguageTag("pt"), // 葡萄牙语
            Locale.forLanguageTag("ko"), // 韩语
            Locale.forLanguageTag("vi")  // 越南语
        )

        for (locale in commonLocales) {
            val code = locale.toLanguageTag()
            if (!languages.any { it.first == code }) {
                val config = Configuration(context.resources.configuration)
                config.setLocale(locale)
                try {
                    val testContext = context.createConfigurationContext(config)
                    testContext.getString(R.string.language_follow_system)
                    languages.add(code to locale.getDisplayName(locale))
                } catch (_: Exception) {
                }
            }
        }
        languages
    }

    var showLanguageDialog by remember { mutableStateOf(false) }

    // 语言切换对话框
    if (showLanguageDialog) {
        AlertDialog(
            onDismissRequest = { showLanguageDialog = false },
            title = { Text(stringResource(R.string.language_setting)) },
            text = {
                Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                    supportedLanguages.forEach { (code, name) ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    if (currentLanguage != code) {
                                        prefs.edit {
                                            putString("app_language", code)
                                            commit()
                                        }

                                        currentLanguage = code

                                        Toast.makeText(
                                            context,
                                            context.getString(R.string.language_changed),
                                            Toast.LENGTH_SHORT
                                        ).show()

                                        val locale = if (code.isEmpty()) Locale.getDefault() else Locale.forLanguageTag(code)
                                        Locale.setDefault(locale)
                                        val config = Configuration(context.resources.configuration)
                                        config.setLocale(locale)

                                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                                            context.createConfigurationContext(config)
                                        } else {
                                            @Suppress("DEPRECATION")
                                            context.resources.updateConfiguration(config, context.resources.displayMetrics)
                                        }

                                        val intent = Intent(context, MainActivity::class.java)
                                        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK or Intent.FLAG_ACTIVITY_NEW_TASK)
                                        context.startActivity(intent)

                                        if (context is Activity) {
                                            context.finish()
                                        }
                                    }
                                    showLanguageDialog = false
                                }
                                .padding(vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = currentLanguage == code,
                                onClick = null
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(name)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = { showLanguageDialog = false }
                ) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }

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

    // 显示KPM开关状态
    var isShowKpmInfo by remember {
        mutableStateOf(prefs.getBoolean("show_kpm_info", true))
    }

    // 更新显示KPM开关状态
    val onShowKpmInfoChange = { newValue: Boolean ->
        prefs.edit { putBoolean("show_kpm_info", newValue) }
        isShowKpmInfo = newValue
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

    // 隐藏链接状态开关状态
    var isHideLinkCard by remember {
        mutableStateOf(prefs.getBoolean("is_hide_link_card", false))
    }

    val onHideLinkCardChange = { newValue: Boolean ->
        prefs.edit { putBoolean("is_hide_link_card", newValue) }
        isHideLinkCard = newValue
    }

    // SELinux状态
    var selinuxEnabled by remember {
        mutableStateOf(Shell.cmd("getenforce").exec().out.firstOrNull() == "Enforcing")
    }

    // 卡片配置状态
    var cardAlpha by rememberSaveable { mutableFloatStateOf(CardConfig.cardAlpha) }
    var cardDim by rememberSaveable { mutableFloatStateOf(CardConfig.cardDim) }
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

    // DPI 设置
    val systemDpi = remember { context.resources.displayMetrics.densityDpi }
    var currentDpi by remember {
        mutableIntStateOf(prefs.getInt("app_dpi", systemDpi))
    }
    var tempDpi by remember { mutableIntStateOf(currentDpi) }
    var isDpiCustom by remember { mutableStateOf(true) }
    var showDpiConfirmDialog by remember { mutableStateOf(false) }

    // 预设 DPI 选项
    val dpiPresets = mapOf(
        stringResource(R.string.dpi_size_small) to 240,
        stringResource(R.string.dpi_size_medium) to 320,
        stringResource(R.string.dpi_size_large) to 420,
        stringResource(R.string.dpi_size_extra_large) to 560
    )

    // 获取DPI大小
    @Composable
    fun getDpiFriendlyName(dpi: Int): String {
        return when (dpi) {
            240 -> stringResource(R.string.dpi_size_small)
            320 -> stringResource(R.string.dpi_size_medium)
            420 -> stringResource(R.string.dpi_size_large)
            560 -> stringResource(R.string.dpi_size_extra_large)
            else -> stringResource(R.string.dpi_size_custom)
        }
    }

    // 初始化卡片配置
    LaunchedEffect(Unit) {
        // 加载设置
        CardConfig.load(context)
        cardAlpha = CardConfig.cardAlpha
        cardDim = CardConfig.cardDim
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

        currentDpi = prefs.getInt("app_dpi", systemDpi)
        tempDpi = currentDpi

        CardConfig.save(context)
    }

    // 应用 DPI 设置
    val applyDpiSetting = { dpi: Int ->
        if (dpi != currentDpi) {
            // 保存到 SharedPreferences
            prefs.edit {
                putInt("app_dpi", dpi)
            }

            // 只修改应用级别的DPI设置
            currentDpi = dpi
            tempDpi = dpi
            Toast.makeText(
                context,
                context.getString(R.string.dpi_applied_success, dpi),
                Toast.LENGTH_SHORT
            ).show()

            val restartIntent = context.packageManager.getLaunchIntentForPackage(context.packageName)
            restartIntent?.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK or Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(restartIntent)

            showDpiConfirmDialog = false
        }
    }

    // 主题色选项
    val themeColorOptions = listOf(
        stringResource(R.string.color_default) to ThemeColors.Default,
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

    val cardColor = MaterialTheme.colorScheme.surfaceContainerHigh
    val cardAlphaUse = CardConfig.cardAlpha
    val isDarkTheme = isSystemInDarkTheme()

    Scaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.more_settings)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = cardColor.copy(alpha = cardAlphaUse),
                    scrolledContainerColor = cardColor.copy(alpha = cardAlphaUse)),
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
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 16.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh.copy(alpha = cardAlpha)
                    ),
                    elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
                ) {
                    Column(modifier = Modifier.padding(vertical = 8.dp)) {
                        // 语言设置
                        ListItem(
                            headlineContent = { Text(stringResource(R.string.language_setting)) },
                            supportingContent = {
                                Text(supportedLanguages.find { it.first == currentLanguage }?.second
                                    ?: stringResource(R.string.language_follow_system))
                            },
                            leadingContent = {
                                Icon(
                                    Icons.Default.Language,
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
                            modifier = Modifier.clickable { showLanguageDialog = true }
                        )

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
                            visible = Build.VERSION.SDK_INT < Build.VERSION_CODES.S || !useDynamicColor,
                            enter = fadeIn() + expandVertically(),
                            exit = fadeOut() + shrinkVertically()
                        ) {
                            Column {
                                ListItem(
                                    headlineContent = { Text(stringResource(R.string.theme_color)) },
                                    supportingContent = {
                                        val currentThemeName = when (ThemeConfig.currentTheme) {
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
                            }
                        }

                        // DPI 设置
                        ListItem(
                            headlineContent = { Text(stringResource(R.string.app_dpi_title)) },
                            supportingContent = { Text(stringResource(R.string.app_dpi_summary)) },
                            leadingContent = {
                                Icon(
                                    Icons.Default.AcUnit,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary
                                )
                            },
                            trailingContent = {
                                Text(
                                    text = getDpiFriendlyName(tempDpi),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.primary
                                )
                            },
                            colors = ListItemDefaults.colors(
                                containerColor = Color.Transparent
                            )
                        )

                        // DPI 滑动条
                        Column(modifier = Modifier.padding(horizontal = 32.dp, vertical = 8.dp)) {
                            Slider(
                                value = tempDpi.toFloat(),
                                onValueChange = {
                                    tempDpi = it.toInt()
                                    isDpiCustom = !dpiPresets.containsValue(tempDpi)
                                },
                                valueRange = 160f..600f,
                                steps = 11,
                                colors = SliderDefaults.colors(
                                    thumbColor = MaterialTheme.colorScheme.primary,
                                    activeTrackColor = MaterialTheme.colorScheme.primary,
                                    inactiveTrackColor = MaterialTheme.colorScheme.surfaceVariant
                                )
                            )

                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(top = 8.dp),
                            ) {
                                dpiPresets.forEach { (name, dpi) ->
                                    TextButton(
                                        onClick = {
                                            tempDpi = dpi
                                            isDpiCustom = false
                                        },
                                        modifier = Modifier.weight(1f)
                                    ) {
                                        Text(
                                            text = name,
                                            color = if (tempDpi == dpi)
                                                MaterialTheme.colorScheme.primary
                                            else
                                                MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                            }

                            TextButton(
                                onClick = {
                                    if (tempDpi != currentDpi) {
                                        showDpiConfirmDialog = true
                                    }
                                },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(top = 8.dp)
                            ) {
                                Text(stringResource(R.string.dpi_apply_settings))
                            }

                            Text(
                                text = if (isDpiCustom)
                                    "${stringResource(R.string.dpi_size_custom)}: $tempDpi"
                                else
                                    "${getDpiFriendlyName(tempDpi)}: $tempDpi",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(top = 4.dp)
                            )
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
                                            CardConfig.cardElevation
                                            CardConfig.cardAlpha = 1f
                                            CardConfig.cardDim = 0f
                                            CardConfig.isCustomAlphaSet = false
                                            CardConfig.isCustomDimSet = false
                                            CardConfig.isCustomBackgroundEnabled = false
                                            saveCardConfig(context)
                                            cardAlpha = 1f
                                            cardDim = 0f

                                            // 重置其他相关设置
                                            ThemeConfig.needsResetOnThemeChange = true
                                            ThemeConfig.preventBackgroundRefresh = false

                                            context.getSharedPreferences("theme_prefs", Context.MODE_PRIVATE)
                                                .edit {
                                                    putBoolean(
                                                        "prevent_background_refresh",
                                                        false
                                                    )
                                                }

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
                            )
                        )

                        // 透明度和亮度调节滑动条
                        AnimatedVisibility(
                            visible = ThemeConfig.customBackgroundUri != null,
                            enter = fadeIn() + expandVertically(),
                            exit = fadeOut() + shrinkVertically(),
                            modifier = Modifier.padding(horizontal = 32.dp)
                        ) {
                            Column(modifier = Modifier.padding(vertical = 8.dp)) {
                                // 透明度滑动条
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

                                // 亮度调节滑动条
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
                                        text = "${(cardDim * 100).roundToInt()}%",
                                        style = MaterialTheme.typography.labelMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }

                                Slider(
                                    value = cardDim,
                                    onValueChange = { newValue ->
                                        cardDim = newValue
                                        CardConfig.cardDim = newValue
                                        CardConfig.isCustomDimSet = true
                                        prefs.edit {
                                            putBoolean("is_custom_dim_set", true)
                                            putFloat("card_dim", newValue)
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
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 16.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh.copy(alpha = cardAlpha)
                    ),
                    elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
                ) {
                    Column(modifier = Modifier.padding(vertical = 8.dp)) {
                        // 添加简洁模式开关
                        SwitchItem(
                            icon = Icons.Filled.Brush,
                            title = stringResource(R.string.simple_mode),
                            summary = stringResource(R.string.simple_mode_summary),
                            checked = isSimpleMode
                        ) {
                            onSimpleModeChange(it)
                        }

                        

                        // 隐藏内核部分版本号
                        SwitchItem(
                            icon = Icons.Filled.VisibilityOff,
                            title = stringResource(R.string.hide_kernel_kernelsu_version),
                            summary = stringResource(R.string.hide_kernel_kernelsu_version_summary),
                            checked = isHideVersion
                        ) {
                            onHideVersionChange(it)
                        }

                        // 模块数量等信息
                        SwitchItem(
                            icon = Icons.Filled.VisibilityOff,
                            title = stringResource(R.string.hide_other_info),
                            summary = stringResource(R.string.hide_other_info_summary),
                            checked = isHideOtherInfo
                        ) {
                            onHideOtherInfoChange(it)
                        }
                        
                        // SuSFS 状态信息
                        SwitchItem(
                            icon = Icons.Filled.VisibilityOff,
                            title = stringResource(R.string.hide_susfs_status),
                            summary = stringResource(R.string.hide_susfs_status_summary),
                            checked = isHideSusfsStatus
                        ) {
                            onHideSusfsStatusChange(it)
                        }

                        if (Natives.version >= Natives.MINIMAL_SUPPORTED_KPM) {
                            // 显示KPM开关
                            SwitchItem(
                                icon = Icons.Filled.Visibility,
                                title = stringResource(R.string.show_kpm_info),
                                summary = stringResource(R.string.show_kpm_info_summary),
                                checked = isShowKpmInfo
                            ) {
                                onShowKpmInfoChange(it)
                            }
                        }

                        // 隐藏链接信息
                        SwitchItem(
                            icon = Icons.Filled.VisibilityOff,
                            title = stringResource(R.string.hide_link_card),
                            summary = stringResource(R.string.hide_link_card_summary),
                            checked = isHideLinkCard
                        ) {
                            onHideLinkCardChange(it)
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
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 16.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh.copy(alpha = cardAlpha)
                    ),
                    elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
                ) {
                    Column(modifier = Modifier.padding(vertical = 8.dp)) {
                        // SELinux 开关
                        KsuIsValid {
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
                        }

                        // SuSFS 配置（仅在支持时显示）
                        val suSFS = getSuSFS()
                        val isSUS_SU = getSuSFSFeatures()
                        if (suSFS == "Supported" && isSUS_SU == "CONFIG_KSU_SUSFS_SUS_SU") {
                            // 默认启用
                            var isEnabled by rememberSaveable {
                                mutableStateOf(true)
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
                                                CardConfig.cardAlpha = 1f
                                            }
                                            if (!CardConfig.isCustomDimSet) {
                                                CardConfig.cardDim = 0.5f
                                            }
                                            CardConfig.save(context)
                                        }
                                        1 -> { // 浅色
                                            ThemeConfig.forceDarkMode = false
                                            CardConfig.isUserLightModeEnabled = true
                                            CardConfig.isUserDarkModeEnabled = false
                                            if (!CardConfig.isCustomAlphaSet) {
                                                CardConfig.cardAlpha = 1f
                                            }
                                            if (!CardConfig.isCustomDimSet) {
                                                CardConfig.cardDim = 0f
                                            }
                                            CardConfig.save(context)
                                        }
                                        0 -> { // 跟随系统
                                            ThemeConfig.forceDarkMode = null
                                            CardConfig.isUserLightModeEnabled = false
                                            CardConfig.isUserDarkModeEnabled = false
                                            if (!CardConfig.isCustomAlphaSet) {
                                                CardConfig.cardAlpha = 1f
                                            }
                                            if (!CardConfig.isCustomDimSet) {
                                                CardConfig.cardDim = if (isDarkTheme) 0.5f else 0f
                                            }
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

    // DPI 设置确认对话框
    if (showDpiConfirmDialog) {
        AlertDialog(
            onDismissRequest = { showDpiConfirmDialog = false },
            title = { Text(stringResource(R.string.dpi_confirm_title)) },
            text = {
                Column {
                    Text(stringResource(R.string.dpi_confirm_message, currentDpi, tempDpi))
                    Text(
                        stringResource(R.string.dpi_confirm_summary),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 8.dp)
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = { applyDpiSetting(tempDpi) }
                ) {
                    Text(stringResource(R.string.confirm))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        showDpiConfirmDialog = false
                        tempDpi = currentDpi
                    }
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
                            val isDark = isSystemInDarkTheme()
                            Box(
                                modifier = Modifier
                                    .size(24.dp)
                                    .clip(CircleShape)
                                    .background(if (isDark) theme.primaryDark else theme.primaryLight)
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