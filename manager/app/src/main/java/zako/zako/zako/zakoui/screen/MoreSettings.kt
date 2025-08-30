package zako.zako.zako.zakoui.screen

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.res.Configuration
import android.net.Uri
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.NavigateNext
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.edit
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.component.ImageEditorDialog
import com.sukisu.ultra.ui.component.KsuIsValid
import com.sukisu.ultra.ui.theme.*
import com.sukisu.ultra.ui.theme.CardConfig.cardElevation
import com.sukisu.ultra.ui.util.*
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.util.*
import kotlin.math.roundToInt

/**
 * @author ShirkNeko
 * @date 2025/5/31.
 */
private val SETTINGS_ITEM_HEIGHT = 56.dp
private val SETTINGS_GROUP_SPACING = 16.dp

/**
 * 保存卡片配置
 */
fun saveCardConfig(context: Context) {
    CardConfig.save(context)
}

/**
 * 更多设置屏幕
 */
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

    // 对话框显示状态
    var showThemeModeDialog by remember { mutableStateOf(false) }
    var showLanguageDialog by remember { mutableStateOf(false) }
    var showThemeColorDialog by remember { mutableStateOf(false) }
    var showDpiConfirmDialog by remember { mutableStateOf(false) }
    var showImageEditor by remember { mutableStateOf(false) }

    // 动态管理器配置状态
    var dynamicSignConfig by remember { mutableStateOf<Natives.DynamicManagerConfig?>(null) }
    var isDynamicSignEnabled by remember { mutableStateOf(false) }
    var dynamicSignSize by remember { mutableStateOf("") }
    var dynamicSignHash by remember { mutableStateOf("") }
    var showDynamicSignDialog by remember { mutableStateOf(false) }

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

    // 简洁模式开关状态
    var isSimpleMode by remember {
        mutableStateOf(prefs.getBoolean("is_simple_mode", false))
    }

    // 隐藏内核版本号开关状态
    var isHideVersion by remember {
        mutableStateOf(prefs.getBoolean("is_hide_version", false))
    }

    // 隐藏模块数量等信息开关状态
    var isHideOtherInfo by remember {
        mutableStateOf(prefs.getBoolean("is_hide_other_info", false))
    }

    // 显示KPM开关状态
    var isShowKpmInfo by remember {
        mutableStateOf(prefs.getBoolean("show_kpm_info", false))
    }

    // 隐藏 Zygisk 状态开关状态
    var isHideZygiskImplement by remember {
        mutableStateOf(prefs.getBoolean("is_hide_zygisk_Implement", false))
    }

    // 隐藏SuSFS状态开关状态
    var isHideSusfsStatus by remember {
        mutableStateOf(prefs.getBoolean("is_hide_susfs_status", false))
    }

    // 隐藏链接状态开关状态
    var isHideLinkCard by remember {
        mutableStateOf(prefs.getBoolean("is_hide_link_card", false))
    }

    // 隐藏标签行开关状态
    var isHideTagRow by remember {
        mutableStateOf(prefs.getBoolean("is_hide_tag_row", false))
    }

    // 内核版本简洁模式开关状态
    var isKernelSimpleMode by remember {
        mutableStateOf(prefs.getBoolean("is_kernel_simple_mode", false))
    }

    // 显示更多模块信息开关状态
    var showMoreModuleInfo by remember {
        mutableStateOf(prefs.getBoolean("show_more_module_info", false))
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

    // 备用图标状态
    var useAltIcon by remember { mutableStateOf(prefs.getBoolean("use_alt_icon", false)) }

    // 图片选择状态
    var selectedImageUri by remember { mutableStateOf<Uri?>(null) }

    // DPI 设置
    val systemDpi = remember { context.resources.displayMetrics.densityDpi }
    var currentDpi by remember {
        mutableIntStateOf(prefs.getInt("app_dpi", systemDpi))
    }
    var tempDpi by remember { mutableIntStateOf(currentDpi) }
    var isDpiCustom by remember { mutableStateOf(true) }

    // 预设 DPI 选项
    val dpiPresets = mapOf(
        stringResource(R.string.dpi_size_small) to 240,
        stringResource(R.string.dpi_size_medium) to 320,
        stringResource(R.string.dpi_size_large) to 420,
        stringResource(R.string.dpi_size_extra_large) to 560
    )

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


    // 更新简洁模式开关状态
    val onSimpleModeChange = { newValue: Boolean ->
        prefs.edit { putBoolean("is_simple_mode", newValue) }
        isSimpleMode = newValue
    }

    // 内核版本简洁模式开关状态
    val onKernelSimpleModeChange = { newValue: Boolean ->
        prefs.edit { putBoolean("is_kernel_simple_mode", newValue) }
        isKernelSimpleMode = newValue
    }

    // 隐藏内核版本号开关状态
    val onHideVersionChange = { newValue: Boolean ->
        prefs.edit { putBoolean("is_hide_version", newValue) }
        isHideVersion = newValue
    }

    // 隐藏模块数量等信息开关状态
    val onHideOtherInfoChange = { newValue: Boolean ->
        prefs.edit { putBoolean("is_hide_other_info", newValue) }
        isHideOtherInfo = newValue
    }

    // 更新显示KPM开关状态
    val onShowKpmInfoChange = { newValue: Boolean ->
        prefs.edit { putBoolean("show_kpm_info", newValue) }
        isShowKpmInfo = newValue
    }

    // 隐藏SuSFS状态开关状态
    val onHideSusfsStatusChange = { newValue: Boolean ->
        prefs.edit { putBoolean("is_hide_susfs_status", newValue) }
        isHideSusfsStatus = newValue
    }

    val onHideZygiskImplement = { newValue: Boolean ->
        prefs.edit { putBoolean("is_hide_zygisk_Implement", newValue) }
        isHideZygiskImplement = newValue

    }

    // 隐藏链接状态开关状态
    val onHideLinkCardChange = { newValue: Boolean ->
        prefs.edit { putBoolean("is_hide_link_card", newValue) }
        isHideLinkCard = newValue
    }

    // 隐藏标签行开关状态
    val onHideTagRowChange = { newValue: Boolean ->
        prefs.edit { putBoolean("is_hide_tag_row", newValue) }
        isHideTagRow = newValue
    }

    // 显示更多模块信息开关状态
    val onShowMoreModuleInfoChange = { newValue: Boolean ->
        prefs.edit { putBoolean("show_more_module_info", newValue) }
        showMoreModuleInfo = newValue
    }

    // 备用图标开关状态
    val onUseAltIconChange = { newValue: Boolean ->
        prefs.edit { putBoolean("use_alt_icon", newValue) }
        useAltIcon = newValue
        toggleLauncherIcon(context, newValue)
        Toast.makeText(context, context.getString(R.string.icon_switched), Toast.LENGTH_SHORT).show()
    }


    // 获取DPI大小友好名称
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

    // 应用语言设置
    val applyLanguageSetting = { code: String ->
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
            ksuApp.refreshCurrentActivity()
        }
    }

    // ========== 初始化 ==========

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
            CardConfig.setThemeDefaults(true)
        }

        currentDpi = prefs.getInt("app_dpi", systemDpi)
        tempDpi = currentDpi

        CardConfig.save(context)
    }

    // 图片选择器
    val pickImageLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            selectedImageUri = it
            showImageEditor = true
        }
    }

    // ========== UI 构建 ==========

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
                cardElevation = 0.dp
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

    // 主题模式选择对话框
    if (showThemeModeDialog) {
        SingleChoiceDialog(
            title = stringResource(R.string.theme_mode),
            options = themeOptions,
            selectedIndex = themeMode,
            onOptionSelected = { index ->
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
                        CardConfig.setThemeDefaults(true)
                        CardConfig.save(context)
                    }
                    1 -> { // 浅色
                        ThemeConfig.forceDarkMode = false
                        CardConfig.isUserLightModeEnabled = true
                        CardConfig.isUserDarkModeEnabled = false
                        CardConfig.setThemeDefaults(false)
                        CardConfig.save(context)
                    }
                    0 -> { // 跟随系统
                        ThemeConfig.forceDarkMode = null
                        CardConfig.isUserLightModeEnabled = false
                        CardConfig.isUserDarkModeEnabled = false
                        val isNightModeActive = (context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
                        CardConfig.setThemeDefaults(isNightModeActive)
                        CardConfig.save(context)
                    }
                }
            },
            onDismiss = { showThemeModeDialog = false }
        )
    }

    // 语言切换对话框
    if (showLanguageDialog) {
        KeyValueChoiceDialog(
            title = stringResource(R.string.language_setting),
            options = supportedLanguages,
            selectedCode = currentLanguage,
            onOptionSelected = { code ->
                applyLanguageSetting(code)
            },
            onDismiss = { showLanguageDialog = false }
        )
    }

    // DPI 设置确认对话框
    if (showDpiConfirmDialog) {
        ConfirmDialog(
            title = stringResource(R.string.dpi_confirm_title),
            message = stringResource(R.string.dpi_confirm_message, currentDpi, tempDpi),
            summaryText = stringResource(R.string.dpi_confirm_summary),
            confirmText = stringResource(R.string.confirm),
            dismissText = stringResource(R.string.cancel),
            onConfirm = { applyDpiSetting(tempDpi) },
            onDismiss = {
                showDpiConfirmDialog = false
                tempDpi = currentDpi
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
                            val isDark = isSystemInDarkTheme()
                            Box(
                                modifier = Modifier.padding(end = 12.dp)
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
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
                            Text(name)
                            Spacer(modifier = Modifier.weight(1f))
                            // 当前选中的主题显示选中标记
                            if (ThemeConfig.currentTheme::class == theme::class) {
                                Icon(
                                    Icons.Default.Check,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary
                                )
                            }
                        }
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = { showThemeColorDialog = false }
                ) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }

    LaunchedEffect(Unit) {
        // 初始化动态管理器配置
        dynamicSignConfig = Natives.getDynamicManager()
        dynamicSignConfig?.let { config ->
            if (config.isValid()) {
                isDynamicSignEnabled = true
                dynamicSignSize = config.size.toString()
                dynamicSignHash = config.hash
            }
        }
    }

    fun parseDynamicSignSize(input: String): Int? {
        return try {
            when {
                input.startsWith("0x", true) -> input.substring(2).toInt(16)
                else -> input.toInt()
            }
        } catch (_: NumberFormatException) {
            null
        }
    }

    // 动态管理器配置对话框
    if (showDynamicSignDialog) {
        AlertDialog(
            onDismissRequest = { showDynamicSignDialog = false },
            title = { Text(stringResource(R.string.dynamic_manager_title)) },
            text = {
                Column(
                    modifier = Modifier.verticalScroll(rememberScrollState())
                ) {
                    // 启用开关
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { isDynamicSignEnabled = !isDynamicSignEnabled }
                            .padding(vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Switch(
                            checked = isDynamicSignEnabled,
                            onCheckedChange = { isDynamicSignEnabled = it }
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(stringResource(R.string.enable_dynamic_manager))
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    // 签名大小输入
                    OutlinedTextField(
                        value = dynamicSignSize,
                        onValueChange = { input ->
                            val isValid = when {
                                input.isEmpty() -> true
                                input.matches(Regex("^\\d+$")) -> true
                                input.matches(Regex("^0[xX][0-9a-fA-F]*$")) -> true
                                else -> false
                            }
                            if (isValid) {
                                dynamicSignSize = input
                            }
                        },
                        label = { Text(stringResource(R.string.signature_size)) },
                        enabled = isDynamicSignEnabled,
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Text
                        )
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    // 签名哈希输入
                    OutlinedTextField(
                        value = dynamicSignHash,
                        onValueChange = { hash ->
                            if (hash.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
                                dynamicSignHash = hash
                            }
                        },
                        label = { Text(stringResource(R.string.signature_hash)) },
                        enabled = isDynamicSignEnabled,
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        supportingText = {
                            Text(stringResource(R.string.hash_must_be_64_chars))
                        },
                        isError = isDynamicSignEnabled && dynamicSignHash.isNotEmpty() && dynamicSignHash.length != 64
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (isDynamicSignEnabled) {
                            val size = parseDynamicSignSize(dynamicSignSize)
                            if (size != null && size > 0 && dynamicSignHash.length == 64) {
                                val success = Natives.setDynamicManager(size, dynamicSignHash)
                                if (success) {
                                    dynamicSignConfig = Natives.DynamicManagerConfig(size, dynamicSignHash)
                                    Toast.makeText(
                                        context,
                                        context.getString(R.string.dynamic_manager_set_success),
                                        Toast.LENGTH_SHORT
                                    ).show()
                                } else {
                                    Toast.makeText(
                                        context,
                                        context.getString(R.string.dynamic_manager_set_failed),
                                        Toast.LENGTH_SHORT
                                    ).show()
                                }
                            } else {
                                Toast.makeText(
                                    context,
                                    context.getString(R.string.invalid_sign_config),
                                    Toast.LENGTH_SHORT
                                ).show()
                                return@Button
                            }
                        } else {
                            val success = Natives.clearDynamicManager()
                            if (success) {
                                dynamicSignConfig = null
                                dynamicSignSize = ""
                                dynamicSignHash = ""
                                Toast.makeText(
                                    context,
                                    context.getString(R.string.dynamic_manager_disabled_success),
                                    Toast.LENGTH_SHORT
                                ).show()
                            } else {
                                Toast.makeText(
                                    context,
                                    context.getString(R.string.dynamic_manager_clear_failed),
                                    Toast.LENGTH_SHORT
                                ).show()
                                return@Button
                            }
                        }
                        showDynamicSignDialog = false
                    },
                    enabled = if (isDynamicSignEnabled) {
                        parseDynamicSignSize(dynamicSignSize)?.let { it > 0 } == true &&
                                dynamicSignHash.length == 64
                    } else true
                ) {
                    Text(stringResource(R.string.confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = { showDynamicSignDialog = false }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }

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
                    IconButton(onClick = {
                        navigator.popBackStack()
                    }) {
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
            // ========== 外观设置部分 ==========
            SettingsCard(
                title = stringResource(R.string.appearance_settings),
            ) {
                // 语言设置
                SettingItem(
                    icon = Icons.Default.Language,
                    title = stringResource(R.string.language_setting),
                    subtitle = supportedLanguages.find { it.first == currentLanguage }?.second
                        ?: stringResource(R.string.language_follow_system),
                    onClick = { showLanguageDialog = true }
                )

                // 主题模式
                SettingItem(
                    icon = Icons.Default.DarkMode,
                    title = stringResource(R.string.theme_mode),
                    subtitle = themeOptions[themeMode],
                    onClick = { showThemeModeDialog = true }
                )

                // 动态颜色开关
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    SwitchSettingItem(
                        icon = Icons.Filled.ColorLens,
                        title = stringResource(R.string.dynamic_color_title),
                        summary = stringResource(R.string.dynamic_color_summary),
                        checked = useDynamicColor,
                        onChange = { enabled ->
                            useDynamicColor = enabled
                            context.saveDynamicColorState(enabled)
                        }
                    )
                }

                // 只在未启用动态颜色时显示主题色选择
                AnimatedVisibility(
                    visible = Build.VERSION.SDK_INT < Build.VERSION_CODES.S || !useDynamicColor,
                    enter = fadeIn() + expandVertically(),
                    exit = fadeOut() + shrinkVertically()
                ) {
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
                        onClick = { showThemeColorDialog = true },
                        trailingContent = {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.padding(start = 8.dp)
                            ) {
                                // 显示当前主题的三种主题色调
                                val theme = ThemeConfig.currentTheme
                                val isDark = isSystemInDarkTheme()

                                // Primary color
                                ColorCircle(
                                    color = if (isDark) theme.primaryDark else theme.primaryLight,
                                    isSelected = false,
                                    modifier = Modifier.padding(horizontal = 2.dp)
                                )

                                // Secondary color
                                ColorCircle(
                                    color = if (isDark) theme.secondaryDark else theme.secondaryLight,
                                    isSelected = false,
                                    modifier = Modifier.padding(horizontal = 2.dp)
                                )

                                // Tertiary color
                                ColorCircle(
                                    color = if (isDark) theme.tertiaryDark else theme.tertiaryLight,
                                    isSelected = false,
                                    modifier = Modifier.padding(horizontal = 2.dp)
                                )
                            }
                        }
                    )
                }

                SettingsDivider()

                // DPI 设置
                SettingItem(
                    icon = Icons.Default.FormatSize,
                    title = stringResource(R.string.app_dpi_title),
                    subtitle = stringResource(R.string.app_dpi_summary),
                    onClick = {},
                    trailingContent = {
                        Text(
                            text = getDpiFriendlyName(tempDpi),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                )

                // DPI 滑动条
                Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                    val sliderValue by animateFloatAsState(
                        targetValue = tempDpi.toFloat(),
                        label = "DPI Slider Animation"
                    )

                    Slider(
                        value = sliderValue,
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
                            val isSelected = tempDpi == dpi
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
                                        tempDpi = dpi
                                        isDpiCustom = false
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
                        text = if (isDpiCustom)
                            "${stringResource(R.string.dpi_size_custom)}: $tempDpi"
                        else
                            "${getDpiFriendlyName(tempDpi)}: $tempDpi",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(top = 8.dp)
                    )

                    Button(
                        onClick = {
                            if (tempDpi != currentDpi) {
                                showDpiConfirmDialog = true
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                        enabled = tempDpi != currentDpi
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

                SettingsDivider()

                // 自定义背景开关
                SwitchSettingItem(
                    icon = Icons.Filled.Wallpaper,
                    title = stringResource(id = R.string.settings_custom_background),
                    summary = stringResource(id = R.string.settings_custom_background_summary),
                    checked = isCustomBackgroundEnabled,
                    onChange = { isChecked ->
                        if (isChecked) {
                            pickImageLauncher.launch("image/*")
                        } else {
                            context.saveCustomBackground(null)
                            isCustomBackgroundEnabled = false
                            CardConfig.cardAlpha = 1f
                            CardConfig.cardDim = 0f
                            CardConfig.isCustomAlphaSet = false
                            CardConfig.isCustomDimSet = false
                            CardConfig.isCustomBackgroundEnabled = false
                            saveCardConfig(context)

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

                // 透明度和亮度调节滑动条
                AnimatedVisibility(
                    visible = ThemeConfig.customBackgroundUri != null,
                    enter = fadeIn() + slideInVertically(),
                    exit = fadeOut() + slideOutVertically()
                ) {
                    Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
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
                            )
                        }

                        val alphaSliderValue by animateFloatAsState(
                            targetValue = cardAlpha,
                            label = "Alpha Slider Animation"
                        )

                        Slider(
                            value = alphaSliderValue,
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
                            )
                        }

                        val dimSliderValue by animateFloatAsState(
                            targetValue = cardDim,
                            label = "Dim Slider Animation"
                        )

                        Slider(
                            value = dimSliderValue,
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

            // 自定义设置
            SettingsCard(
                title = stringResource(R.string.custom_settings)
            ) {
                // 图标切换
                SwitchSettingItem(
                    icon = Icons.Default.Android,
                    title = stringResource(R.string.icon_switch_title),
                    summary = stringResource(R.string.icon_switch_summary),
                    checked = useAltIcon,
                    onChange = onUseAltIconChange
                )

                // 显示更多模块信息开关
                SwitchSettingItem(
                    icon = Icons.Filled.Info,
                    title = stringResource(R.string.show_more_module_info),
                    summary = stringResource(R.string.show_more_module_info_summary),
                    checked = showMoreModuleInfo,
                    onChange = onShowMoreModuleInfoChange
                )

                // 添加简洁模式开关
                SwitchSettingItem(
                    icon = Icons.Filled.Brush,
                    title = stringResource(R.string.simple_mode),
                    summary = stringResource(R.string.simple_mode_summary),
                    checked = isSimpleMode,
                    onChange = onSimpleModeChange
                )

                SwitchSettingItem(
                    icon = Icons.Filled.Brush,
                    title = stringResource(R.string.kernel_simple_kernel),
                    summary = stringResource(R.string.kernel_simple_kernel_summary),
                    checked = isKernelSimpleMode,
                    onChange = onKernelSimpleModeChange
                )

                // 隐藏内核部分版本号
                SwitchSettingItem(
                    icon = Icons.Filled.VisibilityOff,
                    title = stringResource(R.string.hide_kernel_kernelsu_version),
                    summary = stringResource(R.string.hide_kernel_kernelsu_version_summary),
                    checked = isHideVersion,
                    onChange = onHideVersionChange
                )

                // 模块数量等信息
                SwitchSettingItem(
                    icon = Icons.Filled.VisibilityOff,
                    title = stringResource(R.string.hide_other_info),
                    summary = stringResource(R.string.hide_other_info_summary),
                    checked = isHideOtherInfo,
                    onChange = onHideOtherInfoChange
                )

                // SuSFS 状态信息
                SwitchSettingItem(
                    icon = Icons.Filled.VisibilityOff,
                    title = stringResource(R.string.hide_susfs_status),
                    summary = stringResource(R.string.hide_susfs_status_summary),
                    checked = isHideSusfsStatus,
                    onChange = onHideSusfsStatusChange
                )

                // Zygsik 实现状态信息
                SwitchSettingItem(
                    icon = Icons.Filled.VisibilityOff,
                    title = stringResource(R.string.hide_zygisk_implement),
                    summary = stringResource(R.string.hide_zygisk_implement_summary),
                    checked = isHideZygiskImplement,
                    onChange = onHideZygiskImplement
                )

                if (Natives.version >= Natives.MINIMAL_SUPPORTED_KPM) {
                    // 隐藏KPM开关
                    SwitchSettingItem(
                        icon = Icons.Filled.VisibilityOff,
                        title = stringResource(R.string.show_kpm_info),
                        summary = stringResource(R.string.show_kpm_info_summary),
                        checked = isShowKpmInfo,
                        onChange = onShowKpmInfoChange
                    )
                }

                // 隐藏链接信息
                SwitchSettingItem(
                    icon = Icons.Filled.VisibilityOff,
                    title = stringResource(R.string.hide_link_card),
                    summary = stringResource(R.string.hide_link_card_summary),
                    checked = isHideLinkCard,
                    onChange = onHideLinkCardChange
                )

                // 隐藏标签行
                SwitchSettingItem(
                    icon = Icons.Filled.VisibilityOff,
                    title = stringResource(R.string.hide_tag_card),
                    summary = stringResource(R.string.hide_tag_card_summary),
                    checked = isHideTagRow,
                    onChange = onHideTagRowChange
                )
            }
            KsuIsValid {
                // 高级设置
                SettingsCard(
                    title = stringResource(R.string.advanced_settings)
                ) {
                    // SELinux 开关
                    SwitchSettingItem(
                        icon = Icons.Filled.Security,
                        title = stringResource(R.string.selinux),
                        summary = if (selinuxEnabled)
                            stringResource(R.string.selinux_enabled) else
                            stringResource(R.string.selinux_disabled),
                        checked = selinuxEnabled,
                        onChange = { enabled ->
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
                    )

                    // SuSFS 开关（仅在支持时显示）
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

                        SwitchSettingItem(
                            icon = Icons.Filled.Security,
                            title = stringResource(id = R.string.settings_susfs_toggle),
                            summary = stringResource(id = R.string.settings_susfs_toggle_summary),
                            checked = isEnabled,
                            onChange = {
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
                        )
                    }
                    // 动态管理器设置
                    if (Natives.version >= Natives.MINIMAL_SUPPORTED_DYNAMIC_MANAGER) {
                        SettingItem(
                            icon = Icons.Filled.Security,
                            title = stringResource(R.string.dynamic_manager_title),
                            subtitle = if (isDynamicSignEnabled) {
                                stringResource(
                                    R.string.dynamic_manager_enabled_summary,
                                    dynamicSignSize
                                )
                            } else {
                                stringResource(R.string.dynamic_manager_disabled)
                            },
                            onClick = { showDynamicSignDialog = true }
                        )
                    }
                }
            }
        }
    }
}



@Composable
fun SettingsCard(
    title: String,
    icon: ImageVector? = null,
    content: @Composable () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = SETTINGS_GROUP_SPACING),
        colors = getCardColors(MaterialTheme.colorScheme.surfaceContainerHigh),
        elevation = getCardElevation(),
        shape = MaterialTheme.shapes.medium
    ) {
        Column(modifier = Modifier.padding(vertical = 8.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp)
                    .padding(horizontal = 16.dp)
            ) {
                if (icon != null) {
                    Icon(
                        imageVector = icon,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                }
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                )
            }
            content()
        }
    }
}

@Composable
fun SettingItem(
    icon: ImageVector,
    title: String,
    subtitle: String? = null,
    onClick: () -> Unit,
    iconTint: Color = MaterialTheme.colorScheme.primary,
    trailingContent: @Composable (() -> Unit)? = {
        Icon(
            Icons.AutoMirrored.Filled.NavigateNext,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
//            .height(if (subtitle != null) SETTINGS_ITEM_HEIGHT + 12.dp else SETTINGS_ITEM_HEIGHT)
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 5.dp),
        verticalAlignment = Alignment.Top
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = iconTint,
            modifier = Modifier
                .padding(end = 16.dp)
                .size(24.dp)
        )

        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                maxLines = Int.MAX_VALUE,
                overflow = TextOverflow.Visible
            )
            if (subtitle != null) {
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = Int.MAX_VALUE,
                    overflow = TextOverflow.Visible
                )
            }
        }

        trailingContent?.invoke()
    }
}

@Composable
fun SwitchSettingItem(
    icon: ImageVector,
    title: String,
    summary: String? = null,
    checked: Boolean,
    onChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
//            .height(if (summary != null) SETTINGS_ITEM_HEIGHT + 12.dp else SETTINGS_ITEM_HEIGHT)
            .clickable { onChange(!checked) }
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.Top
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = if (checked) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier
                .padding(end = 16.dp)
                .size(24.dp)
        )

        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                lineHeight = 20.sp,
//                maxLines = 1,
//                overflow = TextOverflow.Ellipsis
            )
            if (summary != null) {
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = summary,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    lineHeight = 16.sp,
//                    maxLines = 2,
//                    overflow = TextOverflow.Ellipsis
                )
            }
        }

        Switch(
            checked = checked,
            onCheckedChange = onChange
        )
    }
}

@Composable
fun SettingsDivider() {
    HorizontalDivider(
        modifier = Modifier.padding(vertical = 8.dp)
    )
}

@Composable
fun ColorCircle(
    color: Color,
    isSelected: Boolean,
    modifier: Modifier = Modifier
) {
    Box(
        modifier = modifier
            .size(20.dp)
            .clip(CircleShape)
            .background(color)
            .then(
                if (isSelected) {
                    Modifier.border(
                        width = 2.dp,
                        color = MaterialTheme.colorScheme.primary,
                        shape = CircleShape
                    )
                } else {
                    Modifier
                }
            )
    )
}

@Composable
fun SingleChoiceDialog(
    title: String,
    options: List<String>,
    selectedIndex: Int,
    onOptionSelected: (Int) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                options.forEachIndexed { index, option ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                onOptionSelected(index)
                                onDismiss()
                            }
                            .padding(vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = selectedIndex == index,
                            onClick = null
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(option)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
        }
    )
}

@Composable
fun ConfirmDialog(
    title: String,
    message: String,
    summaryText: String? = null,
    confirmText: String = stringResource(R.string.confirm),
    dismissText: String = stringResource(R.string.cancel),
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                Text(message)
                if (summaryText != null) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        summaryText,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(confirmText)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(dismissText)
            }
        }
    )
}

@Composable
fun KeyValueChoiceDialog(
    title: String,
    options: List<Pair<String, String>>,
    selectedCode: String,
    onOptionSelected: (String) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                options.forEach { (code, name) ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                onOptionSelected(code)
                                onDismiss()
                            }
                            .padding(vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = selectedCode == code,
                            onClick = null
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(name)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
        }
    )
}