package zako.zako.zako.zakoui.screen.moreSettings.state

import android.content.Context
import android.content.SharedPreferences
import android.net.Uri
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import zako.zako.zako.zakoui.screen.moreSettings.util.LocaleHelper
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.theme.CardConfig
import com.sukisu.ultra.ui.theme.ThemeConfig

/**
 * 更多设置状态管理
 */
@Stable
class MoreSettingsState(
    val context: Context,
    val prefs: SharedPreferences,
    val systemIsDark: Boolean
) {
    // 主题模式选择
    var themeMode by mutableIntStateOf(
        when (ThemeConfig.forceDarkMode) {
            true -> 2 // 深色
            false -> 1 // 浅色
            null -> 0 // 跟随系统
        }
    )

    // 动态颜色开关状态
    var useDynamicColor by mutableStateOf(ThemeConfig.useDynamicColor)

    // 语言设置
    var showLanguageDialog by mutableStateOf(false)
    var currentAppLocale by mutableStateOf(LocaleHelper.getCurrentAppLocale(context))

    // 对话框显示状态
    var showThemeModeDialog by mutableStateOf(false)
    var showThemeColorDialog by mutableStateOf(false)
    var showDpiConfirmDialog by mutableStateOf(false)
    var showImageEditor by mutableStateOf(false)

    // 动态管理器配置状态
    var dynamicSignConfig by mutableStateOf<Natives.DynamicManagerConfig?>(null)
    var isDynamicSignEnabled by mutableStateOf(false)
    var dynamicSignSize by mutableStateOf("")
    var dynamicSignHash by mutableStateOf("")
    var showDynamicSignDialog by mutableStateOf(false)


    // 各种设置开关状态
    var isSimpleMode by mutableStateOf(prefs.getBoolean("is_simple_mode", false))
    var isHideVersion by mutableStateOf(prefs.getBoolean("is_hide_version", false))
    var isHideOtherInfo by mutableStateOf(prefs.getBoolean("is_hide_other_info", false))
    var isShowKpmInfo by mutableStateOf(prefs.getBoolean("show_kpm_info", false))
    var isHideZygiskImplement by mutableStateOf(prefs.getBoolean("is_hide_zygisk_Implement", false))
    var isHideSusfsStatus by mutableStateOf(prefs.getBoolean("is_hide_susfs_status", false))
    var isHideLinkCard by mutableStateOf(prefs.getBoolean("is_hide_link_card", false))
    var isHideTagRow by mutableStateOf(prefs.getBoolean("is_hide_tag_row", false))
    var isKernelSimpleMode by mutableStateOf(prefs.getBoolean("is_kernel_simple_mode", false))
    var showMoreModuleInfo by mutableStateOf(prefs.getBoolean("show_more_module_info", false))
    var useAltIcon by mutableStateOf(prefs.getBoolean("use_alt_icon", false))

    // SELinux状态
    var selinuxEnabled by mutableStateOf(false)

    // SuSFS 状态
    var isSusFSEnabled by mutableStateOf(true)

    // 卡片配置状态
    var cardAlpha by mutableFloatStateOf(CardConfig.cardAlpha)
    var cardDim by mutableFloatStateOf(CardConfig.cardDim)
    var isCustomBackgroundEnabled by mutableStateOf(ThemeConfig.customBackgroundUri != null)

    // 图片选择状态
    var selectedImageUri by mutableStateOf<Uri?>(null)

    // DPI 设置
    val systemDpi = context.resources.displayMetrics.densityDpi
    var currentDpi by mutableIntStateOf(prefs.getInt("app_dpi", systemDpi))
    var tempDpi by mutableIntStateOf(currentDpi)
    var isDpiCustom by mutableStateOf(true)

    // 主题模式选项
    val themeOptions = listOf(
        context.getString(R.string.theme_follow_system),
        context.getString(R.string.theme_light),
        context.getString(R.string.theme_dark)
    )

    // 预设 DPI 选项
    val dpiPresets = mapOf(
        context.getString(R.string.dpi_size_small) to 240,
        context.getString(R.string.dpi_size_medium) to 320,
        context.getString(R.string.dpi_size_large) to 420,
        context.getString(R.string.dpi_size_extra_large) to 560
    )
}