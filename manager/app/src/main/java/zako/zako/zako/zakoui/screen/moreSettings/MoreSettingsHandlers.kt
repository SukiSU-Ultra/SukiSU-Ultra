package zako.zako.zako.zakoui.screen.moreSettings

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.res.Configuration
import android.net.Uri
import android.widget.Toast
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.edit
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.theme.*
import com.sukisu.ultra.ui.util.*
import com.topjohnwu.superuser.Shell
import zako.zako.zako.zakoui.screen.moreSettings.state.MoreSettingsState
import zako.zako.zako.zakoui.screen.moreSettings.util.toggleLauncherIcon

/**
 * 更多设置处理器
 */
class MoreSettingsHandlers(
    val context: Context,
    private val prefs: SharedPreferences,
    private val state: MoreSettingsState
) {

    /**
     * 初始化设置
     */
    fun initializeSettings() {
        // 加载设置
        CardConfig.load(context)
        state.cardAlpha = CardConfig.cardAlpha
        state.cardDim = CardConfig.cardDim
        state.isCustomBackgroundEnabled = ThemeConfig.customBackgroundUri != null

        // 设置主题模式
        state.themeMode = when (ThemeConfig.forceDarkMode) {
            true -> 2
            false -> 1
            null -> 0
        }

        // 确保卡片样式跟随主题模式
        when (state.themeMode) {
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
        if (state.themeMode == 0 && state.systemIsDark) {
            CardConfig.setThemeDefaults(true)
        }

        state.currentDpi = prefs.getInt("app_dpi", state.systemDpi)
        state.tempDpi = state.currentDpi

        CardConfig.save(context)

        // 初始化 SELinux 状态
        state.selinuxEnabled = Shell.cmd("getenforce").exec().out.firstOrNull() == "Enforcing"

        // 初始化动态管理器配置
        state.dynamicSignConfig = Natives.getDynamicManager()
        state.dynamicSignConfig?.let { config ->
            if (config.isValid()) {
                state.isDynamicSignEnabled = true
                state.dynamicSignSize = config.size.toString()
                state.dynamicSignHash = config.hash
            }
        }

        // 初始化 SuSFS 状态
        val currentMode = susfsSUS_SU_Mode()
        val wasManuallyDisabled = prefs.getBoolean("enable_sus_su", true)
        if (currentMode != "2" && wasManuallyDisabled) {
            susfsSUS_SU_2()
            prefs.edit { putBoolean("enable_sus_su", true) }
        }
        state.isSusFSEnabled = currentMode == "2"
    }

    /**
     * 处理主题模式变更
     */
    fun handleThemeModeChange(index: Int) {
        state.themeMode = index
        val newThemeMode = when (index) {
            0 -> null // 跟随系统
            1 -> false // 浅色
            2 -> true // 深色
            else -> null
        }
        context.saveThemeMode(newThemeMode)
        ThemeConfig.updateTheme(darkMode = newThemeMode)

        when (index) {
            2 -> { // 深色
                ThemeConfig.updateTheme(darkMode = true)
                CardConfig.updateThemePreference(darkMode = true, lightMode = false)
                CardConfig.setThemeDefaults(true)
                CardConfig.save(context)
            }
            1 -> { // 浅色
                ThemeConfig.updateTheme(darkMode = false)
                CardConfig.updateThemePreference(darkMode = false, lightMode = true)
                CardConfig.setThemeDefaults(false)
                CardConfig.save(context)
            }
            0 -> { // 跟随系统
                ThemeConfig.updateTheme(darkMode = null)
                CardConfig.updateThemePreference(darkMode = null, lightMode = null)
                val isNightModeActive = (context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
                CardConfig.setThemeDefaults(isNightModeActive)
                CardConfig.save(context)
            }
        }
    }

    /**
     * 处理主题色变更
     */
    fun handleThemeColorChange(theme: ThemeColors) {
        context.saveThemeColors(when (theme) {
            ThemeColors.Green -> "green"
            ThemeColors.Purple -> "purple"
            ThemeColors.Orange -> "orange"
            ThemeColors.Pink -> "pink"
            ThemeColors.Gray -> "gray"
            ThemeColors.Yellow -> "yellow"
            else -> "default"
        })
        ThemeConfig.updateTheme(theme = theme)
    }

    /**
     * 处理动态颜色变更
     */
    fun handleDynamicColorChange(enabled: Boolean) {
        state.useDynamicColor = enabled
        context.saveDynamicColorState(enabled)
        ThemeConfig.updateTheme(dynamicColor = enabled)
    }

    /**
     * 获取DPI大小友好名称
     */
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

    /**
     * 应用 DPI 设置
     */
    fun handleDpiApply() {
        if (state.tempDpi != state.currentDpi) {
            prefs.edit {
                putInt("app_dpi", state.tempDpi)
            }

            state.currentDpi = state.tempDpi
            Toast.makeText(
                context,
                context.getString(R.string.dpi_applied_success, state.tempDpi),
                Toast.LENGTH_SHORT
            ).show()

            val restartIntent = context.packageManager.getLaunchIntentForPackage(context.packageName)
            restartIntent?.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK or Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(restartIntent)

            state.showDpiConfirmDialog = false
        }
    }

    /**
     * 处理自定义背景
     */
    fun handleCustomBackground(transformedUri: Uri) {
        context.saveAndApplyCustomBackground(transformedUri)
        state.isCustomBackgroundEnabled = true
        CardConfig.cardElevation = 0.dp
        CardConfig.isCustomBackgroundEnabled = true
        saveCardConfig(context)

        Toast.makeText(
            context,
            context.getString(R.string.background_set_success),
            Toast.LENGTH_SHORT
        ).show()
    }

    /**
     * 处理移除自定义背景
     */
    fun handleRemoveCustomBackground() {
        context.saveCustomBackground(null)
        state.isCustomBackgroundEnabled = false
        CardConfig.cardAlpha = 1f
        CardConfig.cardDim = 0f
        CardConfig.isCustomAlphaSet = false
        CardConfig.isCustomDimSet = false
        CardConfig.isCustomBackgroundEnabled = false
        saveCardConfig(context)
        ThemeConfig.preventBackgroundRefresh = false

        context.getSharedPreferences("theme_prefs", Context.MODE_PRIVATE).edit {
            putBoolean("prevent_background_refresh", false)
        }

        Toast.makeText(
            context,
            context.getString(R.string.background_removed),
            Toast.LENGTH_SHORT
        ).show()
    }

    /**
     * 处理卡片透明度变更
     */
    fun handleCardAlphaChange(newValue: Float) {
        state.cardAlpha = newValue
        CardConfig.cardAlpha = newValue
        CardConfig.isCustomAlphaSet = true
        prefs.edit {
            putBoolean("is_custom_alpha_set", true)
            putFloat("card_alpha", newValue)
        }
    }

    /**
     * 处理卡片亮度变更
     */
    fun handleCardDimChange(newValue: Float) {
        state.cardDim = newValue
        CardConfig.cardDim = newValue
        CardConfig.isCustomDimSet = true
        prefs.edit {
            putBoolean("is_custom_dim_set", true)
            putFloat("card_dim", newValue)
        }
    }

    /**
     * 处理图标变更
     */
    fun handleIconChange(newValue: Boolean) {
        prefs.edit { putBoolean("use_alt_icon", newValue) }
        state.useAltIcon = newValue
        toggleLauncherIcon(context, newValue)
        Toast.makeText(context, context.getString(R.string.icon_switched), Toast.LENGTH_SHORT).show()
    }

    /**
     * 处理简洁模式变更
     */
    fun handleSimpleModeChange(newValue: Boolean) {
        prefs.edit { putBoolean("is_simple_mode", newValue) }
        state.isSimpleMode = newValue
    }

    /**
     * 处理内核简洁模式变更
     */
    fun handleKernelSimpleModeChange(newValue: Boolean) {
        prefs.edit { putBoolean("is_kernel_simple_mode", newValue) }
        state.isKernelSimpleMode = newValue
    }

    /**
     * 处理隐藏版本变更
     */
    fun handleHideVersionChange(newValue: Boolean) {
        prefs.edit { putBoolean("is_hide_version", newValue) }
        state.isHideVersion = newValue
    }

    /**
     * 处理隐藏其他信息变更
     */
    fun handleHideOtherInfoChange(newValue: Boolean) {
        prefs.edit { putBoolean("is_hide_other_info", newValue) }
        state.isHideOtherInfo = newValue
    }

    /**
     * 处理显示KPM信息变更
     */
    fun handleShowKpmInfoChange(newValue: Boolean) {
        prefs.edit { putBoolean("show_kpm_info", newValue) }
        state.isShowKpmInfo = newValue
    }

    /**
     * 处理隐藏SuSFS状态变更
     */
    fun handleHideSusfsStatusChange(newValue: Boolean) {
        prefs.edit { putBoolean("is_hide_susfs_status", newValue) }
        state.isHideSusfsStatus = newValue
    }

    /**
     * 处理隐藏Zygisk实现变更
     */
    fun handleHideZygiskImplementChange(newValue: Boolean) {
        prefs.edit { putBoolean("is_hide_zygisk_Implement", newValue) }
        state.isHideZygiskImplement = newValue
    }

    /**
     * 处理隐藏链接卡片变更
     */
    fun handleHideLinkCardChange(newValue: Boolean) {
        prefs.edit { putBoolean("is_hide_link_card", newValue) }
        state.isHideLinkCard = newValue
    }

    /**
     * 处理隐藏标签行变更
     */
    fun handleHideTagRowChange(newValue: Boolean) {
        prefs.edit { putBoolean("is_hide_tag_row", newValue) }
        state.isHideTagRow = newValue
    }

    /**
     * 处理显示更多模块信息变更
     */
    fun handleShowMoreModuleInfoChange(newValue: Boolean) {
        prefs.edit { putBoolean("show_more_module_info", newValue) }
        state.showMoreModuleInfo = newValue
    }

    /**
     * 处理SELinux变更
     */
    fun handleSelinuxChange(enabled: Boolean) {
        val command = if (enabled) "setenforce 1" else "setenforce 0"
        Shell.getShell().newJob().add(command).exec().let { result ->
            if (result.isSuccess) {
                state.selinuxEnabled = enabled
                val message = if (enabled)
                    context.getString(R.string.selinux_enabled_toast)
                else
                    context.getString(R.string.selinux_disabled_toast)

                Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(
                    context,
                    context.getString(R.string.selinux_change_failed),
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
    }

    /**
     * 处理SuSFS变更
     */
    fun handleSusFSChange(enabled: Boolean) {
        if (enabled) {
            susfsSUS_SU_2()
            prefs.edit { putBoolean("enable_sus_su", true) }
            Toast.makeText(
                context,
                context.getString(R.string.susfs_enabled),
                Toast.LENGTH_SHORT
            ).show()
        } else {
            susfsSUS_SU_0()
            prefs.edit { putBoolean("enable_sus_su", false) }
            Toast.makeText(
                context,
                context.getString(R.string.susfs_disabled),
                Toast.LENGTH_SHORT
            ).show()
        }
        state.isSusFSEnabled = enabled
    }

    /**
     * 处理动态管理器配置
     */
    fun handleDynamicManagerConfig(enabled: Boolean, size: String, hash: String) {
        if (enabled) {
            val parsedSize = parseDynamicSignSize(size)
            if (parsedSize != null && parsedSize > 0 && hash.length == 64) {
                val success = Natives.setDynamicManager(parsedSize, hash)
                if (success) {
                    state.dynamicSignConfig = Natives.DynamicManagerConfig(parsedSize, hash)
                    state.isDynamicSignEnabled = true
                    state.dynamicSignSize = size
                    state.dynamicSignHash = hash
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
            }
        } else {
            val success = Natives.clearDynamicManager()
            if (success) {
                state.dynamicSignConfig = null
                state.isDynamicSignEnabled = false
                state.dynamicSignSize = ""
                state.dynamicSignHash = ""
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
            }
        }
    }

    /**
     * 解析动态签名大小
     */
    private fun parseDynamicSignSize(input: String): Int? {
        return try {
            when {
                input.startsWith("0x", true) -> input.substring(2).toInt(16)
                else -> input.toInt()
            }
        } catch (_: NumberFormatException) {
            null
        }
    }
}