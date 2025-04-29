package com.sukisu.ultra.ui.theme

import android.content.Context
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.CardDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

object CardConfig {
    val defaultElevation: Dp = 1.dp

    var cardAlpha by mutableStateOf(0.80f)
    var cardElevation by mutableStateOf(defaultElevation)
    var isShadowEnabled by mutableStateOf(true)
    var isCustomAlphaSet by mutableStateOf(false)
    var isUserDarkModeEnabled by mutableStateOf(false)
    var isUserLightModeEnabled by mutableStateOf(false)
    var isCustomBackgroundEnabled by mutableStateOf(false)

    private var lastSystemDarkMode: Boolean? = null

    /**
     * 保存卡片配置到SharedPreferences
     */
    fun save(context: Context) {
        val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        prefs.edit().apply {
            putFloat("card_alpha", cardAlpha)
            putBoolean("custom_background_enabled", isCustomBackgroundEnabled)
            putBoolean("is_shadow_enabled", isShadowEnabled)
            putBoolean("is_custom_alpha_set", isCustomAlphaSet)
            putBoolean("is_user_dark_mode_enabled", isUserDarkModeEnabled)
            putBoolean("is_user_light_mode_enabled", isUserLightModeEnabled)
            apply()
        }
    }

    /**
     * 从SharedPreferences加载卡片配置
     */
    fun load(context: Context) {
        val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        cardAlpha = prefs.getFloat("card_alpha", 0.80f)
        isCustomBackgroundEnabled = prefs.getBoolean("custom_background_enabled", false)
        isShadowEnabled = prefs.getBoolean("is_shadow_enabled", true)
        cardElevation = if (isShadowEnabled) defaultElevation else 0.dp
        isCustomAlphaSet = prefs.getBoolean("is_custom_alpha_set", false)
        isUserDarkModeEnabled = prefs.getBoolean("is_user_dark_mode_enabled", false)
        isUserLightModeEnabled = prefs.getBoolean("is_user_light_mode_enabled", false)
    }

    /**
     * 更新阴影启用状态
     */
    fun updateShadowEnabled(enabled: Boolean) {
        isShadowEnabled = enabled
        cardElevation = if (enabled) defaultElevation else 0.dp
    }

    /**
     * 设置深色模式默认值
     */
    fun setDarkModeDefaults() {
        if (!isCustomAlphaSet) {
            cardAlpha = 0.50f
        }
        if (!isShadowEnabled) {
            cardElevation = 0.dp
        }
    }
}

/**
 * 获取卡片颜色配置
 */
@Composable
fun getCardColors(originalColor: Color) = CardDefaults.cardColors(
    containerColor = originalColor.copy(alpha = CardConfig.cardAlpha),
    contentColor = determineContentColor(originalColor)
)

/**
 * 根据背景颜色、主题模式和用户设置确定内容颜色
 */
@Composable
private fun determineContentColor(originalColor: Color): Color {
    val isDarkTheme = isSystemInDarkTheme()

    // 处理主题切换过程中的颜色
    if (ThemeConfig.isThemeChanging) {
        return if (isDarkTheme) Color.White else Color.Black
    }

    return when {
        // 用户明确设置了浅色或深色模式
        CardConfig.isUserLightModeEnabled -> Color.Black
        CardConfig.isUserDarkModeEnabled -> Color.White

        // 根据系统主题和背景亮度自动确定
        !isDarkTheme && originalColor.luminance() > 0.5f -> Color.Black
        isDarkTheme -> Color.White

        // 其他情况根据背景亮度确定
        else -> if (originalColor.luminance() > 0.5f) Color.Black else Color.White
    }
}