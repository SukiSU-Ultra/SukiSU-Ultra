package com.sukisu.ultra.ui.theme

import android.content.Context
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.CardDefaults
import androidx.compose.runtime.*
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.unit.dp

object CardConfig {
    // 卡片透明度
    var cardAlpha by mutableFloatStateOf(1f)
    // 卡片亮度
    var cardDim by mutableFloatStateOf(0f)
    // 卡片阴影
    var cardElevation by mutableStateOf(0.dp)
    var isShadowEnabled by mutableStateOf(true)
    var isCustomAlphaSet by mutableStateOf(false)
    var isCustomDimSet by mutableStateOf(false)
    var isUserDarkModeEnabled by mutableStateOf(false)
    var isUserLightModeEnabled by mutableStateOf(false)
    var isCustomBackgroundEnabled by mutableStateOf(false)

    /**
     * 保存卡片配置到SharedPreferences
     */
    fun save(context: Context) {
        val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        prefs.edit().apply {
            putFloat("card_alpha", cardAlpha)
            putFloat("card_dim", cardDim)
            putBoolean("custom_background_enabled", isCustomBackgroundEnabled)
            putBoolean("is_shadow_enabled", isShadowEnabled)
            putBoolean("is_custom_alpha_set", isCustomAlphaSet)
            putBoolean("is_custom_dim_set", isCustomDimSet)
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
        cardAlpha = prefs.getFloat("card_alpha", 1f)
        cardDim = prefs.getFloat("card_dim", 0f)
        isCustomBackgroundEnabled = prefs.getBoolean("custom_background_enabled", false)
        isShadowEnabled = prefs.getBoolean("is_shadow_enabled", true)
        isCustomAlphaSet = prefs.getBoolean("is_custom_alpha_set", false)
        isCustomDimSet = prefs.getBoolean("is_custom_dim_set", false)
        isUserDarkModeEnabled = prefs.getBoolean("is_user_dark_mode_enabled", false)
        isUserLightModeEnabled = prefs.getBoolean("is_user_light_mode_enabled", false)
        updateShadowEnabled(isShadowEnabled)
    }

    /**
     * 更新阴影启用状态
     */
    fun updateShadowEnabled(enabled: Boolean) {
        isShadowEnabled = enabled
        cardElevation = 0.dp
    }

    /**
     * 设置主题模式默认值
     */
    fun setThemeDefaults(isDarkMode: Boolean) {
        if (!isCustomAlphaSet) {
            cardAlpha = 1f
        }
        if (!isCustomDimSet) {
            cardDim = if (isDarkMode) 0.5f else 0f
        }
        updateShadowEnabled(isShadowEnabled)
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
 * 获取卡片阴影配置
 */
@Composable
fun getCardElevation() = CardDefaults.cardElevation(
    defaultElevation = CardConfig.cardElevation,
    pressedElevation = CardConfig.cardElevation,
    focusedElevation = CardConfig.cardElevation,
    hoveredElevation = CardConfig.cardElevation,
    draggedElevation = CardConfig.cardElevation,
    disabledElevation = CardConfig.cardElevation
)

/**
 * 根据背景颜色、主题模式和用户设置确定内容颜色
 */
@Composable
private fun determineContentColor(originalColor: Color): Color {
    val isDarkTheme = isSystemInDarkTheme()
    if (ThemeConfig.isThemeChanging) {
        return if (isDarkTheme) Color.White else Color.Black
    }

    return when {
        CardConfig.isUserLightModeEnabled -> Color.Black
        !isDarkTheme && originalColor.luminance() > 0.5f -> Color.Black
        isDarkTheme -> Color.White
        else -> if (originalColor.luminance() > 0.5f) Color.Black else Color.White
    }
}
