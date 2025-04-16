package zako.zako.zako.ui.theme

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
    val defaultElevation: Dp = 0.dp

    var cardAlpha by mutableStateOf(0.45f)
    var cardElevation by mutableStateOf(defaultElevation)
    var isShadowEnabled by mutableStateOf(true)
    var isCustomAlphaSet by mutableStateOf(false)
    var isUserDarkModeEnabled by mutableStateOf(false)
    var isUserLightModeEnabled by mutableStateOf(false)
    var isCustomBackgroundEnabled by mutableStateOf(false)

    fun save(context: Context) {
        val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        prefs.edit().apply {
            putFloat("card_alpha", cardAlpha)
            putBoolean("custom_background_enabled", cardElevation == 0.dp)
            putBoolean("is_custom_alpha_set", isCustomAlphaSet)
            putBoolean("is_user_dark_mode_enabled", isUserDarkModeEnabled)
            putBoolean("is_user_light_mode_enabled", isUserLightModeEnabled)
            putBoolean("is_custom_background_enabled", isCustomBackgroundEnabled)
            apply()
        }
    }

    fun load(context: Context) {
        val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        cardAlpha = prefs.getFloat("card_alpha", 0.45f)
        cardElevation = if (prefs.getBoolean("custom_background_enabled", false)) 0.dp else defaultElevation
        isCustomAlphaSet = prefs.getBoolean("is_custom_alpha_set", false)
        isUserDarkModeEnabled = prefs.getBoolean("is_user_dark_mode_enabled", false)
        isUserLightModeEnabled = prefs.getBoolean("is_user_light_mode_enabled", false)
        isCustomBackgroundEnabled = prefs.getBoolean("is_custom_background_enabled", false)
    }

    fun updateShadowEnabled(enabled: Boolean) {
        isShadowEnabled = enabled
        cardElevation = if (enabled) defaultElevation else 0.dp
    }

    fun setDarkModeDefaults() {
        if (!isCustomAlphaSet) {
        cardAlpha = 0.35f
        cardElevation = 0.dp
        }
    }
}


@Composable
fun getCardColors(originalColor: Color) = CardDefaults.elevatedCardColors(
    containerColor = originalColor.copy(alpha = CardConfig.cardAlpha),
    contentColor = when {
        CardConfig.isUserLightModeEnabled -> {
            Color.Black
        }
        CardConfig.isUserDarkModeEnabled -> {
            Color.White
        }
        !isSystemInDarkTheme() && !CardConfig.isUserDarkModeEnabled -> {
            Color.Black
        }
        !isSystemInDarkTheme() && !CardConfig.isCustomBackgroundEnabled && !CardConfig.isUserDarkModeEnabled && originalColor.luminance() > 0.3 -> {
            Color.Black
        }
        isSystemInDarkTheme() && !CardConfig.isUserDarkModeEnabled && !CardConfig.isUserLightModeEnabled-> {
            Color.White
        }
        else -> {
            Color.White
        }
    }
)

fun getCardElevation() = CardConfig.cardElevation