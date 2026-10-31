package com.sukisu.ultra.ai

import androidx.annotation.StringRes
import com.sukisu.ultra.ai.R
import kotlinx.serialization.Serializable

/**
 * Fine-grained theme write scopes. [AiConfig.allowThemeWrite] stays the master
 * switch; a feature is writable only when both the master and its id are set.
 */
@Serializable
enum class AiThemeFeature(
    val id: String,
    @StringRes val labelRes: Int,
    @StringRes val summaryRes: Int,
) {
    APPEARANCE(
        "appearance",
        R.string.ai_theme_feature_appearance,
        R.string.ai_theme_feature_appearance_summary,
    ),
    CUSTOM_TEXTS(
        "custom_texts",
        R.string.ai_theme_feature_custom_texts,
        R.string.ai_theme_feature_custom_texts_summary,
    ),
    IMAGES(
        "images",
        R.string.ai_theme_feature_images,
        R.string.ai_theme_feature_images_summary,
    ),
    APP_ICON(
        "app_icon",
        R.string.ai_theme_feature_app_icon,
        R.string.ai_theme_feature_app_icon_summary,
    ),
    HOME_DISPLAY(
        "home_display",
        R.string.ai_theme_feature_home_display,
        R.string.ai_theme_feature_home_display_summary,
    ),
    THEME_PACKAGE(
        "theme_package",
        R.string.ai_theme_feature_theme_package,
        R.string.ai_theme_feature_theme_package_summary,
    );

    companion object {
        val ALL_IDS: Set<String> = entries.map { it.id }.toSet()

        fun fromId(id: String?): AiThemeFeature? =
            entries.firstOrNull { it.id == id }

        /** Theme keys accepted by [AiThemeService.set]. */
        fun forKey(key: String): AiThemeFeature? = when (key.trim().lowercase().replace('-', '_')) {
            "ui_mode", "color_mode", "miuix_monet", "key_color", "color_style", "color_spec",
            "card_background_alpha", "background_blur", "background_scrim",
            "extract_color_from_background", "use_system_wallpaper", "blur",
            "floating_bottom_bar", "floating_bottom_bar_blur", "navigation_badge", "page_scale",
            "predictive_back", "swipe_dismiss", "pager_mode", "module_description_max_lines",
            -> APPEARANCE

            "custom_home_title" -> CUSTOM_TEXTS
            "app_icon", "app_icon_dynamic_color" -> APP_ICON
            "show_full_status", "hide_home_warnings" -> HOME_DISPLAY
            else -> null
        }
    }
}

/** Fine-grained extension write scopes; the master switch is still required. */
@Serializable
enum class AiExtensionFeature(
    val id: String,
    @StringRes val labelRes: Int,
    @StringRes val summaryRes: Int,
) {
    STICKY_TOGGLES(
        "sticky_toggles",
        R.string.ai_extension_feature_sticky,
        R.string.ai_extension_feature_sticky_summary,
    ),
    KPM(
        "kpm",
        R.string.ai_extension_feature_kpm,
        R.string.ai_extension_feature_kpm_summary,
    ),
    CPU_SPOOF(
        "cpu_spoof",
        R.string.ai_extension_feature_cpu_spoof,
        R.string.ai_extension_feature_cpu_spoof_summary,
    ),
    VERSION_SPOOF(
        "version_spoof",
        R.string.ai_extension_feature_version_spoof,
        R.string.ai_extension_feature_version_spoof_summary,
    ),
    UMOUNT_PATHS(
        "umount_paths",
        R.string.ai_extension_feature_umount,
        R.string.ai_extension_feature_umount_summary,
    ),
    DYNAMIC_MANAGER(
        "dynamic_manager",
        R.string.ai_extension_feature_dynamic_manager,
        R.string.ai_extension_feature_dynamic_manager_summary,
    ),
    SUSFS_RUNTIME(
        "susfs_runtime",
        R.string.ai_extension_feature_susfs_runtime,
        R.string.ai_extension_feature_susfs_runtime_summary,
    ),
    SUSFS_CONFIG(
        "susfs_config",
        R.string.ai_extension_feature_susfs_config,
        R.string.ai_extension_feature_susfs_config_summary,
    );

    companion object {
        val ALL_IDS: Set<String> = entries.map { it.id }.toSet()

        fun fromId(id: String?): AiExtensionFeature? =
            entries.firstOrNull { it.id == id }
    }
}
