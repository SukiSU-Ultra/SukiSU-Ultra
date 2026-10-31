package com.sukisu.ultra.ui.screen.ai

import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.core.content.FileProvider
import androidx.core.graphics.toColorInt
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.sukisu.ultra.BuildConfig
import com.sukisu.ultra.KernelSUApplication
import com.sukisu.ultra.data.repository.SettingsRepository
import com.sukisu.ultra.data.repository.SettingsRepositoryImpl
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.theme.ColorMode
import com.sukisu.ultra.ui.util.BuiltinAppIcons
import com.sukisu.ultra.ui.util.CustomTextKey
import com.sukisu.ultra.ui.util.ImageStorage
import com.sukisu.ultra.ui.util.ThemePackageData
import com.sukisu.ultra.ui.util.ThemePackageStorage
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject

/**
 * Appearance-only write surface for the AI assistant. Everything else in the
 * settings store (update checks, root features, module sorting, superuser
 * filters, ...) is deliberately out of reach: [set] only accepts the keys
 * returned by [read], and custom texts have their own entry point.
 */
object AiThemeController {

    private val repo: SettingsRepository = SettingsRepositoryImpl()

    suspend fun read(): String = withContext(Dispatchers.IO) {
        buildJsonObject {
            put("ui_mode", repo.uiMode)
            val colorMode = ColorMode.fromValue(repo.themeMode)
            put("color_mode", colorMode.name.lowercase())
            put("color_mode_value", colorMode.value)
            put("miuix_monet", repo.miuixMonet)
            put("key_color", String.format("#%08X", repo.keyColor))
            put("color_style", repo.colorStyle)
            put("color_spec", repo.colorSpec)
            put("custom_home_title", repo.customHomeTitle)
            put("app_icon", repo.appIconId)
            put("app_icon_dynamic_color", repo.appIconDynamicColor)
            put("card_background_alpha", repo.cardBackgroundAlphaPercent)
            put("background_blur", repo.customBackgroundBlurPercent)
            put("background_scrim", repo.customBackgroundScrimPercent)
            put("extract_color_from_background", repo.extractColorFromBackground)
            put("use_system_wallpaper", repo.useSystemWallpaper)
            put("blur", repo.enableBlur)
            put("floating_bottom_bar", repo.enableFloatingBottomBar)
            put("floating_bottom_bar_blur", repo.enableFloatingBottomBarBlur)
            put("navigation_badge", repo.enableNavigationBadge)
            put("page_scale", repo.pageScale)
            put("enable_predictive_back", repo.enablePredictiveBack)
            put("enable_swipe_dismiss", repo.enableSwipeDismiss)
            put("pager_interception_mode", repo.pagerInterceptionMode)
            put("module_description_max_lines", repo.moduleDescriptionMaxLines)
            put("show_full_status", repo.showFullStatus)
            put("hide_home_warnings", repo.hideHomeWarnings)
            put("show_ai_home_card", repo.showAiHomeCard)
            put("has_background_image", hasBackgroundImage())
            put("has_home_card_image", hasHomeCardImage())
            put("background_source", when {
                repo.useSystemWallpaper -> "system_wallpaper"
                repo.customBackgroundUri.isNotBlank() -> "custom"
                else -> "none"
            })
            putJsonObject("custom_texts") {
                repo.customTexts.forEach { (key, value) -> put(key, value) }
            }
        }.toString()
    }

    /**
     * @return the refreshed appearance JSON on success.
     * @throws IllegalArgumentException for unknown keys or invalid values.
     */
    suspend fun set(key: String, value: String): String = withContext(Dispatchers.IO) {
        val normalizedKey = key.trim().lowercase().replace('-', '_')
        val text = value.trim()
        when (normalizedKey) {
            "ui_mode" -> setUiMode(text)
            "color_mode" -> setColorMode(text)
            "miuix_monet" -> setMiuixMonet(text.toBooleanValue())
            "key_color" -> repo.keyColor = parseColor(text)
            "color_style" -> {
                val style = PaletteStyle.entries.firstOrNull { it.name.equals(text, true) }
                    ?: throw IllegalArgumentException(
                        "Unknown color_style '$text'. Use one of: ${
                            PaletteStyle.entries.joinToString { it.name }
                        }"
                    )
                repo.colorStyle = style.name
            }

            "color_spec" -> {
                val spec = ColorSpec.SpecVersion.entries.firstOrNull { it.name.equals(text, true) }
                    ?: throw IllegalArgumentException(
                        "Unknown color_spec '$text'. Use one of: ${
                            ColorSpec.SpecVersion.entries.joinToString { it.name }
                        }"
                    )
                repo.colorSpec = spec.name
            }

            "custom_home_title" -> {
                repo.customHomeTitle = text
                val texts = repo.customTexts.toMutableMap()
                if (text.isEmpty()) texts.remove(CustomTextKey.HOME_TITLE.key)
                else texts[CustomTextKey.HOME_TITLE.key] = text
                repo.customTexts = texts
            }

            "app_icon" -> {
                val icon = BuiltinAppIcons.all.firstOrNull { it.id.equals(text, true) }
                    ?: throw IllegalArgumentException(
                        "Unknown app_icon '$text'. Use one of: ${
                            BuiltinAppIcons.all.joinToString { it.id }
                        }"
                    )
                repo.appIconId = icon.id
                BuiltinAppIcons.apply(ksuApp, icon, repo.appIconDynamicColor)
            }

            "app_icon_dynamic_color" -> {
                val enabled = text.toBooleanValue()
                repo.appIconDynamicColor = enabled
                BuiltinAppIcons.apply(ksuApp, BuiltinAppIcons.find(repo.appIconId), enabled)
            }

            "card_background_alpha" -> repo.cardBackgroundAlphaPercent = text.toIntRange(
                ImageStorage.CARD_ALPHA_MIN,
                ImageStorage.CARD_ALPHA_MAX,
                normalizedKey,
            )

            "background_blur" -> repo.customBackgroundBlurPercent = text.toIntRange(
                ImageStorage.BACKGROUND_BLUR_PERCENT_MIN,
                ImageStorage.BACKGROUND_BLUR_PERCENT_MAX,
                normalizedKey,
            )

            "background_scrim" -> repo.customBackgroundScrimPercent = text.toIntRange(
                ImageStorage.BACKGROUND_SCRIM_MIN,
                ImageStorage.BACKGROUND_SCRIM_MAX,
                normalizedKey,
            )

            "extract_color_from_background" ->
                repo.extractColorFromBackground = text.toBooleanValue()

            "use_system_wallpaper" -> repo.useSystemWallpaper = text.toBooleanValue()

            "blur" -> repo.enableBlur = text.toBooleanValue()
            "floating_bottom_bar" -> repo.enableFloatingBottomBar = text.toBooleanValue()
            "navigation_badge" -> repo.enableNavigationBadge = text.toBooleanValue()
            "page_scale" -> {
                val scale = text.toFloatOrNull()
                    ?: throw IllegalArgumentException("page_scale must be a number")
                require(scale in 0.8f..1.1f) { "page_scale must be between 0.8 and 1.1" }
                repo.pageScale = scale
            }

            "predictive_back" -> {
                require(Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    "predictive_back requires Android 14 (API 34) or newer"
                }
                val enabled = text.toBooleanValue()
                repo.enablePredictiveBack = enabled
                KernelSUApplication.setEnableOnBackInvokedCallback(ksuApp.applicationInfo, enabled)
            }

            "swipe_dismiss" -> repo.enableSwipeDismiss = text.toBooleanValue()
            "pager_mode" -> repo.pagerInterceptionMode = text.toIntRange(0, 2, normalizedKey)
            "module_description_max_lines" ->
                repo.moduleDescriptionMaxLines = text.toIntRange(1, 5, normalizedKey)
            "show_full_status" -> repo.showFullStatus = text.toBooleanValue()
            "hide_home_warnings" -> repo.hideHomeWarnings = text.toBooleanValue()
            "show_ai_home_card" -> throw IllegalArgumentException(
                "show_ai_home_card is read-only for the assistant: disabling it would close this " +
                    "chat and remove the only AI entry. Change it manually in Settings > Appearance."
            )

            "floating_bottom_bar_blur" -> {
                require(Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    "floating_bottom_bar_blur requires Android 13 (API 33) or newer"
                }
                repo.enableFloatingBottomBarBlur = text.toBooleanValue()
            }

            else -> throw IllegalArgumentException(
                "Unknown theme key '$key'. Allowed: ui_mode, color_mode, miuix_monet, key_color, " +
                    "color_style, color_spec, custom_home_title, app_icon, app_icon_dynamic_color, " +
                    "card_background_alpha, background_blur, background_scrim, " +
                    "extract_color_from_background, use_system_wallpaper, blur, " +
                    "floating_bottom_bar, floating_bottom_bar_blur, navigation_badge, page_scale, " +
                    "predictive_back, swipe_dismiss, pager_mode, module_description_max_lines, " +
                    "show_full_status, hide_home_warnings"
            )
        }
        read()
    }

    suspend fun setCustomText(key: String, text: String): String = withContext(Dispatchers.IO) {
        val customKey = CustomTextKey.fromKey(key.trim())
            ?: throw IllegalArgumentException(
                "Unknown custom text key '$key'. Use one of: ${
                    CustomTextKey.entries.joinToString { it.key }
                }"
            )
        val trimmed = text.trim()
        val texts = repo.customTexts.toMutableMap()
        if (trimmed.isEmpty()) texts.remove(customKey.key) else texts[customKey.key] = trimmed
        repo.customTexts = texts
        if (customKey == CustomTextKey.HOME_TITLE) repo.customHomeTitle = trimmed
        read()
    }

    /** Equivalent to Settings > Appearance "Reset" (card alpha/blur/scrim only). */
    suspend fun resetAppearance(): String = withContext(Dispatchers.IO) {
        repo.cardBackgroundAlphaPercent = ImageStorage.DEFAULT_CARD_ALPHA
        repo.customBackgroundBlurPercent = ImageStorage.defaultBackgroundBlurPercent(ksuApp)
        repo.customBackgroundScrimPercent = ImageStorage.DEFAULT_BACKGROUND_SCRIM
        "Appearance reset: card alpha, background blur and scrim restored to defaults."
    }

    suspend fun resetAllCustomTexts(): String = withContext(Dispatchers.IO) {
        repo.customTexts = emptyMap()
        repo.customHomeTitle = ""
        "All custom texts were reset to their defaults."
    }

    suspend fun clearThemeImage(target: String): String = withContext(Dispatchers.IO) {
        when (target.trim().lowercase().replace('-', '_')) {
            "background", "wallpaper" -> {
                ImageStorage.clear(ksuApp)
                repo.customBackgroundUri = ""
                repo.customBackgroundUpdatedAt = System.currentTimeMillis()
                "The custom background image was removed."
            }

            "home_card", "home", "card" -> {
                ImageStorage.clearHomeCardImage(ksuApp)
                repo.homeCardImagePath = ""
                "The home card image was removed."
            }

            else -> throw IllegalArgumentException("target must be background or home_card")
        }
    }

    suspend fun exportThemePackage(uri: Uri): String = withContext(Dispatchers.IO) {
        ThemePackageStorage.export(
            context = ksuApp,
            uri = uri,
            data = buildThemePackageData(),
            backgroundFile = currentBackgroundFile(),
            cardBackgroundFile = currentHomeCardFile(),
        ).getOrThrow()
        "Theme package exported to the selected location."
    }

    suspend fun shareThemePackage(): String = withContext(Dispatchers.IO) {
        val file = File(ksuApp.cacheDir, ThemePackageStorage.packageFileName())
        ThemePackageStorage.exportToFile(
            file = file,
            data = buildThemePackageData(),
            backgroundFile = currentBackgroundFile(),
            cardBackgroundFile = currentHomeCardFile(),
        ).getOrThrow()
        val uri = FileProvider.getUriForFile(
            ksuApp,
            "${BuildConfig.APPLICATION_ID}.fileprovider",
            file,
        )
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "application/octet-stream"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val launched = withContext(Dispatchers.Main) {
            runCatching {
                ksuApp.startActivity(
                    Intent.createChooser(intent, "SukiSU theme")
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                )
            }.isSuccess
        }
        check(launched) { "Could not open the share sheet" }
        "Theme package shared: ${file.name}"
    }

    private fun buildThemePackageData(): ThemePackageData {
        val builtinIconIds = BuiltinAppIcons.all.map { it.id }.toSet()
        return ThemePackageData(
            themeMode = repo.themeMode,
            miuixMonet = repo.miuixMonet,
            keyColor = repo.keyColor,
            colorStyle = repo.colorStyle,
            colorSpec = repo.colorSpec,
            cardBackgroundAlphaPercent = repo.cardBackgroundAlphaPercent,
            customBackgroundBlurPercent = repo.customBackgroundBlurPercent,
            customBackgroundScrimPercent = repo.customBackgroundScrimPercent,
            hasBackground = currentBackgroundFile() != null,
            hasCardBackground = currentHomeCardFile() != null,
            uiMode = repo.uiMode,
            appIconId = repo.appIconId.takeIf { it in builtinIconIds } ?: BuiltinAppIcons.DEFAULT_ID,
            enableFloatingBottomBar = repo.enableFloatingBottomBar,
            enableFloatingBottomBarBlur = repo.enableFloatingBottomBarBlur,
            enableNavigationBadge = repo.enableNavigationBadge,
            enablePredictiveBack = repo.enablePredictiveBack,
            enableSwipeDismiss = repo.enableSwipeDismiss,
            moduleSortEnabledFirst = repo.moduleSortEnabledFirst,
            moduleSortActionFirst = repo.moduleSortActionFirst,
            moduleSortWebUiFirst = repo.moduleSortWebUiFirst,
            moduleSortZygiskFirst = repo.moduleSortZygiskFirst,
            moduleSortMetamoduleFirst = repo.moduleSortMetamoduleFirst,
            moduleSortNameOrder = repo.moduleSortNameOrder,
            moduleSortManual = repo.moduleSortManual,
            customHomeTitle = repo.customHomeTitle.takeIf { it.isNotBlank() },
            customTexts = repo.customTexts.takeIf { it.isNotEmpty() },
        )
    }

    private fun currentBackgroundFile(): File? = if (repo.useSystemWallpaper) {
        ImageStorage.systemWallpaperFile(ksuApp).takeIf { it.isFile }
    } else {
        repo.customBackgroundUri.takeIf { it.isNotBlank() }
            ?.let(::File)?.takeIf { it.isFile }
    }

    private fun currentHomeCardFile(): File? =
        repo.homeCardImagePath.takeIf { it.isNotBlank() }
            ?.let(::File)?.takeIf { it.isFile }

    private fun hasBackgroundImage(): Boolean =
        repo.useSystemWallpaper || repo.customBackgroundUri.isNotBlank()

    private fun hasHomeCardImage(): Boolean = repo.homeCardImagePath.isNotBlank()

    /** Full list of custom text keys, so the model can choose a valid one. */
    fun customTextKeysJson(): String = buildJsonArray {
        CustomTextKey.entries.forEach { key ->
            add(
                buildJsonObject {
                    put("key", key.key)
                    put("group", key.group.name.lowercase())
                    put("default", ksuApp.getString(key.defaultRes))
                }
            )
        }
    }.toString()

    /** Compact appearance summary used in the environment snapshot. */
    suspend fun summaryJson(): String = withContext(Dispatchers.IO) {
        buildJsonObject {
            put("ui_mode", repo.uiMode)
            put("color_mode", ColorMode.fromValue(repo.themeMode).name.lowercase())
            put("miuix_monet", repo.miuixMonet)
            put("key_color", String.format("#%08X", repo.keyColor))
            put("color_style", repo.colorStyle)
            put("color_spec", repo.colorSpec)
            put("custom_home_title", repo.customHomeTitle)
            put("app_icon", repo.appIconId)
            put("app_icon_dynamic_color", repo.appIconDynamicColor)
            put("blur", repo.enableBlur)
            put("page_scale", repo.pageScale)
            put("swipe_dismiss", repo.enableSwipeDismiss)
            put("pager_mode", repo.pagerInterceptionMode)
            put("show_full_status", repo.showFullStatus)
            put("hide_home_warnings", repo.hideHomeWarnings)
            put("has_background_image", hasBackgroundImage())
            put("has_home_card_image", hasHomeCardImage())
        }.toString()
    }

    /** Allowed values for the fixed-choice theme keys. */
    fun optionsJson(): String = buildJsonObject {
        put("keys", buildJsonArray {
            listOf(
                "ui_mode", "color_mode", "miuix_monet", "key_color", "color_style",
                "color_spec", "custom_home_title", "app_icon", "app_icon_dynamic_color",
                "card_background_alpha", "background_blur", "background_scrim",
                "extract_color_from_background", "use_system_wallpaper", "blur",
                "floating_bottom_bar", "floating_bottom_bar_blur", "navigation_badge",
                "page_scale", "predictive_back", "swipe_dismiss", "pager_mode",
                "module_description_max_lines", "show_full_status", "hide_home_warnings",
            ).forEach { add(it) }
        })
        put("ui_mode", buildJsonArray {
            add("material"); add("miuix")
        })
        put("color_mode", buildJsonArray {
            listOf(
                "system", "light", "dark", "amoled", "monet_system", "monet_light", "monet_dark",
            ).forEach { add(it) }
        })
        put("color_style", buildJsonArray {
            PaletteStyle.entries.forEach { add(it.name) }
        })
        put("color_spec", buildJsonArray {
            ColorSpec.SpecVersion.entries.forEach { add(it.name) }
        })
        put("app_icon", buildJsonArray {
            BuiltinAppIcons.all.forEach { add(it.id) }
        })
        putJsonObject("ranges") {
            put("card_background_alpha", "${ImageStorage.CARD_ALPHA_MIN}..${ImageStorage.CARD_ALPHA_MAX}")
            put("background_blur", "0..100")
            put("background_scrim", "-100..100")
            put("page_scale", "0.8..1.1")
            put("pager_mode", "0..2")
            put("module_description_max_lines", "1..5")
        }
        putJsonObject("read_only") {
            put("show_ai_home_card", "Disabling it would close the AI chat and remove the AI entry.")
        }
    }.toString()

    private fun setUiMode(value: String) {
        val newMode = when (value.lowercase()) {
            "material" -> "material"
            "miuix" -> "miuix"
            else -> throw IllegalArgumentException("ui_mode must be 'material' or 'miuix'")
        }
        val oldMode = repo.uiMode
        val currentThemeMode = repo.themeMode
        val newThemeMode = when (oldMode) {
            "material" if newMode == "miuix" -> {
                val colorMode = ColorMode.fromValue(currentThemeMode)
                val baseMode = if (colorMode == ColorMode.DARK_AMOLED) 2 else currentThemeMode
                if (repo.miuixMonet && !colorMode.isMonet) {
                    ColorMode.fromValue(baseMode).toMonetMode()
                } else if (!repo.miuixMonet && colorMode.isMonet) {
                    ColorMode.fromValue(baseMode).toNonMonetMode()
                } else {
                    baseMode
                }
            }
            "miuix" if newMode == "material" -> {
                val colorMode = ColorMode.fromValue(currentThemeMode)
                if (colorMode.isMonet) colorMode.toNonMonetMode() else currentThemeMode
            }
            else -> currentThemeMode
        }
        repo.uiMode = newMode
        repo.themeMode = newThemeMode
    }

    private fun setColorMode(value: String) {
        val parsed = parseColorMode(value)
        val normalized = if (repo.uiMode == "miuix") {
            when {
                repo.miuixMonet && !parsed.isMonet -> parsed.toMonetMode()
                !repo.miuixMonet && parsed.isMonet -> parsed.toNonMonetMode()
                else -> parsed.value
            }
        } else {
            parsed.value
        }
        repo.themeMode = normalized
    }

    private fun setMiuixMonet(enabled: Boolean) {
        val currentThemeMode = repo.themeMode
        val colorMode = ColorMode.fromValue(currentThemeMode)
        val newThemeMode = if (enabled) {
            if (!colorMode.isMonet) colorMode.toMonetMode() else currentThemeMode
        } else {
            if (colorMode.isMonet) colorMode.toNonMonetMode() else currentThemeMode
        }
        repo.miuixMonet = enabled
        repo.themeMode = newThemeMode
    }

    private fun parseColorMode(value: String): ColorMode {
        when (value.lowercase().replace('-', '_')) {
            "system" -> return ColorMode.SYSTEM
            "light" -> return ColorMode.LIGHT
            "dark" -> return ColorMode.DARK
            "amoled", "dark_amoled" -> return ColorMode.DARK_AMOLED
            "monet_system" -> return ColorMode.MONET_SYSTEM
            "monet_light" -> return ColorMode.MONET_LIGHT
            "monet_dark" -> return ColorMode.MONET_DARK
        }
        val numeric = value.toIntOrNull()
            ?: throw IllegalArgumentException(
                "color_mode must be one of system, light, dark, amoled, monet_system, " +
                    "monet_light, monet_dark"
            )
        return ColorMode.entries.firstOrNull { it.value == numeric }
            ?: throw IllegalArgumentException("color_mode value must be between 0 and 6")
    }

    private fun parseColor(value: String): Int {
        val text = value.trim()
        val parsed = runCatching {
            if (text.startsWith("#")) {
                text.toColorInt()
            } else {
                "#$text".toColorInt()
            }
        }.getOrNull()
        if (parsed != null) return parsed
        return text.toLongOrNull()?.toInt()
            ?: throw IllegalArgumentException(
                "key_color must be #RRGGBB, #AARRGGBB or an ARGB integer"
            )
    }

    private fun String.toBooleanValue(): Boolean = when (lowercase()) {
        "true", "1", "yes", "on", "enabled" -> true
        "false", "0", "no", "off", "disabled" -> false
        else -> throw IllegalArgumentException("Expected true/false, got '$this'")
    }

    private fun String.toIntRange(min: Int, max: Int, key: String): Int {
        val parsed = toIntOrNull() ?: throw IllegalArgumentException("$key must be an integer")
        require(parsed in min..max) { "$key must be between $min and $max" }
        return parsed
    }
}
