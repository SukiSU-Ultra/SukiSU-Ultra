package com.sukisu.ultra.ui.util

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.res.Configuration
import android.os.Build
import android.os.LocaleList
import androidx.core.content.edit
import java.util.Locale

object LocaleHelper {
    private const val PREFS = "settings"
    private const val KEY_LANGUAGE = "app_language"

    // follow system language.
    const val SYSTEM = ""

    val SUPPORTED_TAGS: List<String> = listOf(
        "en", "ar", "az", "bg", "bn", "bn-BD", "bs", "da", "de", "es", "et",
        "fa", "fil", "fr", "gl", "hi", "hr", "hu", "id", "it", "he", "ja",
        "km", "kn", "ko", "lt", "lv", "mr", "ms", "my", "nl", "pl", "pt",
        "pt-BR", "ro", "ru", "sl", "sr", "te", "th", "tr", "uk", "vi",
        "zh-CN", "zh-HK", "zh-TW"
    )

    fun getPersistedLanguage(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_LANGUAGE, SYSTEM) ?: SYSTEM

    fun setLanguage(context: Context, tag: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit { putString(KEY_LANGUAGE, tag) }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            // Keep the system per-app language in sync on Android 13+.
            context.getSystemService(android.app.LocaleManager::class.java)
                ?.applicationLocales = if (tag.isEmpty()) {
                LocaleList.getEmptyLocaleList()
            } else {
                LocaleList.forLanguageTags(tag)
            }
        }
    }

    fun displayName(tag: String): String {
        val locale = Locale.forLanguageTag(tag)
        return locale.getDisplayName(locale)
            .replaceFirstChar { if (it.isLowerCase()) it.titlecase(locale) else it.toString() }
    }

    fun wrap(base: Context): Context {
        val tag = getPersistedLanguage(base)
        if (tag.isEmpty()) return base

        val locale = Locale.forLanguageTag(tag)
        Locale.setDefault(locale)

        val config = Configuration(base.resources.configuration)
        config.setLocale(locale)
        return base.createConfigurationContext(config)
    }
}

fun Context.findActivity(): Activity? {
    var ctx = this
    while (ctx is ContextWrapper) {
        if (ctx is Activity) return ctx
        ctx = ctx.baseContext
    }
    return null
}
