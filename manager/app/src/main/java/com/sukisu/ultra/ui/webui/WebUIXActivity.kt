package com.sukisu.ultra.ui.webui

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import androidx.compose.material3.ColorScheme
import com.dergoogler.mmrl.platform.Platform
import com.dergoogler.mmrl.platform.PlatformManager
import com.dergoogler.mmrl.ui.component.dialog.ConfirmData
import com.dergoogler.mmrl.ui.component.dialog.confirm
import com.dergoogler.mmrl.webui.activity.WXActivity
import com.dergoogler.mmrl.webui.util.WebUIOptions
import com.dergoogler.mmrl.webui.view.WebUIXView
import com.sukisu.ultra.BuildConfig
import com.sukisu.ultra.ui.theme.ThemeConfig
import com.sukisu.ultra.ui.theme._isSystemInDarkTheme
import com.sukisu.ultra.ui.theme.createColorScheme
import kotlinx.coroutines.CoroutineScope
import kotlin.jvm.java

class WebUIXActivity : WXActivity() {
    private val userAgent
        get(): String {
            val ksuVersion = BuildConfig.VERSION_CODE

            val platform = PlatformManager.get(Platform.Unknown) {
                platform
            }

            val platformVersion = PlatformManager.get(-1) {
                moduleManager.versionCode
            }

            val osVersion = Build.VERSION.RELEASE
            val deviceModel = Build.MODEL

            return "SukiSU-Ultra/$ksuVersion (Linux; Android $osVersion; $deviceModel; ${platform.name}/$platformVersion)"
        }


    val prefs: SharedPreferences get() = getSharedPreferences("settings", MODE_PRIVATE)
    val context: Context get() = this

    override suspend fun onRender(scope: CoroutineScope) {
        scope.initPlatform(context)
        super.onRender(scope)

        val darkTheme = when (ThemeConfig.forceDarkMode) {
            true -> true
            false -> false
            null -> _isSystemInDarkTheme(context)
        }

        val colorScheme = createColorScheme(
            context = context,
            darkTheme = darkTheme
        )

        val loading = createLoadingRenderer(colorScheme)
        setContentView(loading)

        val ready = scope.initPlatform(context)

        if (!ready.await()) {
            confirm(
                ConfirmData(
                    title = "Failed!",
                    description = "Failed to initialize platform. Please try again.",
                    confirmText = "Close",
                    onConfirm = {
                        finish()
                    },
                ),
                colorScheme = colorScheme
            )
            return
        }

        init(
            darkTheme = darkTheme,
            colorScheme = colorScheme
        )
    }

    private fun init(darkTheme: Boolean, colorScheme: ColorScheme) {
        val modId =
            this.modId
                ?: throw IllegalArgumentException("modId cannot be null or empty")

        val webDebugging = prefs.getBoolean("enable_web_debugging", false)
        val erudaInject = prefs.getBoolean("use_webuix_eruda", false)

        val options = WebUIOptions(
            modId = modId,
            context = context,
            debug = webDebugging,
            isDarkMode = darkTheme,
            // keep plugins disabled for security reasons
            pluginsEnabled = false,
            enableEruda = erudaInject,
            cls = WebUIXActivity::class.java,
            userAgentString = userAgent,
            colorScheme = colorScheme
        )

        this.view = WebUIXView(options).apply {
            wx.addJavascriptInterface<WebViewInterface>()
        }

        // Activity Title
        config {
            if (title != null) {
                setActivityTitle("SukiSU-Ultra - $title")
            }
        }

        setContentView(view)
    }
}