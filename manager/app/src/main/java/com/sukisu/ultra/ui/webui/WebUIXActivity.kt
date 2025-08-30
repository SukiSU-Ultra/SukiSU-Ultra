package com.sukisu.ultra.ui.webui

import android.app.ActivityManager
import android.os.Build
import android.os.Bundle
import android.webkit.WebView
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.*
import androidx.lifecycle.lifecycleScope
import com.dergoogler.mmrl.platform.Platform
import com.dergoogler.mmrl.platform.model.ModId
import com.dergoogler.mmrl.ui.component.Loading
import com.dergoogler.mmrl.webui.screen.WebUIScreen
import com.dergoogler.mmrl.webui.util.rememberWebUIOptions
import com.sukisu.ultra.BuildConfig
import com.sukisu.ultra.ui.theme.KernelSUTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class WebUIXActivity : ComponentActivity() {
    private lateinit var webView: WebView

    private val userAgent
        get(): String {
            val ksuVersion = BuildConfig.VERSION_CODE

            val platform = Platform.get("Unknown") {
                platform.name
            }

            val platformVersion = Platform.get(-1) {
                moduleManager.versionCode
            }

            val osVersion = Build.VERSION.RELEASE
            val deviceModel = Build.MODEL

            return "SukiSU-Ultra /$ksuVersion (Linux; Android $osVersion; $deviceModel; $platform/$platformVersion)"
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        webView = WebView(this)

        lifecycleScope.launch {
            initPlatform()
        }

        val moduleId = intent.getStringExtra("id")!!
        val name = intent.getStringExtra("name")!!
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            @Suppress("DEPRECATION")
            setTaskDescription(ActivityManager.TaskDescription("SukiSU-Ultra - $name"))
        } else {
            val taskDescription =
                ActivityManager.TaskDescription.Builder().setLabel("SukiSU-Ultra - $name").build()
            setTaskDescription(taskDescription)
        }

        val prefs = getSharedPreferences("settings", MODE_PRIVATE)

        setContent {
            KernelSUTheme {
                var isLoading by remember { mutableStateOf(true) }

                LaunchedEffect(Platform.isAlive) {
                    while (!Platform.isAlive) {
                        delay(1000)
                    }

                    isLoading = false
                }

                if (isLoading) {
                    Loading()
                    return@KernelSUTheme
                }

                val webDebugging = prefs.getBoolean("enable_web_debugging", false)
                val erudaInject = prefs.getBoolean("use_webuix_eruda", false)
                val dark = isSystemInDarkTheme()

                val options = rememberWebUIOptions(
                    modId = ModId(moduleId),
                    debug = webDebugging,
                    appVersionCode = BuildConfig.VERSION_CODE,
                    isDarkMode = dark,
                    enableEruda = erudaInject,
                    cls = WebUIXActivity::class.java,
                    userAgentString = userAgent
                )

                WebUIScreen(
                    webView = webView,
                    options = options,
                    interfaces = listOf(
                        WebViewInterface.factory()
                    )
                )
            }
        }
    }
}