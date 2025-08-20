package com.sukisu.ultra.ui.webui

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView
import com.dergoogler.mmrl.platform.Platform
import com.dergoogler.mmrl.platform.PlatformManager
import com.dergoogler.mmrl.webui.activity.WXActivity
import com.dergoogler.mmrl.webui.util.WebUIOptions
import com.dergoogler.mmrl.webui.view.WebUIXView
import com.sukisu.ultra.BuildConfig
import com.sukisu.ultra.ui.theme.KernelSUTheme
import com.sukisu.ultra.ui.theme.ThemeConfig
import com.sukisu.ultra.ui.theme._isSystemInDarkTheme
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
        super.onRender(scope)

        val modId =
            this.modId
                ?: throw IllegalArgumentException("modId cannot be null or empty")

        val webDebugging = prefs.getBoolean("enable_web_debugging", false)
        val erudaInject = prefs.getBoolean("use_webuix_eruda", false)

        setContent {
            // keep the compose logic so custom background continue to work
            KernelSUTheme {
                var ready by remember { mutableStateOf(false) }

                LaunchedEffect(Unit) {
                    val init = initPlatform(context)
                    ready = init.await()
                }

                if (!ready) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize(),
                        contentAlignment = Alignment.Center
                    ) {
                        CircularProgressIndicator()
                    }

                    return@KernelSUTheme
                }

                val darkTheme = remember(ThemeConfig) {
                    when (ThemeConfig.forceDarkMode) {
                        true -> true
                        false -> false
                        null -> _isSystemInDarkTheme(context)
                    }
                }

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
                    colorScheme = MaterialTheme.colorScheme
                )

                // Activity Title
                config {
                    if (title != null) {
                        setActivityTitle("SukiSU-Ultra - $title")
                    }
                }

                AndroidView(
                    factory = { WebUIXView(options) },
                    update = { view ->
                        val v = view.apply {
                            wx.addJavascriptInterface<WebViewInterface>()
                        }

                        // pass it for the activity
                        this.view = v
                    }
                )
            }
        }
    }
}