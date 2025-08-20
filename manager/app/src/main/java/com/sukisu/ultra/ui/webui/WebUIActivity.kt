package com.sukisu.ultra.ui.webui

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.os.Bundle
import android.view.ViewGroup
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updateLayoutParams
import androidx.lifecycle.lifecycleScope
import androidx.webkit.WebViewAssetLoader
import com.dergoogler.mmrl.platform.model.ModId.Companion.getModId
import com.dergoogler.mmrl.platform.model.ModId.Companion.webrootDir
import com.dergoogler.mmrl.ui.component.dialog.ConfirmData
import com.dergoogler.mmrl.ui.component.dialog.confirm
import com.dergoogler.mmrl.webui.activity.WXActivity.Companion.createLoadingRenderer
import com.topjohnwu.superuser.Shell
import com.sukisu.ultra.ui.util.createRootShell
import com.dergoogler.mmrl.webui.util.WebUIOptions
import com.dergoogler.mmrl.webui.view.WebUIView
import com.sukisu.ultra.ui.theme.ThemeConfig
import com.sukisu.ultra.ui.theme._isSystemInDarkTheme
import com.sukisu.ultra.ui.theme.createColorScheme
import kotlinx.coroutines.launch

class WebUIActivity : ComponentActivity() {
    val modId get() = intent.getModId() ?: throw IllegalArgumentException("Invalid Module ID")
    val prefs: SharedPreferences get() = getSharedPreferences("settings", MODE_PRIVATE)
    val context: Context get() = this

    private var rootShell: Shell? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        // Enable edge to edge
        enableEdgeToEdge()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            window.isNavigationBarContrastEnforced = false
        }

        super.onCreate(savedInstanceState)

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

        lifecycleScope.launch {
            val ready = initPlatform(context)

            if (ready.await()) {
                init()
                return@launch
            }

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
        }

    }

    private fun init() {
        val webDebugging = prefs.getBoolean("enable_web_debugging", false)

        val options = WebUIOptions(
            modId = modId,
            debug = webDebugging,
            // keep plugins disabled for security reasons
            pluginsEnabled = false,
            context = context,
        )

        val rootShell = createRootShell(true).also { this.rootShell = it }
        val webViewAssetLoader = WebViewAssetLoader.Builder()
            .setDomain("mui.kernelsu.org")
            .addPathHandler(
                "/",
                SuFilePathHandler(this, modId.webrootDir, rootShell)
            )
            .build()

        val webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(
                view: WebView,
                request: WebResourceRequest,
            ): WebResourceResponse? {
                return webViewAssetLoader.shouldInterceptRequest(request.url)
            }
        }

        val webView = WebUIView(options).apply {
            ViewCompat.setOnApplyWindowInsetsListener(this) { view, insets ->
                val inset = insets.getInsets(WindowInsetsCompat.Type.systemBars())
                view.updateLayoutParams<ViewGroup.MarginLayoutParams> {
                    leftMargin = inset.left
                    rightMargin = inset.right
                    topMargin = inset.top
                    bottomMargin = inset.bottom
                }
                return@setOnApplyWindowInsetsListener insets
            }

            addJavascriptInterface<WebViewInterface>()
            setWebViewClient(webViewClient)
            loadDomain()
        }

        setContentView(webView)
    }

    override fun onDestroy() {
        runCatching { rootShell?.close() }
        super.onDestroy()
    }
}