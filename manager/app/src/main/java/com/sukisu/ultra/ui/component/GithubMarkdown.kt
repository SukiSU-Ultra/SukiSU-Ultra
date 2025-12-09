package com.sukisu.ultra.ui.component

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.util.Log
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import android.widget.FrameLayout
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.LoadingIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.net.toUri
import androidx.webkit.WebViewAssetLoader
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.activity.util.adjustLightnessArgb
import com.sukisu.ultra.ui.activity.util.cssColorFromArgb
import com.sukisu.ultra.ui.activity.util.ensureVisibleByMix
import com.sukisu.ultra.ui.activity.util.relativeLuminance
import com.sukisu.ultra.ui.theme.isInDarkTheme
import okhttp3.Headers.Companion.toHeaders
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okio.IOException
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Suppress("DEPRECATION")
@Composable
fun GithubMarkdown(content: String, backgroundColor: androidx.compose.ui.graphics.Color) {
    var loading by remember { mutableStateOf(true) }
    val context = LocalContext.current
    val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
    val themeMode = prefs.getInt("color_mode", 0)
    val isDark = isInDarkTheme(themeMode)
    val dir = if (LocalLayoutDirection.current == LayoutDirection.Rtl) "rtl" else "ltr"

    val bgArgb = backgroundColor.toArgb()
    val bgLuminance = relativeLuminance(bgArgb)

    fun makeVariant(delta: Float): Int {
        val candidate = adjustLightnessArgb(bgArgb, delta)
        val madeLighter = delta > 0f
        return ensureVisibleByMix(bgArgb, candidate, 1.15, madeLighter)
    }

    val bgDefault = cssColorFromArgb(bgArgb)
    val bgMuted = cssColorFromArgb(makeVariant(if (bgLuminance > 0.6) -0.06f else 0.06f))
    val bgNeutralMuted = cssColorFromArgb(makeVariant(if (bgLuminance > 0.6) -0.12f else 0.12f))
    val bgAttentionMuted = cssColorFromArgb(makeVariant(-0.12f))
    val fgLink = cssColorFromArgb(MaterialTheme.colorScheme.primary.toArgb())

    val cssHref = "https://appassets.androidplatform.net/assets/github-markdown.css"
    val html = """
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset='utf-8'/>
          <meta name='viewport' content='width=device-width, initial-scale=1'/>
          <link rel="stylesheet" href="$cssHref" />
          <style>
            html, body { margin:0; padding:0; }
            img, video { max-width:100%; height:auto; }
            .markdown-body {
              padding: 16px;
              --bgColor-default: $bgDefault;
              --bgColor-muted: $bgMuted;
              --bgColor-neutral-muted: $bgNeutralMuted;
              --bgColor-attention-muted: $bgAttentionMuted;
              --fgColor-accent: $fgLink;
            }
          </style>
        </head>
        <body dir='${dir}'>
          <article class='markdown-body' data-theme='${if (isDark) "dark" else "light"}'>${content}</article>
        </body>
        </html>
    """.trimIndent()

    AndroidView(
        factory = { context ->
            val frameLayout = FrameLayout(context)
            val webView = WebView(context).apply {
                try {
                    setBackgroundColor(Color.TRANSPARENT)
                    isVerticalScrollBarEnabled = false
                    isHorizontalScrollBarEnabled = false
                    settings.apply {
                        offscreenPreRaster = true
                        domStorageEnabled = true
                        mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
                        allowContentAccess = false
                        allowFileAccessFromFileURLs = false
                        allowFileAccess = false
                        cacheMode = WebSettings.LOAD_CACHE_ELSE_NETWORK
                        textZoom = 90
                        setSupportZoom(false)
                        setGeolocationEnabled(false)
                    }
                    webViewClient = object : WebViewClient() {
                        private val assetLoader = WebViewAssetLoader.Builder()
                            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(context))
                            .build()

                        override fun shouldOverrideUrlLoading(
                            view: WebView, request: WebResourceRequest
                        ): Boolean {
                            val url = request.url.toString()
                            val intent = Intent(Intent.ACTION_VIEW, url.toUri())
                            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            context.startActivity(intent)
                            return true
                        }

                        override fun shouldInterceptRequest(
                            view: WebView, request: WebResourceRequest
                        ): WebResourceResponse? {
                            assetLoader.shouldInterceptRequest(request.url)?.let { return it }
                            val scheme = request.url.scheme ?: return null
                            if (!scheme.startsWith("http")) return null
                            val client: OkHttpClient = ksuApp.okhttpClient
                            val call = client.newCall(
                                Request.Builder()
                                    .url(request.url.toString())
                                    .method(request.method, null)
                                    .headers(request.requestHeaders.toHeaders())
                                    .build()
                            )
                            return try {
                                val reply: Response = call.execute()
                                val header = reply.header("content-type", "text/plain; charset=utf-8")
                                val contentTypes = header?.split(";\\s*".toRegex()) ?: emptyList()
                                val mimeType = contentTypes.firstOrNull() ?: "image/*"
                                val charset = contentTypes.getOrNull(1)?.split("=\\s*".toRegex())?.getOrNull(1) ?: "utf-8"
                                val body = reply.body ?: return null
                                WebResourceResponse(mimeType, charset, body.byteStream())
                            } catch (e: IOException) {
                                WebResourceResponse(
                                    "text/html", "utf-8",
                                    ByteArrayInputStream(Log.getStackTraceString(e).toByteArray(StandardCharsets.UTF_8))
                                )
                            }
                        }

                        override fun onPageCommitVisible(view: WebView?, url: String?) {
                            loading = false
                        }
                    }
                    loadDataWithBaseURL(
                        "https://appassets.androidplatform.net", html,
                        "text/html", StandardCharsets.UTF_8.name(), null
                    )
                } catch (e: Throwable) {
                    Log.e("GithubMarkdown", "WebView setup failed", e)
                }
            }
            frameLayout.addView(webView)
            frameLayout
        },
        modifier = Modifier
            .fillMaxWidth()
            .wrapContentHeight()
            .clipToBounds(),
    )

    if (loading) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center
        ) {
            LoadingIndicator()
        }
    }

}