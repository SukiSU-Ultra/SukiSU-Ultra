package com.sukisu.ultra.ui.webui

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.util.Log
import android.webkit.JsPromptResult
import android.webkit.JsResult
import android.webkit.WebView
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.createRootShell
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume

sealed class WebUIEvent {
    data object Loading : WebUIEvent()
    data object WebViewReady : WebUIEvent()
    data class Error(val message: String) : WebUIEvent()
    data object Close : WebUIEvent()
    data class ShowAlert(val message: String, val result: JsResult) : WebUIEvent()
    data class ShowConfirm(val message: String, val result: JsResult) : WebUIEvent()
    data class ShowPrompt(val message: String, val defaultValue: String, val result: JsPromptResult) : WebUIEvent()
    data class ShowFileChooser(val intent: Intent) : WebUIEvent()
}

class WebUIState {
    var webView: WebView? = null
    var rootShell: Shell? = null
    lateinit var modDir: String
    var moduleName: String = ""

    @Volatile
    private var commandPage: WebUICommandPage? = null
    private var disposed = false

    // Called on Main, including reloads: never deliver an old command to a new document.
    internal fun onPageStarted(view: WebView) {
        commandPage?.dispose()
        commandPage = if (disposed) null else WebUICommandPage(view)
    }

    internal fun exec(block: suspend (WebUICommandPage) -> Unit) {
        commandPage?.let { page -> page.execution.exec { block(page) } }
    }

    internal fun spawn(block: suspend (WebUICommandPage) -> Unit) {
        commandPage?.let { page -> page.execution.launch { block(page) } }
    }

    var uiEvent by mutableStateOf<WebUIEvent>(WebUIEvent.Loading)
    var isUrlLoaded = false
    var currentInsets: Insets = Insets(0, 0, 0, 0)
    var isInsetsEnabled by mutableStateOf(false)
    var webCanGoBack by mutableStateOf(false)
    var filePathCallback: android.webkit.ValueCallback<Array<Uri>>? = null

    fun onAlertResult() {
        val event = uiEvent
        if (event is WebUIEvent.ShowAlert) {
            event.result.confirm()
            uiEvent = WebUIEvent.WebViewReady
        }
    }

    fun onConfirmResult(confirmed: Boolean) {
        val event = uiEvent
        if (event is WebUIEvent.ShowConfirm) {
            if (confirmed) event.result.confirm() else event.result.cancel()
            uiEvent = WebUIEvent.WebViewReady
        }
    }

    fun onPromptResult(result: String?) {
        val event = uiEvent
        if (event is WebUIEvent.ShowPrompt) {
            if (result != null) event.result.confirm(result) else event.result.cancel()
            uiEvent = WebUIEvent.WebViewReady
        }
    }

    fun onFileChooserResult(uris: Array<Uri>?) {
        filePathCallback?.onReceiveValue(uris)
        filePathCallback = null
        uiEvent = WebUIEvent.WebViewReady
    }

    fun requestExit() {
        uiEvent = WebUIEvent.Close
    }

    fun dispose(activity: Activity) {
        disposed = true
        commandPage?.dispose()
        commandPage = null
        activity.setTaskDescription(activity.getString(R.string.app_name))
        webView?.let { view ->
            (view.parent as? android.view.ViewGroup)?.removeView(view)
            view.destroy()
        }
        webView = null
        runCatching { rootShell?.close() }
        rootShell = null
    }
}

internal class WebUICommandPage(private val view: WebView) {
    val execution = WebUIExecution { error -> Log.w("WebUI", "Command failed", error) }

    @Volatile
    private var disposed = false

    suspend fun evaluateJavascript(script: String) = withContext(Dispatchers.Main.immediate) {
        if (disposed) throw CancellationException("WebUI page disposed")
        suspendCancellableCoroutine { continuation ->
            // The completion callback provides renderer backpressure, not just Main queue ordering.
            view.evaluateJavascript(script) {
                if (continuation.isActive) continuation.resume(Unit)
            }
        }
    }

    suspend fun <T> withShell(
        onCancel: () -> Unit = {},
        block: (Shell) -> T,
    ): T = withWebUIResource(create = { createRootShell(true) }, onCancel = onCancel, block = block)

    fun dispose() {
        disposed = true
        execution.dispose()
    }
}
