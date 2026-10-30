package com.sukisu.ultra.ui.webui

import android.app.Activity
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.text.TextUtils
import android.util.Base64
import android.util.Log
import android.view.Window
import android.webkit.JavascriptInterface
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationCompat
import androidx.core.content.pm.PackageInfoCompat
import androidx.core.net.toUri
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import com.sukisu.ultra.ui.util.listModules
import com.sukisu.ultra.ui.util.withNewRootShell
import com.topjohnwu.superuser.CallbackList
import com.topjohnwu.superuser.ShellUtils
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.DownloadManager
import com.sukisu.ultra.ui.util.DownloadService
import com.sukisu.ultra.ui.util.resolveDownloadMimeType
import com.sukisu.ultra.ui.webui.file.KsuIO
import com.sukisu.ultra.ui.webui.pm.KsuPm
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.coroutineScope
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.File

class WebViewInterface(private val state: WebUIState) {
    private val webView get() = state.webView
    private val modDir get() = state.modDir

    @JavascriptInterface
    fun exec(cmd: String): String {
        return withNewRootShell(true) { ShellUtils.fastCmd(this, cmd) }
    }

    @JavascriptInterface
    fun exec(cmd: String, callbackFunc: String) {
        exec(cmd, null, callbackFunc)
    }

    private fun processOptions(sb: StringBuilder, options: String?) {
        val opts = if (options == null) JSONObject() else JSONObject(options)

        val cwd = opts.optString("cwd")
        if (!TextUtils.isEmpty(cwd)) {
            sb.append("cd ${cwd};")
        }

        opts.optJSONObject("env")?.let { env ->
            env.keys().forEach { key ->
                sb.append("export ${key}=${env.getString(key)};")
            }
        }
    }

    @JavascriptInterface
    fun exec(
        cmd: String,
        options: String?,
        callbackFunc: String
    ) {
        val finalCommand = StringBuilder()
        processOptions(finalCommand, options)
        finalCommand.append(cmd)

        state.exec { page ->
            val result = page.withShell { shell ->
                shell.newJob().add(finalCommand.toString()).to(ArrayList(), ArrayList()).exec()
            }
            val stdout = result.out.joinToString(separator = "\n")
            val stderr = result.err.joinToString(separator = "\n")
            page.evaluateJavascript(
                "(function() { try { ${callbackFunc}(${result.code}, ${JSONObject.quote(stdout)}, " +
                    "${JSONObject.quote(stderr)}); } catch(e) { console.error(e); } })();"
            )
        }
    }
    @JavascriptInterface
    fun spawn(command: String, args: String, options: String?, callbackFunc: String) {
        val finalCommand = StringBuilder()

        processOptions(finalCommand, options)

        if (args.isNotEmpty()) {
            finalCommand.append(command).append(" ")
            val argsArray = JSONArray(args)
            for (i in 0 until argsArray.length()) {
                finalCommand.append(argsArray.getString(i)).append(" ")
            }
        } else {
            finalCommand.append(command)
        }

        state.spawn { page ->
            coroutineScope {
                val output = WebUIOutput()
                val delivery = launch(start = CoroutineStart.UNDISPATCHED) {
                    try {
                        output.drain { batch ->
                            val events = JSONArray()
                            batch.forEach { line ->
                                events.put(JSONArray().put(line.stream).put(line.data))
                            }
                            page.evaluateJavascript(
                                "(function() { var events = $events; " +
                                    "for (var i = 0; i < events.length; i++) { try { " +
                                    "${callbackFunc}[events[i][0]].emit('data', events[i][1]); " +
                                    "} catch(e) { console.error('emitData', e); } } })();"
                            )
                        }
                    } finally {
                        output.cancel()
                    }
                }
                try {
                    val result = page.withShell(onCancel = output::cancel) { shell ->
                        // Direct callbacks preserve each reader's order without a per-line Main hop.
                        val stdout = output.callbackList("stdout")
                        val stderr = output.callbackList("stderr")
                        shell.newJob().add(finalCommand.toString()).to(stdout, stderr).exec()
                    }
                    output.finish()
                    delivery.join()
                    page.evaluateJavascript(
                        "(function() { try { ${callbackFunc}.emit('exit', ${result.code}); " +
                                $$"} catch(e) { console.error(`emitExit error: ${e}`); } })();"
                    )
                    // Keep the existing exit-before-error contract. The JS wrapper deletes its
                    // callback on exit; do not cache that object or make error newly observable.
                    if (result.code != 0) {
                        page.evaluateJavascript(
                            "(function() { try { var err = new Error(); err.exitCode = ${result.code}; " +
                                "err.message = ${JSONObject.quote(result.err.joinToString("\n"))}; " +
                                "${callbackFunc}.emit('error', err); " +
                                "} catch(e) { console.error('emitErr', e); } })();"
                        )
                    }
                } finally {
                    output.cancel()
                }
            }
        }
    }

    private fun WebUIOutput.callbackList(stream: String) = object : CallbackList<String>({ it.run() }) {
        override fun onAddElement(s: String) {
            this@callbackList.add(stream, s)
        }
    }

    @JavascriptInterface
    fun toast(msg: String) {
        webView?.post {
            webView?.let { Toast.makeText(it.context, msg, Toast.LENGTH_SHORT).show() }
        }
    }

    @JavascriptInterface
    fun fullScreen(enable: Boolean) {
        val context = webView?.context
        if (context is Activity) {
            Handler(Looper.getMainLooper()).post {
                if (enable) {
                    hideSystemUI(context.window)
                } else {
                    showSystemUI(context.window)
                }
            }
        }
        enableEdgeToEdge(enable)
    }

    @JavascriptInterface
    fun enableEdgeToEdge(enable: Boolean = true) {
        state.isInsetsEnabled = enable
    }

    @JavascriptInterface
    fun moduleInfo(): String {
        val moduleInfos = JSONArray(listModules())
        val currentModuleInfo = JSONObject()
        currentModuleInfo.put("moduleDir", modDir)
        val moduleId = File(modDir).name
        for (i in 0 until moduleInfos.length()) {
            val currentInfo = moduleInfos.getJSONObject(i)

            if (currentInfo.getString("id") != moduleId) {
                continue
            }

            val keys = currentInfo.keys()
            for (key in keys) {
                currentModuleInfo.put(key, currentInfo.get(key))
            }
            break
        }
        return currentModuleInfo.toString()
    }

    @Deprecated("Use ksu.pm().listPackages() instead")
    @JavascriptInterface
    fun listPackages(type: String): String {
        val packageNames = webUIApps()
            .filter { appInfo ->
                if (appInfo.special) return@filter false
                val flags = appInfo.packageInfo.applicationInfo?.flags ?: 0
                when (type.lowercase()) {
                    "system" -> (flags and ApplicationInfo.FLAG_SYSTEM) != 0
                    "user" -> (flags and ApplicationInfo.FLAG_SYSTEM) == 0
                    else -> true
                }
            }
            .map { it.packageName }
            .sorted()

        val jsonArray = JSONArray()
        for (pkgName in packageNames) {
            jsonArray.put(pkgName)
        }
        return jsonArray.toString()
    }

    @Deprecated("Use ksu.pm().getPackagesInfo() instead")
    @JavascriptInterface
    fun getPackagesInfo(packageNamesJson: String): String {
        val packageNames = JSONArray(packageNamesJson)
        val jsonArray = JSONArray()
        val appMap = webUIApps().filterNot { it.special }.associateBy { it.packageName }
        for (i in 0 until packageNames.length()) {
            val pkgName = packageNames.getString(i)
            val appInfo = appMap[pkgName]
            if (appInfo != null) {
                val pkg = appInfo.packageInfo
                val app = pkg.applicationInfo
                val obj = JSONObject()
                obj.put("packageName", pkg.packageName)
                obj.put("versionName", pkg.versionName ?: "")
                obj.put("versionCode", PackageInfoCompat.getLongVersionCode(pkg))
                obj.put("appLabel", appInfo.label)
                obj.put("isSystem", app?.let { (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0 } ?: JSONObject.NULL)
                obj.put("uid", app?.uid ?: JSONObject.NULL)
                jsonArray.put(obj)
            } else {
                val obj = JSONObject()
                obj.put("packageName", pkgName)
                obj.put("error", "Package not found or inaccessible")
                jsonArray.put(obj)
            }
        }
        return jsonArray.toString()
    }

    @JavascriptInterface
    fun exit() {
        state.requestExit()
    }

    @JavascriptInterface
    fun io() = KsuIO

    @JavascriptInterface
    fun pm() = KsuPm

    fun destroy() {
        KsuIO.destroy()
    }
}

class WebUIDownloadInterface(private val state: WebUIState) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val webView get() = state.webView

    companion object {
        // Use a different notification ID range to avoid collision with DownloadService
        private const val WEBUI_NOTIFICATION_ID_BASE = 200000
    }

    @JavascriptInterface
    fun openExternal(url: String) {
        val currentWebView = webView ?: return
        val uri = url.toUri()
        if (uri.scheme != "http" && uri.scheme != "https") return

        runCatching {
            currentWebView.context.startActivity(Intent(Intent.ACTION_VIEW, uri))
        }.onFailure { throwable ->
            Log.e("WebUIDownload", "Failed to open $url", throwable)
        }
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    @JavascriptInterface
    fun save(base64: String, fileName: String?) {
        val currentWebView = webView ?: return
        val context = currentWebView.context
        val displayName = sanitizeWebUIDownloadFileName(fileName)
        val mimeType = resolveDownloadMimeType(displayName, null)
        val notificationManager = context.getSystemService(NotificationManager::class.java)
        val downloadId = DownloadManager.registerLocalSave(
            fileName = displayName,
            mimeType = mimeType,
        )

        ensureNotificationChannel(notificationManager, context)
        notificationManager.notify(WEBUI_NOTIFICATION_ID_BASE + downloadId, buildProgressNotification(context, displayName, 0))

        scope.launch {
            var pendingUri: Uri? = null
            val savedUri = try {
                val decoded = Base64.decode(base64, Base64.DEFAULT)
                val collection = MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
                val values = android.content.ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, displayName)
                    put(MediaStore.MediaColumns.MIME_TYPE, mimeType)
                    put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                    put(MediaStore.MediaColumns.IS_PENDING, 1)
                }
                val uri = context.contentResolver.insert(collection, values)
                    ?: error("Failed to create download")
                pendingUri = uri
                var lastProgress = -1
                ByteArrayInputStream(decoded).use { input ->
                    val output = context.contentResolver.openOutputStream(uri)
                        ?: error("Failed to open download")
                    output.use { stream ->
                        writeWebUIDownload(input, stream) { written ->
                            val progress = if (decoded.isEmpty()) {
                                100
                            } else {
                                ((written * 100L) / decoded.size.toLong()).toInt().coerceIn(0, 100)
                            }
                            DownloadManager.updateProgress(downloadId, progress)
                            if (progress - lastProgress >= 2 || progress == 100) {
                                notificationManager.notify(
                                    WEBUI_NOTIFICATION_ID_BASE + downloadId,
                                    buildProgressNotification(context, displayName, progress)
                                )
                                lastProgress = progress
                            }
                        }
                    }
                }
                val published = android.content.ContentValues().apply {
                    put(MediaStore.MediaColumns.IS_PENDING, 0)
                }
                if (context.contentResolver.update(uri, published, null, null) != 1) {
                    error("Failed to publish download")
                }
                uri
            } catch (throwable: Throwable) {
                pendingUri?.let { context.contentResolver.delete(it, null, null) }
                Log.e("WebUIDownload", "Failed to save $displayName", throwable)
                DownloadManager.markFailed(downloadId, throwable.message ?: "Unknown error")
                notificationManager.notify(WEBUI_NOTIFICATION_ID_BASE + downloadId, buildFailureNotification(context, displayName))
                postToast(currentWebView.context.getString(R.string.download_failed_content, displayName))
                null
            }

            if (savedUri != null) {
                DownloadManager.markCompleted(downloadId, savedUri)
                notificationManager.notify(
                    WEBUI_NOTIFICATION_ID_BASE + downloadId,
                    buildCompletionNotification(context, downloadId, displayName, savedUri, mimeType)
                )
                postToast(currentWebView.context.getString(R.string.download_complete_content, displayName))
            }
        }
    }

    @JavascriptInterface
    fun startChunkedDownload(fileName: String?, mimeType: String?): String {
        val currentWebView = webView ?: return ""
        val sanitizedFileName = sanitizeWebUIDownloadFileName(fileName)
        return runCatching {
            BlobDownloadHandler.registerBlobDownload(
                sanitizedFileName,
                mimeType,
                currentWebView.context.cacheDir,
            )
        }.getOrElse {
            Log.e("WebUIDownload", "Failed to start chunked download", it)
            ""
        }
    }

    @JavascriptInterface
    fun writeDownloadChunk(downloadId: String, base64Chunk: String): Boolean {
        return BlobDownloadHandler.writeChunk(downloadId, base64Chunk)
    }

    @JavascriptInterface
    fun completeChunkedDownload(downloadId: String): Boolean {
        return BlobDownloadHandler.completeDownload(downloadId)
    }

    @JavascriptInterface
    fun cancelChunkedDownload(downloadId: String) {
        BlobDownloadHandler.cancelDownload(downloadId)
    }

    fun destroy() {
        scope.cancel()
        BlobDownloadHandler.cleanup()
    }

    private fun postToast(message: String) {
        webView?.let { currentWebView ->
            currentWebView.post {
                Toast.makeText(currentWebView.context, message, Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun ensureNotificationChannel(notificationManager: NotificationManager, context: Context) {
        notificationManager.createNotificationChannel(
            NotificationChannel(
                DownloadService.CHANNEL_ID,
                context.getString(R.string.download_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            )
        )
    }

    private fun buildProgressNotification(
        context: Context,
        fileName: String,
        progress: Int,
    ) = NotificationCompat.Builder(context, DownloadService.CHANNEL_ID)
        .setContentTitle(context.getString(R.string.download_progress_title, fileName))
        .setContentText("$progress%")
        .setSmallIcon(android.R.drawable.stat_sys_download)
        .setProgress(100, progress, progress == 0)
        .setOngoing(true)
        .setSilent(true)
        .build()

    private fun buildCompletionNotification(
        context: Context,
        downloadId: Int,
        fileName: String,
        contentUri: Uri,
        mimeType: String,
    ): android.app.Notification {
        val openIntent = Intent.createChooser(
            Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(contentUri, mimeType)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
            },
            context.getString(R.string.open),
        ).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            downloadId,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(context, DownloadService.CHANNEL_ID)
            .setContentTitle(context.getString(R.string.download_complete_title))
            .setContentText(context.getString(R.string.download_complete_content, fileName))
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .addAction(android.R.drawable.ic_menu_view, context.getString(R.string.open), pendingIntent)
            .build()
    }

    private fun buildFailureNotification(
        context: Context,
        fileName: String,
    ) = NotificationCompat.Builder(context, DownloadService.CHANNEL_ID)
        .setContentTitle(context.getString(R.string.download_failed_title))
        .setContentText(context.getString(R.string.download_failed_content, fileName))
        .setSmallIcon(android.R.drawable.stat_notify_error)
        .setAutoCancel(true)
        .build()
}

fun hideSystemUI(window: Window) =
    WindowInsetsControllerCompat(window, window.decorView).let { controller ->
        controller.hide(WindowInsetsCompat.Type.systemBars())
        controller.systemBarsBehavior = WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
    }

fun showSystemUI(window: Window) =
    WindowInsetsControllerCompat(window, window.decorView).show(WindowInsetsCompat.Type.systemBars())
