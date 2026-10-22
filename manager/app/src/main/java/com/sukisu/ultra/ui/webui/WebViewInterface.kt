package com.sukisu.ultra.ui.webui

import android.app.Activity
import android.content.pm.ApplicationInfo
import android.os.Handler
import android.os.Looper
import android.text.TextUtils
import android.view.Window
import android.webkit.JavascriptInterface
import android.widget.Toast
import androidx.core.content.pm.PackageInfoCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import com.sukisu.ultra.ui.util.listModules
import com.sukisu.ultra.ui.util.withNewRootShell
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import com.topjohnwu.superuser.CallbackList
import com.topjohnwu.superuser.ShellUtils
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
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
        val opts = if (options == null) JSONObject() else {
            JSONObject(options)
        }

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

        if (!TextUtils.isEmpty(args)) {
            finalCommand.append(command).append(" ")
            JSONArray(args).let { argsArray ->
                for (i in 0 until argsArray.length()) {
                    finalCommand.append(argsArray.getString(i))
                    finalCommand.append(" ")
                }
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
                            "} catch(e) { console.error(`emitExit error: \${e}`); } })();"
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

    @JavascriptInterface
    fun listPackages(type: String): String {
        val packageNames = SuperUserViewModel.apps
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

    @JavascriptInterface
    fun getPackagesInfo(packageNamesJson: String): String {
        val packageNames = JSONArray(packageNamesJson)
        val jsonArray = JSONArray()
        val appMap = SuperUserViewModel.apps.filterNot { it.special }.associateBy { it.packageName }
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
                obj.put("isSystem", if (app != null) ((app.flags and ApplicationInfo.FLAG_SYSTEM) != 0) else JSONObject.NULL)
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
}

fun hideSystemUI(window: Window) =
    WindowInsetsControllerCompat(window, window.decorView).let { controller ->
        controller.hide(WindowInsetsCompat.Type.systemBars())
        controller.systemBarsBehavior = WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
    }

fun showSystemUI(window: Window) =
    WindowInsetsControllerCompat(window, window.decorView).show(WindowInsetsCompat.Type.systemBars())
