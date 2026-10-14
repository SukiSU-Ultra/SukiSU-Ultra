package com.sukisu.ultra.ui.screen.dynamicmanagers

import android.content.pm.PackageManager
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.compose.runtime.*
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.util.getKsuDaemonPath
import com.sukisu.ultra.ui.util.getRootShell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

internal data class DynamicManagerEntry(val packageName: String, val certSize: Int, val hash: String, val uid: Int)
internal data class DynamicManagerState(val enabled: Boolean, val entries: List<DynamicManagerEntry>)
internal data class InstalledApp(val label: String, val packageName: String, val apkPath: String)
internal data class DynamicManagersActions(
    val onBack: () -> Unit,
    val onRefresh: () -> Unit,
    val onSetEnabled: (Boolean) -> Unit,
    val onLoadApps: () -> Unit,
    val onRemove: (String) -> Unit,
    val onAdd: (InstalledApp) -> Unit,
)

@Composable
fun DynamicManagersScreen() {
    val context = LocalContext.current
    val navigator = LocalNavigator.current
    val scope = rememberCoroutineScope()
    var state by remember { mutableStateOf<DynamicManagerState?>(null) }
    var apps by remember { mutableStateOf<List<InstalledApp>>(emptyList()) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    suspend fun runCommand(vararg args: String): String = withContext(Dispatchers.IO) {
        val shell = getRootShell()
        val escaped = args.joinToString(" ") { "'${it.replace("'", "'\\''")}'" }
        val out = shell.newJob().add("${getKsuDaemonPath()} $escaped").to(ArrayList<String>(), null).exec()
        check(out.code == 0) { out.err.joinToString("\n").ifBlank { "ksud command failed" } }
        out.out.joinToString("\n")
    }

    suspend fun refresh() {
        busy = true
        error = null
        try {
            val lines = runCommand("manager", "list").lines()
            val enabled = lines.firstOrNull { it.startsWith("enabled:") }?.substringAfter(':')?.trim().toBoolean()
            val entries = lines.drop(1).filter { it.isNotBlank() }.mapNotNull { line ->
                val fields = line.split('\t')
                if (fields.size < 4) null else DynamicManagerEntry(fields[0], fields[1].toIntOrNull() ?: 0, fields[2], fields[3].toIntOrNull() ?: 0)
            }
            state = DynamicManagerState(enabled, entries)
        } catch (t: Throwable) {
            error = t.message
        } finally {
            busy = false
        }
    }

    LaunchedEffect(Unit) { refresh() }

    @RequiresApi(Build.VERSION_CODES.P)
    suspend fun loadApps() {
        busy = true
        error = null
        try {
            apps = withContext(Dispatchers.IO) {
                val pm = context.packageManager
                val packages = if (Build.VERSION.SDK_INT >= 33) {
                    pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getInstalledPackages(PackageManager.GET_SIGNING_CERTIFICATES)
                }
                packages.mapNotNull { info ->
                    if (info.packageName == context.packageName) return@mapNotNull null
                    val appInfo = info.applicationInfo ?: return@mapNotNull null
                    InstalledApp(pm.getApplicationLabel(appInfo).toString(), info.packageName, appInfo.sourceDir)
                }.sortedBy { it.label.lowercase() }
            }
        } catch (t: Throwable) {
            error = t.message
        } finally {
            busy = false
        }
    }

    fun addApp(app: InstalledApp) {
        scope.launch {
            busy = true
            error = null
            try {
                val signOutput = runCommand("debug", "get-sign", app.apkPath)
                val size = Regex("size:\\s*(0x[0-9a-fA-F]+|[0-9]+)").find(signOutput)?.groupValues?.get(1)
                    ?: error("Could not parse signature size")
                val certSize = if (size.startsWith("0x")) size.substring(2).toLong(16).toInt() else size.toInt()
                val hash = Regex("hash:\\s*([0-9a-fA-F]{64})").find(signOutput)?.groupValues?.get(1)
                    ?: error("Could not parse signature hash")
                runCommand("manager", "add", app.packageName, certSize.toString(), hash)
                apps = emptyList()
                refresh()
            } catch (t: Throwable) {
                error = t.message
            } finally {
                busy = false
            }
        }
    }

    val actions = DynamicManagersActions(
        onBack = navigator::pop,
        onRefresh = { scope.launch { refresh() } },
        onSetEnabled = { enabled -> scope.launch { runCatching { runCommand("manager", "set-enabled", enabled.toString()); refresh() }.onFailure { error = it.message } } },
        onLoadApps = { scope.launch { loadApps() } },
        onRemove = { packageName -> scope.launch { runCatching { runCommand("manager", "remove", packageName); refresh() }.onFailure { error = it.message } } },
        onAdd = ::addApp,
    )
    when (LocalUiMode.current) {
        UiMode.Material -> DynamicManagersMaterial(state, apps, busy, error, actions)
        UiMode.Miuix -> DynamicManagersMiuix(state, apps, busy, error, actions)
    }
}
