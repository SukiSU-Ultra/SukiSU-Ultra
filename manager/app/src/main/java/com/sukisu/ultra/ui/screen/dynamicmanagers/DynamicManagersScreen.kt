package com.sukisu.ultra.ui.screen.dynamicmanagers

import androidx.compose.runtime.*
import androidx.compose.runtime.rememberCoroutineScope
import com.sukisu.ultra.data.model.AppInfo
import com.sukisu.ultra.data.repository.SuperUserRepositoryImpl
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.util.DynamicManagerState
import com.sukisu.ultra.ui.util.addDynamicManager
import com.sukisu.ultra.ui.util.getDynamicManagerSignature
import com.sukisu.ultra.ui.util.getDynamicManagers
import com.sukisu.ultra.ui.util.removeDynamicManager
import com.sukisu.ultra.ui.util.setDynamicManagersEnabled
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal typealias InstalledApp = AppInfo
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
    val navigator = LocalNavigator.current
    val scope = rememberCoroutineScope()
    var state by remember { mutableStateOf<DynamicManagerState?>(null) }
    var apps by remember { mutableStateOf<List<InstalledApp>>(emptyList()) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    suspend fun refresh() {
        busy = true
        error = null
        try {
            state = getDynamicManagers()
        } catch (t: Throwable) {
            error = t.message
        } finally {
            busy = false
        }
    }

    LaunchedEffect(Unit) { refresh() }

    suspend fun loadApps() {
        busy = true
        error = null
        try {
            apps = withContext(Dispatchers.IO) {
                SuperUserRepositoryImpl().getAppList().getOrThrow().first
                    .filter { it.packageName != com.sukisu.ultra.ksuApp.packageName }
                    .sortedBy { it.label.lowercase() }
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
                val signature = getDynamicManagerSignature(app.packageInfo.applicationInfo?.sourceDir ?: error("APK path unavailable"))
                addDynamicManager(app.packageName, signature)
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
        onSetEnabled = { enabled -> scope.launch { runCatching { setDynamicManagersEnabled(enabled); refresh() }.onFailure { error = it.message } } },
        onLoadApps = { scope.launch { loadApps() } },
        onRemove = { packageName -> scope.launch { runCatching { removeDynamicManager(packageName); refresh() }.onFailure { error = it.message } } },
        onAdd = ::addApp,
    )
    when (LocalUiMode.current) {
        UiMode.Material -> DynamicManagersMaterial(state, apps, busy, error, actions)
        UiMode.Miuix -> DynamicManagersMiuix(state, apps, busy, error, actions)
    }
}
