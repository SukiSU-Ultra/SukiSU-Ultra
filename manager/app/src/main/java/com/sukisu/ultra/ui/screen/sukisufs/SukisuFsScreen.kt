package com.sukisu.ultra.ui.screen.sukisufs

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * sukisu-fs configuration screen.
 *
 * Lets the user:
 *   - mount / unmount a sukisu-fs layer over an existing directory;
 *   - add, remove, and list per-uid visibility rules.
 *
 * The screen is built around two thin coroutine wrappers that call
 * the appropriate `sukisuFs*` ioctl helpers. The actual UI is split
 * between the Material 3 and Miuix variants in their own files.
 */
@Composable
fun SukisuFsScreen() {
    val scope = rememberCoroutineScope()
    var mountStatus by remember { mutableStateOf<SukisuFsMountState?>(null) }
    var rules by remember { mutableStateOf<List<SukisuFsRule>>(emptyList()) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    suspend fun refresh() {
        busy = true
        error = null
        try {
            val st = withContext(Dispatchers.IO) { sukisuFsGetStatus() }
            mountStatus = st
            rules = withContext(Dispatchers.IO) { sukisuFsListRules() }
        } catch (t: Throwable) {
            error = t.message
        } finally {
            busy = false
        }
    }

    LaunchedEffect(Unit) { refresh() }

    val actions = SukisuFsActions(
        onBack = { /* navigator::pop - handled by parent */ },
        onRefresh = { scope.launch { refresh() } },
        onMount = { source, target ->
            scope.launch {
                busy = true
                try {
                    withContext(Dispatchers.IO) { sukisuFsMount(source, target) }
                    refresh()
                } catch (t: Throwable) {
                    error = t.message
                } finally {
                    busy = false
                }
            }
        },
        onUnmount = { target ->
            scope.launch {
                busy = true
                try {
                    withContext(Dispatchers.IO) { sukisuFsUnmount(target) }
                    refresh()
                } catch (t: Throwable) {
                    error = t.message
                } finally {
                    busy = false
                }
            }
        },
        onAddRule = { rule ->
            scope.launch {
                busy = true
                try {
                    withContext(Dispatchers.IO) { sukisuFsAddRule(rule) }
                    refresh()
                } catch (t: Throwable) {
                    error = t.message
                } finally {
                    busy = false
                }
            }
        },
        onRemoveRule = { path ->
            scope.launch {
                busy = true
                try {
                    withContext(Dispatchers.IO) { sukisuFsRemoveRule(path) }
                    refresh()
                } catch (t: Throwable) {
                    error = t.message
                } finally {
                    busy = false
                }
            }
        },
        onClearRules = {
            scope.launch {
                busy = true
                try {
                    withContext(Dispatchers.IO) { sukisuFsClearRules() }
                    refresh()
                } catch (t: Throwable) {
                    error = t.message
                } finally {
                    busy = false
                }
            }
        },
    )

    when (LocalUiMode.current) {
        UiMode.Material -> SukisuFsMaterial(mountStatus, rules, busy, error, actions)
        UiMode.Miuix -> SukisuFsMiuix(mountStatus, rules, busy, error, actions)
    }
}

data class SukisuFsMountState(
    val mounted: Boolean,
    val source: String?,
    val target: String?,
)

data class SukisuFsRule(
    val view: SukisuFsView,
    val uidMin: Int,
    val uidMax: Int,
    val path: String,
)

enum class SukisuFsView { HIDE, SHOW }

data class SukisuFsActions(
    val onBack: () -> Unit,
    val onRefresh: () -> Unit,
    val onMount: (source: String, target: String) -> Unit,
    val onUnmount: (target: String) -> Unit,
    val onAddRule: (SukisuFsRule) -> Unit,
    val onRemoveRule: (path: String) -> Unit,
    val onClearRules: () -> Unit,
)
