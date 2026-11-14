package com.sukisu.ultra.ui.screen.kernelmodules

import android.content.ClipData
import android.content.ClipboardManager
import android.widget.Toast
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

@Suppress("UsePropertyAccessSyntax")
@Composable
fun KernelModulesScreen() {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var state by remember { mutableStateOf(KernelModulesUiState()) }

    fun refresh() {
        scope.launch {
            state = state.copy(isLoading = true, failed = false)
            val snapshot = try {
                readKernelModulesSnapshot()
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                null
            }
            state = if (snapshot != null) {
                state.copy(snapshot = snapshot, isLoading = false, failed = false)
            } else {
                state.copy(isLoading = false, failed = true)
            }
        }
    }

    LaunchedEffect(Unit) {
        refresh()
    }

    val copiedText = stringResource(R.string.kernel_modules_params_copied)
    val actions = KernelModulesActions(
        onBack = { navigator.pop() },
        onRefresh = ::refresh,
        onToggleExpanded = { name ->
            state = state.copy(
                expanded = if (name in state.expanded) {
                    state.expanded - name
                } else {
                    state.expanded + name
                },
            )
        },
        onCopy = { value ->
            val clipboard = context.getSystemService(ClipboardManager::class.java)
            clipboard?.setPrimaryClip(ClipData.newPlainText("SukiSU block_modules", value))
            Toast.makeText(context, copiedText, Toast.LENGTH_SHORT).show()
        },
    )

    when (LocalUiMode.current) {
        UiMode.Miuix -> KernelModulesMiuix(state = state, actions = actions)
        UiMode.Material -> KernelModulesMaterial(state = state, actions = actions)
    }
}
