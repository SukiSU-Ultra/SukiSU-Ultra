package com.sukisu.ultra.ui.screen.builtinzygisk

import android.widget.Toast
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.dropUnlessResumed
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.navigation3.LocalNavigator

@Composable
fun BuiltinZygiskScreen() {
    val context = LocalContext.current
    val navigator = LocalNavigator.current
    val viewModel: BuiltinZygiskViewModel = viewModel()
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(Unit) {
        viewModel.load()
    }

    val onBack = dropUnlessResumed { navigator.pop() }
    val onRefresh = {
        viewModel.load()
    }
    val onSetOption = { key: String, value: String ->
        viewModel.setOption(key, value) {
            Toast.makeText(context, R.string.builtin_zygisk_option_failed, Toast.LENGTH_SHORT).show()
        }
    }
    val onSwitch = { target: String, name: String ->
        viewModel.switchTo(target) { ok ->
            val message = if (ok) {
                context.getString(R.string.builtin_zygisk_switch_done, name)
            } else {
                context.getString(R.string.builtin_zygisk_switch_failed)
            }
            Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
        }
    }
    val onToggleProcesses = { id: String ->
        viewModel.toggleModuleProcesses(id)
    }

    when (LocalUiMode.current) {
        UiMode.Miuix -> BuiltinZygiskMiuix(
            uiState = state,
            onBack = onBack,
            onRefresh = onRefresh,
            onSwitch = onSwitch,
            onToggleProcesses = onToggleProcesses,
            onSetOption = onSetOption,
        )
        UiMode.Material -> BuiltinZygiskMaterial(
            uiState = state,
            onBack = onBack,
            onRefresh = onRefresh,
            onSwitch = onSwitch,
            onToggleProcesses = onToggleProcesses,
            onSetOption = onSetOption,
        )
    }
}
