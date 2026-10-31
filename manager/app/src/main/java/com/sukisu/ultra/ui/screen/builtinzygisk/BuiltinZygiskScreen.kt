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
    val onRearm = {
        viewModel.rearm {
            Toast.makeText(context, R.string.builtin_zygisk_rearm_success, Toast.LENGTH_SHORT).show()
        }
    }
    val onRefresh = {
        viewModel.load()
    }

    when (LocalUiMode.current) {
        UiMode.Miuix -> BuiltinZygiskMiuix(
            uiState = state,
            onBack = onBack,
            onRefresh = onRefresh,
            onRearm = onRearm,
        )
        UiMode.Material -> BuiltinZygiskMaterial(
            uiState = state,
            onBack = onBack,
            onRefresh = onRefresh,
            onRearm = onRearm,
        )
    }
}
