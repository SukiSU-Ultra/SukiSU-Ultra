package com.sukisu.ultra.ui.screen.appcontext

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.delay
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.viewmodel.AppContextViewModel

/**
 * App Context screen - shows all tracked UID contexts
 */
@Composable
fun AppContextScreen() {
    val navigator = LocalNavigator.current
    val viewModel: AppContextViewModel = viewModel()
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    var showTools by rememberSaveable { mutableStateOf(false) }
    val lifecycleOwner = LocalLifecycleOwner.current
    LaunchedEffect(lifecycleOwner, showTools) {
        if (!showTools) {
            lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
                viewModel.refresh(silent = true)
                while (true) {
                    delay(5_000)
                    viewModel.refresh(silent = true)
                }
            }
        }
    }

    if (showTools) {
        AppContextToolsDialog(onDismiss = {
            showTools = false
            viewModel.refresh()
        })
    }

    when (LocalUiMode.current) {
        UiMode.Miuix -> AppContextScreenMiuix(
            state = state,
            onBack = { navigator.pop() },
            onRefresh = { viewModel.refresh() },
            onTools = { showTools = true },
        )
        UiMode.Material -> AppContextScreenMaterial(
            state = state,
            onBack = { navigator.pop() },
            onRefresh = { viewModel.refresh() },
            onTools = { showTools = true },
        )
    }
}
