package com.sukisu.ultra.ui.screen.appcontext

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
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

    when (LocalUiMode.current) {
        UiMode.Miuix -> AppContextScreenMiuix(
            state = state,
            onBack = { navigator.pop() },
            onRefresh = viewModel::refresh,
        )
        UiMode.Material -> AppContextScreenMaterial(
            state = state,
            onBack = { navigator.pop() },
            onRefresh = viewModel::refresh,
        )
    }
}
