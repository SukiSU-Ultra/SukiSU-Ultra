package com.sukisu.ultra.ui.screen.extensions

import android.widget.Toast
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.viewmodel.ExtensionItem
import com.sukisu.ultra.ui.viewmodel.ExtensionsViewModel

@Composable
fun ExtensionsScreen() {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val viewModel: ExtensionsViewModel = viewModel()
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LifecycleResumeEffect(Unit) {
        viewModel.refresh()
        onPauseOrDispose { }
    }

    // Generic extensions are toggled in place; a Screen descriptor opens its route.
    val onOpenDetails: (ExtensionItem) -> Unit = { item ->
        when (val entry = item.descriptor.entry) {
            is ExtensionEntry.Screen -> navigator.push(entry.route)
            ExtensionEntry.Generic -> Unit
        }
    }

    LaunchedEffect(state.error) {
        state.error?.let {
            Toast.makeText(context, it, Toast.LENGTH_LONG).show()
            viewModel.clearError()
        }
    }

    when (LocalUiMode.current) {
        UiMode.Miuix -> ExtensionsScreenMiuix(
            state = state,
            onBack = { navigator.pop() },
            onRefresh = viewModel::refresh,
            onOpenDetails = onOpenDetails,
            onToggle = viewModel::setEnabled,
        )
        UiMode.Material -> ExtensionsScreenMaterial(
            state = state,
            onBack = { navigator.pop() },
            onRefresh = viewModel::refresh,
            onOpenDetails = onOpenDetails,
            onToggle = viewModel::setEnabled,
        )
    }
}
